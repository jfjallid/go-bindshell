//go:build portforwards

package main

import (
	"strings"
	"io"
	"strconv"
	"net"
	"golang.org/x/crypto/ssh"
)

func init() {
      features["direct-tcpip"] = handleForward
      features["tcpip-forward"] = createReverseForward
}

func createReverseForward(c *Client, payload []byte) (bool, []byte) {
	// Wants a response
	r := reverseForwardRequest{}
	if err := ssh.Unmarshal(payload, &r); err != nil {
		log.Errorf("Client '%s': Failed to unmarshal request payload: %v\n", c.identifier, err)
        return false, nil
	}

    if !c.privs.allowReverseForward {
        if addr, ok := c.privs.allowedListen[int(r.BindPort)]; !ok {
            return false, nil
        } else {
            if r.BindAddr != addr.String() {
                log.Noticef("Reverse portforward with bind addr %s was attempted but only %s is allowed\n", r.BindAddr, addr.String())
                return false, nil
            }
        }
    }


	//TODO check if addr is domain name or ip. Probably limit to only support ipv4 addresses
	// Optionally limit to only listen on localhost?
	log.Debugf("Client '%s':tcpip-forward with bindaddr: %s\n", c.identifier, r.BindAddr)
	if r.BindAddr == "" {
		r.BindAddr = "0.0.0.0"
	} else {
		bindIP := net.ParseIP(r.BindAddr)
		//NOTE Might introduce problem if I request forward for 127.0.0.1:1234 then localhost:1234 ?
		if (bindIP == nil) && (r.BindAddr != "localhost") {
			// Hostname or invalid ip
			log.Debugf("Client '%s': tcpip-forward request with invalid ip\n", c.identifier)
            return false, nil
		}
	}
	log.Debugf("Client '%s': Sent tcpip-forward request with listen address: %s and port: %d\n", c.identifier, r.BindAddr, r.BindPort)
	// Setup a socket and listener and be ready to forward any incoming connections via a newChannel request
	listenAddr := net.JoinHostPort(r.BindAddr, strconv.FormatInt(int64(r.BindPort), 10))
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Debugf("Client '%s': tcpip-forward request failed to start listener: %v\n", c.identifier, err)
        return false, nil
	}
	// Need to check bindport in case client requested a bind for port 0 e.g, assign me a port
	_, bindPortStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		log.Errorf("Client '%s': tcpip-forward request failed to parse assigned listening port: %v\n", c.identifier, err)
		l.Close()
        return false, nil
	}
	bindPort, err := strconv.Atoi(bindPortStr)
	if err != nil {
		log.Errorf("Client '%s': tcpip-forward request failed to parse int of assigned listening port: %v\n", c.identifier, err)
		l.Close()
        return false, nil
	}
	// Must close listener if shutdown before receiving cancel-tcpip-forward.
	//defer l.Close()
	c.reverseForwards[listenAddr] = l // Shouldn't need a pointer to an interface
	c.reverseForwardListeners[l] = listenAddr
	go handleReverseForward(c, l)
	response := ssh.Marshal(&reverseForwardSuccess{uint32(bindPort)})
    return true, response
}

func handleReverseForward(c *Client, l net.Listener) {
	defer log.Debugf("Client '%s': Closed remote listener: %s\n", c.identifier, l.Addr())
	for {
		conn, err := l.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok {
				if opErr.Temporary() {
					// Try again
					continue
				}
				// Likely that listener is closed
				break
			}
			log.Errorf("Client '%s': Error %v\n", c.identifier, err)
			continue
		}
		bindAddr, bindPortStr, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", c.identifier, err)
			conn.Close()
			continue
		}
		bindPort, err := strconv.Atoi(bindPortStr)
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", c.identifier, err)
			conn.Close()
			continue
		}
		if val, ok := c.reverseForwardListeners[l]; ok {
			// Use configured bindAddr instead of the one translated by net lib.
			// l.Addr() returns 127.0.0.1:1234 instead of localhost:1234 even
			// if localhost // was specified as listen address.
			// Important for reverse SOCKS.
			bindAddr = strings.Split(val, ":")[0]
		}

		originAddr, originPortStr, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", c.identifier, err)
			conn.Close()
			continue
		}
		originPort, err := strconv.Atoi(originPortStr)
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", c.identifier, err)
			conn.Close()
			continue
		}

		r := reverseForwardChannelData{
			DestHost:   bindAddr,
			DestPort:   uint32(bindPort),
			OriginHost: originAddr,
			OriginPort: uint32(originPort),
		}
		// Open channel
		log.Debugf("Client '%s': Attempting to open channel to forward traffic from %s:%d to %s:%d\n", c.identifier, r.OriginHost, r.OriginPort, r.DestHost, r.DestPort)
		payload := ssh.Marshal(&r)
		channel, reqs, err := c.conn.OpenChannel("forwarded-tcpip", payload)
		if err != nil {
			log.Errorf("Client '%s': Failed to open forwarded-tcpip channel: %v\n", c.identifier, err)
			conn.Close()
			continue
		}
		// Don't think I need these?
		//go ssh.DiscardRequests(reqs)
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Debugf("Denying received request: %v\n", req)
				req.Reply(false, nil)
			}
		}(reqs)

		go func() {
			defer channel.Close()
			defer conn.Close()
			io.Copy(channel, conn)
			log.Debugln("Closed io.Copy(channel, conn)")
		}()
		go func() {
			defer channel.Close()
			defer conn.Close()
			io.Copy(conn, channel)
			log.Debugln("Closed io.Copy(conn, channel)")
		}()
	}
}

func handleForward(c *Client, newChannel ssh.NewChannel) {
	d := localForwardChannelData{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &d); err != nil {
		log.Errorln(err)
		newChannel.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}
    if !c.privs.allowForward {
        if addr, ok := c.privs.allowedOpen[int(d.DestPort)]; !ok {
		    newChannel.Reject(ssh.ConnectionFailed, "Portforward not allowed")
            return
        } else {
            if d.DestHost != addr.String() {
                log.Noticef("Portforward for %s was attempted but only to %s is allowed\n", d.DestHost, addr.String())
		        newChannel.Reject(ssh.ConnectionFailed, "Portforward not allowed")
                return
            }
        }
    }
    
	log.Debugf("Received direct-tcpip request with to %s:%d from %s:%d\n", d.DestHost, d.DestPort, d.OriginHost, d.OriginPort)
	//TODO determine if I want to forward data e.g., perhaps only allow certain destinations?
	destIP := net.ParseIP(d.DestHost)
	if (destIP == nil) && (d.DestHost != "localhost") {
		// Hostname or invalid ip
		log.Debugf("Client '%s': direct-tcpip request with invalid ip\n", c.identifier)
		newChannel.Reject(ssh.ConnectionFailed, "Invalid destination host IP")
		return
	}
	dest := net.JoinHostPort(d.DestHost, strconv.FormatInt(int64(d.DestPort), 10))

	dconn, err := net.Dial("tcp", dest)
	if err != nil {
		log.Debugf("Client '%s': Error: %v\n", c.identifier, err)
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Debugf("Client '%s': Error: %v\n", c.identifier, err)
		dconn.Close()
		return
	}
	//go ssh.DiscardRequests(requests)
	go func(in <-chan *ssh.Request) {
		for req := range in {
			log.Debugf("Denying received request: %v\n", req)
			req.Reply(false, nil)
		}
	}(requests)

	go func() {
		defer channel.Close()
		defer dconn.Close()
		io.Copy(channel, dconn)
		log.Debugln("Closed io.Copy(channel, dconn)")
	}()
	go func() {
		defer channel.Close()
		defer dconn.Close()
		io.Copy(dconn, channel)
		log.Debugln("Closed io.Copy(dconn, channel)")
	}()
}
