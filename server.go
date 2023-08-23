package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
)

const MYSIGWINCH = syscall.Signal(0x11c)

var (
	termRegex = regexp.MustCompile("[a-z0-9-]")
	features  = make(map[string]interface{})
)

type permissions struct {
	pty                 bool
	allowForward        bool
	allowReverseForward bool
	allowedOpen         map[int]net.IPAddr
	allowedListen       map[int]net.IPAddr
	restrict            bool
}

type Client struct {
	conn                    ssh.Conn
	identifier              string
	privs                   permissions
	ptm                     *os.File
	pts                     *os.File
	sessionChan             ssh.Channel
	term                    string
	ws                      *winsize
	wsch                    chan os.Signal
	oncePTYClose            sync.Once
	reverseForwards         map[string]net.Listener
	reverseForwardListeners map[net.Listener]string
}

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// RFC 4254 Section 6.2
type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

// RFC 4254 Section 6.7
type winsizeChangeMsg struct {
	cols   uint32
	rows   uint32
	width  uint32
	height uint32
}

// RFC 4254 Section 7.1
type reverseForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type cancelReverseForward struct {
	BindAddr string
	BindPort uint32
}

type reverseForwardSuccess struct {
	BindPort uint32
}

// RFC 4254 Section 7.2
type reverseForwardChannelData struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

type localForwardChannelData struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

func (self *Client) handleRequests(in <-chan *ssh.Request) {
	//Sessions have out-of-band but in-channel requests such as "shell", "env", "pty-req" and "window-change",
	for req := range in {
		switch req.Type {
		case "pty-req":
			if val, ok := features["pty-req"]; !ok {
				req.Reply(false, nil)
			} else {
				if !self.privs.pty {
					req.Reply(false, nil)
					continue
				}
				fn := val.(func(*Client, []byte) (bool, []byte))
				ok, res := fn(self, req.Payload)
				if ok {
					defer self.oncePTYClose.Do(func() {
						self.ptm.Close()
						self.pts.Close()
						self.ptm = nil
						self.pts = nil
					})
				}
				req.Reply(ok, res)
			}
		case "shell":
			log.Debugf("Client '%s': Received request to spawn shell\n", self.identifier)
			if val, ok := features["shell"]; !ok {
				req.Reply(false, nil)
			} else {
				fn := val.(func(*Client) (bool, []byte))
				req.Reply(fn(self))
			}
		case "window-change":
			if self.ws == nil {
				log.Noticef("Client '%s': Unexpected window-change request before pty-req. Ignoring\n", self.identifier)
				break
			}
			// Read dimensions from payload
			self.ws.Col = uint16(binary.BigEndian.Uint32(req.Payload[0:4]))
			self.ws.Row = uint16(binary.BigEndian.Uint32(req.Payload[4:8]))
			self.wsch <- MYSIGWINCH
		case "exec":
			log.Debugf("Client '%s': Received exec request: %v\n", self.identifier, req)
			if val, ok := features["exec"]; !ok {
				req.Reply(false, nil)
			} else {
				fn := val.(func(*Client, []byte))
				go fn(self, req.Payload)
				req.Reply(true, nil)
			}
		case "env":
			req.Reply(false, nil)
		default:
			log.Noticef("Client '%s': Received unhandled request: %v\n", self.identifier, req)
			req.Reply(false, nil)
		}
	}
	log.Debugf("Client '%s': Stopped handling requests for session channel\n", self.identifier)
}

func (c *Client) handleNewChannels(chans <-chan ssh.NewChannel) {
	defer c.conn.Close()
	defer log.Noticef("Client '%s' disconnected\n", c.identifier)
	// Service the incoming Channel channel.
	for newChannel := range chans {
		if newChannel.ChannelType() == "session" {
			if c.sessionChan != nil {
				newChannel.Reject(ssh.ResourceShortage, "Already opened a session channel")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Noticef("Client '%s': Could not accept session channel: %v", c.identifier, err)
				continue
			}
			c.sessionChan = channel
			// Could this defer statement be called before it is time?
			// e.g., could the "chans" channel be closed before the connection is closed?
			defer func() {
				c.sessionChan.Close()
				log.Debugf("Client '%s': Closed session channel\n", c.identifier)
			}()
			go c.handleRequests(requests)
		} else if newChannel.ChannelType() == "direct-tcpip" {
			log.Debugf("Client '%s': Received request for direct-tcpip\n", c.identifier)
			if val, ok := features["direct-tcpip"]; !ok {
				newChannel.Reject(ssh.Prohibited, "Missing support for port forwarding.")
			} else {
				fn := val.(func(*Client, ssh.NewChannel))
				fn(c, newChannel)
			}
		} else {
			//If I decice to support mutiple channel types I should store the
			//references somewhere and make sure they are closed properly upon exit
			log.Noticef("Client '%s': Unknown channelType: %v\n", c.identifier, newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
	}
}

// Out-of-channel e.g. global requests
func (self *Client) handleOOCRequests(in <-chan *ssh.Request) {
	defer func() {
		log.Debugln("Closing reverse forward listeners")
		for l, addr := range self.reverseForwardListeners {
			l.Close()
			delete(self.reverseForwards, addr)
		}
	}()
	// Handle tcpip-forward requests
	for req := range in {
		switch req.Type {
		case "tcpip-forward":
			if val, ok := features["tcpip-forward"]; !ok {
				req.Reply(false, nil)
			} else {
				fn := val.(func(*Client, []byte) (bool, []byte))
				req.Reply(fn(self, req.Payload))
				// Must close listener if shutdown before receiving cancel-tcpip-forward.
				//TODO Find a way to close the new listener if server is shutdown before receiving cancel-tcpip-forward
				//req.Reply(createReverseForward(self, req.Payload))
			}

			//req.Reply(true, payload)
		case "cancel-tcpip-forward":
			r := cancelReverseForward{}
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				log.Errorf("Client '%s': Failed to unmarshal request payload: %v\n", self.identifier, err)
				req.Reply(false, nil)
				continue
			}
			log.Debugf("Client '%s': Sent cancel-tcpip-forward request with listen address: %s and port: %d\n", self.identifier, r.BindAddr, r.BindPort)
			//TODO Check if addr is domain name or ip. Probably limit to only support ipv4 addresses
			listenAddr := net.JoinHostPort(r.BindAddr, strconv.FormatInt(int64(r.BindPort), 10))
			if val, ok := self.reverseForwards[listenAddr]; ok {
				// Close listener
				delete(self.reverseForwards, listenAddr)
				delete(self.reverseForwardListeners, val)
				val.Close()
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}
		default:
			log.Noticef("Client '%s': Discarding request on original request channel: %v\n", self.identifier, req)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (c *Client) parsePubkeyOptions(list []string) {
	explitNoForward := false
	explicitNoPty := false
	for _, item := range list {
		parts := strings.Split(item, "=")
		switch parts[0] {
		case "restrict":
			c.privs.restrict = true
		case "no-pty":
			explicitNoPty = true
		case "no-port-forwarding":
			explitNoForward = true
		case "permitlisten":
			if len(parts) > 1 {
				ip, port, err := parseAddr(parts[1])
				if err != nil {
					log.Debugf("Failed to parse Authorized_keys option permitlisten with argument: (%s)\n", parts[1])
					continue
				}
				c.privs.allowedListen[port] = *ip
			}
		case "permitopen":
			c.privs.pty = true
			if len(parts) > 1 {
				ip, port, err := parseAddr(parts[1])
				if err != nil {
					log.Debugf("Failed to parse Authorized_keys option permitopen with argument: (%s)\n", parts[1])
					continue
				}
				c.privs.allowedOpen[port] = *ip
			}
		default:
		}
	}
	/*
	   If restrict, then block everything by default and only allow what is explicitly allowed
	   If explit no forward, then block forward, otherwise allow port forward unless restrict.
	*/
	if !c.privs.restrict {
		if !explicitNoPty {
			c.privs.pty = true
		}
		if !explitNoForward {
			c.privs.allowForward = true
			c.privs.allowReverseForward = true
		}
	}
	/* TODO Handle cases
	   1. Only want to allow a few specific port for listen or open
	   2. Don't want to allow any port forwards
	*/
	if !explitNoForward {
		c.privs.allowForward = true
		c.privs.allowReverseForward = true
	}
	if !explicitNoPty {
		c.privs.pty = true
	}
}

func (c *Client) parsePermissions(extensions, criticalOptions map[string]string) {
	// Default to allow everything unless specifically denied
	c.privs.allowForward = true
	c.privs.allowReverseForward = true
	c.privs.pty = true

	for key, _ := range criticalOptions {
		switch key {
		case "no-port-forwarding":
			c.privs.allowForward = false
			c.privs.allowReverseForward = false
		case "no-pty":
			c.privs.pty = false
		default:
		}
	}
	for key, _ := range extensions {
		switch key {
		case "no-port-forwarding":
			c.privs.allowForward = false
			c.privs.allowReverseForward = false
		case "no-pty":
			c.privs.pty = false
		default:
		}
	}
}

func parseAddr(s string) (ip *net.IPAddr, port int, err error) {
	// localhost:*
	// localhost:1234
	// 0.0.0.0:2222
	// [::1]:*
	// [::1]:2323
	i := strings.LastIndex(s, ":")
	if i == -1 {
		err = fmt.Errorf("Invalid format of address")
		return
	}
	port = -1 // Means any port
	addrStr := s[:i]
	portStr := s[i+1:]
	if portStr != "*" {
		// A specified port
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return
		} else if port < 0 {
			err = fmt.Errorf("Invalid port")
			return
		}
	}
	if addrStr == "localhost" {
		ip, err = net.ResolveIPAddr("tcp", "127.0.0.1")
		if err != nil {
			return
		}
	} else {
		ip, err = net.ResolveIPAddr("tcp", addrStr)
		if err != nil {
			return
		}
	}
	return ip, port, nil
}

func genHostKey() (signer ssh.Signer, err error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Criticalf("Failed to gen privateKey: %v", err)
		return
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	signer, err = ssh.ParsePrivateKey(pemdata)
	if err != nil {
		log.Criticalf("Failed to parse private key: %v", err)
	}

	return
}

func NewServer(bindAddr string) {
	var checker ssh.CertChecker
	var hostKey ssh.Signer
	var err error
	var authEnabled bool

	config := &ssh.ServerConfig{
		BannerCallback: func(conn ssh.ConnMetadata) string {
			// No callback string
			return ""
		},
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			if err != nil {
				log.Noticef("Auth attempt from (%s) for (%s) with method: (%s) and error: %v\n", conn.RemoteAddr().String(), conn.User(), method, err)
			}
		},
	}

	if val, ok := features["ca"]; ok {
		var caPubkey *ssh.PublicKey
		var crl map[string]int
		// Use CA host cert if available
		fn := val.(func() (ssh.Signer, *ssh.PublicKey, map[string]int, error))
		hostKey, caPubkey, crl, err = fn()
		if err != nil {
			log.Errorln(err)
			return
		}
		caFingerPrint := ssh.FingerprintSHA256(*caPubkey)
		checker.IsUserAuthority = func(auth ssh.PublicKey) bool {
			if ssh.FingerprintSHA256(auth) == caFingerPrint {
				log.Debugf("Certificate signed by trusted CA using key with fingerprint %s\n", ssh.FingerprintSHA256(auth))
				return true
			} else {
				log.Debugf("Certificate NOT signed by trusted CA with fingerprint %s\n", ssh.FingerprintSHA256(auth))
			}
			return false
		}
		checker.IsRevoked = func(cert *ssh.Certificate) bool {
			// The SSH package lacks functionality to handle KRL files so for now there is only a basic check
			// against a list of fingerprints combined with serial numbers that are revoked.
			// Save certificate
			if val, ok := crl[ssh.FingerprintSHA256(cert.Key)]; ok {
				if val >= int(cert.Serial) {
					log.Noticef("Certificate is REVOKED with fingerprint: %s and serial: %d\n", ssh.FingerprintSHA256(cert.Key), cert.Serial)
					return true
				}
			}
			return false
		}

		// Using a customized checker.Authenticate() to store certificate identity
		config.PublicKeyCallback = func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := pubKey.(*ssh.Certificate)
			if !ok {
				if checker.UserKeyFallback != nil {
					return checker.UserKeyFallback(conn, pubKey)
				}
				return nil, fmt.Errorf("ssh: normal key pairs not accepted")
			}

			if cert.CertType != ssh.UserCert {
				return nil, fmt.Errorf("ssh: cert has type %d", cert.CertType)
			}
			if !checker.IsUserAuthority(cert.SignatureKey) {
				return nil, fmt.Errorf("ssh: certificate signed by unrecognized authority")
			}

			if err := checker.CheckCert(conn.User(), cert); err != nil {
				return nil, err
			}

			cert.Permissions.Extensions["cert-identity"] = cert.KeyId
			return &cert.Permissions, nil
		}
		authEnabled = true
		log.Infoln("Added support for cert auth")
	}

	if val, ok := features["pubkey"]; ok {
		fn := val.(func() (func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error), error))
		callbackFunc, err := fn()
		if err != nil {
			log.Errorln(err)
			return
		}

		if checker.IsUserAuthority != nil {
			// CA is enabled
			checker.UserKeyFallback = callbackFunc
		} else {
			// CA is not enabled
			config.PublicKeyCallback = callbackFunc
		}

		if hostKey == nil {
			// CA is not enabled so generate hostkey
			hostKey, err = genHostKey()
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		authEnabled = true
		log.Infoln("Added support for pubkey auth")
	}

	if val, ok := features["password"]; ok {
		fn := val.(func() (func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error), error))
		callbackFunc, err := fn()
		if err != nil {
			log.Errorln(err)
			return
		}
		config.PasswordCallback = callbackFunc

		if hostKey == nil {
			// CA and pubkey is not enabled so generate hostkey
			hostKey, err = genHostKey()
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		authEnabled = true
		log.Infoln("Added support for password based auth")
	}

	if !authEnabled {
		log.Errorln("No auth method enabled")
		return
	}

	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Criticalf("failed to listen for connection: %v", err)
		return
	}
	defer listener.Close()
	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Criticalf("failed to accept incoming connection: %v", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Errorf("Client '%s': failed to handshake: %v\n", nConn.RemoteAddr().String(), err)
			nConn.Close()
			continue
		}
		//NOTE There will be a clash if two clients request the same reverse port forward
		// Perhaps keep track globally of reverse forwards in use instead of attempting to open second one and failing?
		c := Client{
			conn:                    conn,
			identifier:              fmt.Sprintf("%s@%s", conn.User(), conn.RemoteAddr().String()),
			reverseForwards:         make(map[string]net.Listener),
			reverseForwardListeners: make(map[net.Listener]string),
			privs: permissions{
				allowedListen: make(map[int]net.IPAddr),
				allowedOpen:   make(map[int]net.IPAddr),
			},
		}
		if conn.Permissions != nil {
			if val, ok := conn.Permissions.Extensions["pubkey-fp"]; ok {
				log.Noticef("Client '%s' logged in with public key: %s\n", c.identifier, val)
			} else if val, ok := conn.Permissions.Extensions["cert-identity"]; ok {
				log.Noticef("Client '%s' logged in with client cert issued to: %s\n", c.identifier, val)
			} else {
				log.Noticef("Client '%s' logged in with password.\n", c.identifier)
			}
			c.parsePermissions(conn.Permissions.Extensions, conn.Permissions.CriticalOptions)
			log.Debugf("User has the following permissions: %#v\n", c.privs)
		} else {
			log.Noticef("Client '%s' logged in without setting permissions\n", c.identifier)
		}

		// The incoming Request channel must be serviced.
		go c.handleOOCRequests(reqs)
		// Handle new channel opening requests
		go c.handleNewChannels(chans)
	}
}
