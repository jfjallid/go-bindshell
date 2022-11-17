package main

/*
An authenticated bind shell using SSH and public key authentication
with support for port forwarding.
Due to some dependencies on spawning a PTY, this will only work on linux
distributions. Limitations are in the opening of the /dev/ptmx device.

Use this program at your own risk.

Created: 2022
Author:
Jimmy Fjällid
*/

import (
	"syscall"

	log "github.com/jfjallid/golog"
	"golang.org/x/crypto/ssh"

	//"golang.org/x/sys/unix"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	//"os/signal"
	"regexp"
	"strconv"
	"sync"
    "time"
)

var (
	termRegex = regexp.MustCompile("[a-z0-9-]")
	bindAddr  = "0.0.0.0:2022"
)

//go:embed authorized_keys
var authorizedKeysBytes []byte

const MYSIGWINCH = syscall.Signal(0x11c)

type Client struct {
	conn            ssh.Conn
	identifier      string
	ptm             *os.File
	pts             *os.File
	sessionChan     ssh.Channel
	term            string
	ws              *winsize
	wsch            chan os.Signal
	oncePTYClose    sync.Once
	reverseForwards map[string]net.Listener
}

type winsize struct {
    Row     uint16
    Col     uint16
    Xpixel  uint16
    Ypixel  uint16
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
    cols    uint32
    rows    uint32
    width   uint32
    height  uint32
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

func watchdog(duration time.Duration) {
	t := time.NewTimer(duration)
	<-t.C
	log.Infoln("Watchdog fired! Exiting process")
	os.Exit(0)
}


func (self *Client) execCommand(payload []byte) {
	defer func() {
		self.sessionChan.Close()
	}()
	payloadCmdLen := binary.BigEndian.Uint32(payload[:4])
	payloadCmd := string(payload[4:])
	if int(payloadCmdLen) != len(payloadCmd) {
		log.Errorf("Client '%s': Received an exec command with invalid size. Reported size: %d, actual size: %d\n",
			self.identifier, payloadCmdLen, len(payloadCmd))
	}

	log.Debugf("Client '%s': Received request to execute command: %s\n", self.identifier, payloadCmd)
    var cmd *exec.Cmd
    var err error
	if self.pts != nil {
	    cmd, err = self.runPTYCommand([]string{payloadCmd})
		// Close PTY
		defer func() {
			self.oncePTYClose.Do(func() {
				self.ptm.Close()
				self.pts.Close()
				self.ptm = nil
				self.pts = nil
			})
			log.Debugf("Client '%s': Closed PTY\n", self.identifier)
		}()
		defer func() {
			if self.wsch != nil {
				log.Debugf("Client '%s': Closing wsch chan\n", self.identifier)
				//signal.Stop(self.wsch) //NOTE Needed?
				close(self.wsch)
			}
		}()

	} else {
	    cmd, err = self.runCommand([]string{payloadCmd})
    }
	err = cmd.Wait()

	if err != nil {
		log.Errorf("Client '%s': Command exit error: %v\n", self.identifier, err)
	}
	log.Debugf("Client '%s': Spawned process exited\n", self.identifier)
}

func (self *Client) spawnShell() (res bool, reply []byte) {
    var cmd *exec.Cmd
    var err error
    if self.pts != nil {
	    cmd, err = self.runPTYCommand([]string{})
    } else {
	    cmd, err = self.runCommand([]string{})
    }
    if err != nil {
        log.Errorf("Client '%s': Failed to spawn shell: %v\n", self.identifier, err)
        reply = []byte(fmt.Sprintf("Failed to spawn shell: %v", err))
        return
    }
    //log.Debugf("cmd: %v\n", cmd)
    //log.Debugf("cmd pid: %d\n", cmd.Process.Pid)

    go func() {
	    defer func() {
            //log.Debugln("Setting cmd = nil")
	    	cmd = nil
	    }()

	    // Close session
	    defer func() {
	    	self.sessionChan.Close()
	    }()

	    if self.pts != nil {
	    	// Close PTY
	    	defer func() {
	    		self.oncePTYClose.Do(func() {
	    			self.ptm.Close()
	    			self.pts.Close()
	    			self.ptm = nil
	    			self.pts = nil
	    		})
	    		log.Debugf("Client '%s': Closed PTY\n", self.identifier)
	    	}()

	    	defer func() {
	    		//signal.Stop(self.wsch) //NOTE needed?
	    		close(self.wsch)
	    	}()
	    }

	    err = cmd.Wait()
	    if err != nil {
	    	log.Errorf("Client '%s': Shell process exit error: %v\n", self.identifier, err)
	    }
	    log.Debugf("Client '%s': Spawned process exited\n", self.identifier)
    }()
    res = true
	return
}

func (self *Client) runCommand(args []string) (cmd *exec.Cmd, err error) {
	if len(args) == 0 {
		// No args so a normal shell
		cmd = exec.Command(NON_PTY_SHELL)
	} else {
		args = append([]string{NON_PTY_EXEC_FLAG}, args...)
		cmd = exec.Command(NON_PTY_EXEC, args...)
	}

	var stdinPipe io.WriteCloser
	var stdoutPipe, stderrPipe io.ReadCloser
	stdinPipe, err = cmd.StdinPipe()
	if err != nil {
		log.Errorf("Client '%s': Error: %v\n", self.identifier, err)
		return
	}
	stdoutPipe, err = cmd.StdoutPipe()
	if err != nil {
		log.Errorf("Client '%s': Error: %v\n", self.identifier, err)
		return
	}
	stderrPipe, err = cmd.StderrPipe()
	if err != nil {
		log.Errorf("Client '%s': Error: %v\n", self.identifier, err)
		return
	}

	// If using self.sessionChan directly, the process hangs after completion until any data is sent on stdin
	// Has something to do with self.sessionChan not being an *os.File and thus cmd.Exec behaves strangely.
	// Can solve it by using a pipe.
	//cmd.Stdin = self.sessionChan
	//cmd.Stdout = self.sessionChan
	//cmd.Stderr = self.sessionChan
	err = cmd.Start()
	if err != nil {
		log.Infof("Client '%s': Error: %v\n", self.identifier, err)
		return
	}
	go func() {
		io.Copy(self.sessionChan, stdoutPipe)
		log.Debugf("Client '%s': Stopped io.Copy from stdoutPipe to session channel", self.identifier)
	}()
	go func() {
		io.Copy(self.sessionChan, stderrPipe)
		log.Debugf("Client '%s': Stopped io.Copy from stderrPipe to session channel", self.identifier)
	}()
	go func() {
		io.Copy(stdinPipe, self.sessionChan)
		log.Debugf("Client '%s': Stopped io.Copy from session channel to stdinPipe", self.identifier)
		// Probably means client pressed ctrl-d so exit process to prevent hanging connection
		//cmd.Process.Signal(unix.SIGTERM)
		cmd.Process.Signal(syscall.SIGKILL)
	}()

	return
}

func (self *Client) handleRequests(in <-chan *ssh.Request) {
	//Sessions have out-of-band but in-channel requests such as "shell", "env", "pty-req" and "window-change",
	for req := range in {
		switch req.Type {
		case "pty-req":
            pr := ptyRequestMsg{}
	        if err := ssh.Unmarshal(req.Payload, &pr); err != nil {
			    log.Errorf("Client '%s': Failed to parse pty-req payload: %v\n", self.identifier, err)
                req.Reply(false, nil)
                continue
	        }
			log.Debugf("Client '%s': Received request to allocated a PTY with term: %s\n", self.identifier, pr.Term)
			if self.ptm != nil {
				log.Noticef("Client '%s': Received another request to spawn pty. Ignoring.\n", self.identifier)
				req.Reply(false, nil)
				continue
			}
			// Sanity check of the passed term
			if termRegex.MatchString(pr.Term) {
				self.term = "TERM=" + pr.Term
			} else {
				log.Infof("Client '%s': Received invalid TERM variable from client: %s\n", self.identifier, pr.Term)
				self.term = "TERM=xterm"
			}
			//ws := &unix.Winsize{}
            ws := &winsize{
                Col: uint16(pr.Columns),
                Row: uint16(pr.Rows),
                Xpixel: uint16(pr.Width),
                Ypixel: uint16(pr.Height),
            }
			self.ws = ws

			ptm, pts, err := newPTY()
			if err != nil {
				log.Errorf("Client '%s': Failed to spawn new PTY: %v\n", self.identifier, err)
				req.Reply(false, nil)
				continue
			}
			self.ptm = ptm
			self.pts = pts
			defer self.oncePTYClose.Do(func() {
				self.ptm.Close()
				self.pts.Close()
				self.ptm = nil
				self.pts = nil
			})

			req.Reply(true, nil)
		case "shell":
			log.Debugf("Client '%s': Received request to spawn shell\n", self.identifier)
            log.Debugln(req)
			//req.Reply(true, nil)
			req.Reply(self.spawnShell())
		case "window-change":
			if self.ws == nil {
				log.Noticef("Client '%s': Unexpected window-change request before pty-req. Ignoring\n", self.identifier)
				break
			}
			// Read dimensions from payload
			self.ws.Col = uint16(binary.BigEndian.Uint32(req.Payload[0:4]))
			self.ws.Row = uint16(binary.BigEndian.Uint32(req.Payload[4:8]))
			//self.wsch <- syscall.SIGWINCH
			self.wsch <- MYSIGWINCH
		case "exec":
			log.Debugf("Client '%s': Received exec request: %v\n", self.identifier, req)
			go self.execCommand(req.Payload)
			req.Reply(true, nil)
		case "env":
			req.Reply(false, nil)
		default:
			log.Noticef("Client '%s': Received unhandled request: %v\n", self.identifier, req)
			req.Reply(false, nil)
		}
	}
	log.Debugf("Client '%s': Stopped handling requests for session channel\n", self.identifier)
}

func (self *Client) handleReverseForward(l net.Listener) {
	defer log.Debugf("Client '%s': Closed remote listener: %s\n", self.identifier, l.Addr())
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
			log.Errorf("Client '%s': Error %v\n", self.identifier, err)
			continue
		}
		bindAddr, bindPortStr, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", self.identifier, err)
			conn.Close()
			continue
		}
		bindPort, err := strconv.Atoi(bindPortStr)
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", self.identifier, err)
			conn.Close()
			continue
		}

		originAddr, originPortStr, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", self.identifier, err)
			conn.Close()
			continue
		}
		originPort, err := strconv.Atoi(originPortStr)
		if err != nil {
			// Can this ever happen?
			log.Errorf("Client '%s': Error %v\n", self.identifier, err)
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
		log.Debugf("Client '%s': Attempting to open channel to forward traffic from %s:%d to %s:%d\n", self.identifier, r.OriginHost, r.OriginPort, r.DestHost, r.DestPort)
		payload := ssh.Marshal(&r)
		channel, reqs, err := self.conn.OpenChannel("forwarded-tcpip", payload)
		if err != nil {
			log.Errorf("Client '%s': Failed to open forwarded-tcpip channel: %v\n", self.identifier, err)
			conn.Close()
			continue
		}
		// Don't think I need these?
		go ssh.DiscardRequests(reqs)
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

func (c *Client) handleForward(newChannel ssh.NewChannel) {
	d := localForwardChannelData{}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &d); err != nil {
		log.Errorln(err)
		newChannel.Reject(ssh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
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
	go ssh.DiscardRequests(requests)
	//go func (in <-chan *ssh.Request) {
	//    for req := range in {
	//        log.Debugf("Received request: %v\n", req)
	//        req.Reply(false, nil)
	//    }
	//}(requests)

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
			//defer c.sessionChan.Close()
			defer func() {
				c.sessionChan.Close()
				log.Debugf("Client '%s': Closed session channel\n", c.identifier)
			}()
			go c.handleRequests(requests)
		} else if newChannel.ChannelType() == "direct-tcpip" {
			log.Debugf("Client '%s': Received request for direct-tcpip\n", c.identifier)
			c.handleForward(newChannel)
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
	// Handle tcpip-forward requests
	for req := range in {
		switch req.Type {
		case "tcpip-forward":
			// Wants a response
			r := reverseForwardRequest{}
			if err := ssh.Unmarshal(req.Payload, &r); err != nil {
				log.Errorf("Client '%s': Failed to unmarshal request payload: %v\n", self.identifier, err)
				req.Reply(false, nil)
				continue
			}
			//TODO check if addr is domain name or ip. Probably limit to only support ipv4 addresses
			// Optionally limit to only listen on localhost?
			log.Debugf("Client '%s':tcpip-forward with bindaddr: %s\n", self.identifier, r.BindAddr)
			if r.BindAddr == "" {
				r.BindAddr = "0.0.0.0"
			} else {
				bindIP := net.ParseIP(r.BindAddr)
				//NOTE Might introduce problem if I request forward for 127.0.0.1:1234 then localhost:1234 ?
				if (bindIP == nil) && (r.BindAddr != "localhost") {
					// Hostname or invalid ip
					log.Debugf("Client '%s': tcpip-forward request with invalid ip\n", self.identifier)
					req.Reply(false, nil)
					continue
				}
			}
			log.Debugf("Client '%s': Sent tcpip-forward request with listen address: %s and port: %d\n", self.identifier, r.BindAddr, r.BindPort)
			// Setup a socket and listener and be ready to forward any incoming connections via a newChannel request
			listenAddr := net.JoinHostPort(r.BindAddr, strconv.FormatInt(int64(r.BindPort), 10))
			l, err := net.Listen("tcp", listenAddr)
			if err != nil {
				log.Debugf("Client '%s': tcpip-forward request failed to start listener: %v\n", self.identifier, err)
				req.Reply(false, nil)
				continue
			}
			// Need to check bindport in case client requested a bind for port 0 e.g, assign me a port
			_, bindPortStr, err := net.SplitHostPort(l.Addr().String())
			if err != nil {
				log.Errorf("Client '%s': tcpip-forward request failed to parse assigned listening port: %v\n", self.identifier, err)
				l.Close()
				req.Reply(false, nil)
				continue
			}
			bindPort, err := strconv.Atoi(bindPortStr)
			if err != nil {
				log.Errorf("Client '%s': tcpip-forward request failed to parse int of assigned listening port: %v\n", self.identifier, err)
				l.Close()
				req.Reply(false, nil)
				continue
			}
			// Must close listener if shutdown before receiving cancel-tcpip-forward.
			defer l.Close()
			self.reverseForwards[listenAddr] = l // Shouldn't need a pointer to an interface
			go self.handleReverseForward(l)
			payload := ssh.Marshal(&reverseForwardSuccess{uint32(bindPort)})
			req.Reply(true, payload)
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
				val.Close()
				delete(self.reverseForwards, listenAddr)
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

func main() {
	watchdogDuration, err := time.ParseDuration("168h")
    if err != nil {
        log.Criticalln(err)
        return
    }
    go watchdog(watchdogDuration)

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetLogLevel(6)
	// Public key authentication is done by comparing the public key of a
	// received connection with the entries in the authorized_keys file
	// included by go:embed authorized_keys
	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Criticalln(err)
			return
		}
		/* NOTE consider using a struct as value for map to add info such as
		   comment from the authorized_keys file. Could be used to store allowed
		   username to connect a public key to a username that owns the key
		   and then validate the username against the struct in the callback.
		*/

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		//PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		//	// Should use constant-time compare (or better, salt+hash) in
		//	// a production setting.
		//	if c.User() == "user" && string(pass) == "tiger" {
		//		return nil, nil
		//	}
		//	return nil, fmt.Errorf("password rejected for %q", c.User())
		//},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
	private, err := ssh.ParsePrivateKey(pemdata)
	if err != nil {
		log.Criticalf("Failed to parse private key: %v", err)
		return
	}

	config.AddHostKey(private)

	//TODO add flag or build option to specify listen port?
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
		c := Client{
			conn:            conn,
			identifier:      fmt.Sprintf("%s@%s", conn.User(), conn.RemoteAddr().String()),
			reverseForwards: make(map[string]net.Listener),
		}
		log.Noticef("Client '%s' logged in with password.", c.identifier)
		//log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

		// The incoming Request channel must be serviced.
		go c.handleOOCRequests(reqs)
		// Handle new channel opening requests
		go c.handleNewChannels(chans)
	}
}
