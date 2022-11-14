package main

/*
An attempt to build a secure authenticated bind shell using SSH and public key
authentication. Due to some dependencies on spawning a PTY, this will only work
on linux distributions. Limitations are in the opening of the /dev/ptmx device.

Copyright Jimmy Fjällid 2022
*/

import (
	log "github.com/jfjallid/golog"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
    "regexp"
    "sync"
)

var (
    termRegex = regexp.MustCompile("[a-z0-9-]")
    oncePTYClose sync.Once
)

type Client struct {
    conn        ssh.Conn
    ptm         *os.File
    pts         *os.File
    sessionChan ssh.Channel
    term        string
    ws          *unix.Winsize
    wsch        chan os.Signal
}

type ptyRequestMsg struct {
    Term        string
    Columns     uint32
    Rows        uint32
    Width       uint32
    Height      uint32
    Modelist    string
}

func newPTY() (ptm, pts *os.File, err error) {
    ptm, err = os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
    if err != nil {
        log.Errorln("Failed to open /dev/ptmx: ", err)
        return
    }
    // If we fail we should attempt to close the PTY
    defer func() {
        if err != nil {
            ptm.Close()
        }
    }()
    
    // Get path to PTS
    sname, err := ptsname(ptm)
    if err != nil {
        log.Errorln(err)
        return
    }

    //NOTE How to call grantpt() from Golang? Seems to be an ioctl operation
    //called TIOCPTYGRANT but it is not defined in the unix syscall package

    err = unlockpt(ptm)
    if err != nil {
        log.Errorln(err)
        return
    }
    pts, err = os.OpenFile(sname, os.O_RDWR|unix.O_NOCTTY, 0)
    if err != nil {
        log.Errorf("Failed to open %s with error: %v", sname, err)
        return
    }

    return
}

func ptsname(f *os.File) (sname string, err error) {
    log.Debugf("Attempting to get ptsname of slave PTS for PTM: %s with FD: %d\n", f.Name(), int(f.Fd()))
    fd, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPTN)
    if err != nil {
        log.Errorf("Failed on ioctl(2) to get file descriptor of PTS: %v", err)
        return "", err
    }
    sname = "/dev/pts/" + strconv.Itoa(fd)
    log.Debugf("PTS has sname: %s\n", sname)
    // Perhaps check that the PTS exists with Stat or similar method?
    return
}

func unlockpt(f *os.File) (err error) {
    ret, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCSPTLCK)
    if (err == nil) && (ret != 0) {
        log.Errorln("Received no error but return code was non-zero which, indicates an error?")
        err = fmt.Errorf("nil error but non-zero return code. Strange")
    }
    return
}

func (self *Client) spawnShell(payload []byte){
    //log.Debugf("Received request to spawn shell with payload: %s\n", payload)
    cmd := exec.Command("/bin/bash", "-l", "-i")
    defer func(){
        cmd=nil
    }()
    cmd.Env = append(cmd.Environ(), self.term)

    // Close session
    defer func() {
        self.sessionChan.Close()
    }()

    if self.pts != nil {
        // Close PTY
        defer func() {
            oncePTYClose.Do(func() {
                self.ptm.Close()
                self.pts.Close()
                self.ptm = nil
                self.pts = nil
            })
            log.Debugln("Closed PTY")
        }()

        cmd.Stdout = self.pts
        cmd.Stderr = self.pts
        cmd.Stdin = self.pts
        // Setting Setsid and Setctty to connect PTS to process properly with a process group
        cmd.SysProcAttr = &unix.SysProcAttr {
            Setsid: true,
            Setctty: true,
        }
        //NOTE Need some way to close these? Use a context? Use my own version
        // of io.Copy from gocat?
        go func() {
            io.Copy(self.sessionChan, self.ptm)
            log.Debugln("Stopped io.Copy from PTY to session channel")
        }()
        go func() {
            io.Copy(self.ptm, self.sessionChan)
            log.Debugln("Stopped io.Copy from session channel to PTY")
        }()
        err := cmd.Start()
        if err != nil {
            log.Errorln(err)
            return
        }
        self.wsch = make(chan os.Signal, 1)
        signal.Notify(self.wsch, unix.SIGWINCH)
        go func() {
            for range self.wsch {
                //ws, err := unix.IoctlGetWinsize(int(self.ptm.Fd()), unix.TIOCSWINSZ)
                //if err != nil {
                //    log.Errorf("Failed to get windows size of PTM: %v\n", err)
                //}
                err := unix.IoctlSetWinsize(int(self.pts.Fd()), unix.TIOCSWINSZ, self.ws)
                if err != nil {
                    log.Errorf("Failed to resize pty of process: %v\n", err)
                }
//                defer func() {
//                    if err := recover(); err != nil {
//                        log.Debugf("panic occurred: %v\n", err)
//                        log.Debugf("cmd.Process: %v\n", cmd.Process)
//                    }
//                }()
                if (cmd != nil) && (cmd.Process != nil) {
                    cmd.Process.Signal(unix.SIGWINCH)
                }
            }
        }()
        // Send initial resize
        self.wsch <-unix.SIGWINCH

        // Cleanup. Perhaps better done in dedicated function to avoid write on closed chan?
        defer func() {
            signal.Stop(self.wsch)
            close(self.wsch)
        }()
    } else {
        outPipe, err := cmd.StdoutPipe()
        if err != nil {
            log.Errorln(err)
            return
        }
        errPipe, err := cmd.StderrPipe()
        if err != nil {
            log.Errorln(err)
            return
        }
        inPipe, err := cmd.StdinPipe()
        if err != nil {
            log.Errorln(err)
            return
        }
        go io.Copy(self.sessionChan, outPipe)
        go io.Copy(self.sessionChan, errPipe)
        go io.Copy(inPipe, self.sessionChan)
        defer func(){
            inPipe.Close()
            outPipe.Close()
            errPipe.Close()
        }()
    }
    err := cmd.Wait()
    if err != nil {
        log.Errorf("Shell process exit error: %v\n", err)
    }
    log.Debugln("Spawned process exited")
    return
}

func (self *Client) handleRequests(in <-chan *ssh.Request) {
	//Sessions have out-of-band requests such as "shell", "env", "pty-req" and "window-change",
	for req := range in {
        switch req.Type {
        case "pty-req":
            termLen := req.Payload[3]
            termEnv := string(req.Payload[4:termLen+4])
            log.Debugf("Received request to allocated a PTY with term: %s\n", termEnv)
            if self.ptm != nil {
                log.Noticeln("Received another request to spawn pty. Ignoring.")
                req.Reply(false, nil)
                continue
            }
            // Do I need any sanity check of the passed term?
            if termRegex.MatchString(termEnv) {
                self.term = "TERM="+termEnv
            } else {
                log.Infof("Received invalid TERM variable from client: %s\n", termEnv)
                self.term = "TERM=xterm"
            }
            ws := &unix.Winsize{}
            ws.Col = uint16(binary.BigEndian.Uint32(req.Payload[termLen+4:]))
            ws.Row = uint16(binary.BigEndian.Uint32(req.Payload[termLen+4+4:]))
            self.ws = ws
            
            ptm, pts, err := newPTY()
            if err != nil {
                log.Errorf("Failed to spawn new PTY: %v\n", err)
                req.Reply(false, nil)
                continue
            }
            self.ptm = ptm
            self.pts = pts
            //NOTE Is this the wrong place to close the PTY?
            //defer self.ptm.Close()
            //defer self.pts.Close()
            defer oncePTYClose.Do(func() {
                self.ptm.Close()
                self.pts.Close()
                self.ptm = nil
                self.pts = nil
            })

            req.Reply(true, nil)
        case "shell":
            // Check if payload is empty, otherwise there is a command there?
            req.Reply(true, nil)
            go self.spawnShell(req.Payload)
        case "window-change":
            if self.ws == nil {
                log.Noticeln("Unexpected window-change request before pty-req. Ignoring")
                break
            }
            // Read dimensions from payload
            self.ws.Col = uint16(binary.BigEndian.Uint32(req.Payload[0:4]))
            self.ws.Row = uint16(binary.BigEndian.Uint32(req.Payload[4:8]))
            //self.ws.Xpixel = uint16(binary.BigEndian.Uint32(req.Payload[8:12]))
            //self.ws.Ypixel = uint16(binary.BigEndian.Uint32(req.Payload[12:16]))
            //log.Debugf("Changing window size to Row: %d, Col: %d, X: %d, Y: %d\n", self.ws.Row, self.ws.Col, self.ws.Xpixel, self.ws.Ypixel)
            //err := unix.IoctlSetWinsize(int(self.pts.Fd()), unix.TIOCSWINSZ, self.ws)
            //if err != nil {
            //    log.Errorf("Failed to change window size of pty: %v\n", err)
            //}
            self.wsch <-unix.SIGWINCH
        case "exec":

        case "env":
            break
        default:
            log.Noticef("Received unhandled request: %v\n", req)
            req.Reply(false, nil)
        }
	}
}

func main() {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
    log.SetFlags(log.LstdFlags|log.Lshortfile)
    log.SetLogLevel(6)
	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if c.User() == "user" && string(pass) == "tiger" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Criticalf("Failed to gen privateKey: %v", err)
        return
    }

    pemdata := pem.EncodeToMemory(
        &pem.Block{
            Type: "RSA PRIVATE KEY",
            Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
        },
    )
	private, err := ssh.ParsePrivateKey(pemdata)
	if err != nil {
		log.Criticalf("Failed to parse private key: %v", err)
        return
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Criticalf("failed to listen for connection: %v", err)
        return
	}
    defer listener.Close()

	nConn, err := listener.Accept()
	if err != nil {
		log.Criticalf("failed to accept incoming connection: %v", err)
        return
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Errorf("failed to handshake: %v", err)
        return
	}
    defer conn.Close()
    c := Client{
        conn: conn,
    }
    log.Noticef("%s logged in with password.", conn.User())
	//log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	// The incoming Request channel must be serviced.
	//go ssh.DiscardRequests(reqs)
    go func(in <-chan *ssh.Request) {
        for req := range in {
            log.Noticef("Discarding request on original request channel: %v\n", req)
            if req.WantReply {
                req.Reply(false, nil)
            }
        }
    }(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
            log.Noticef("Unknown channelType: %v\n", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
        //If I decice to support mutiple channel types I must check here if it
        //is a session channel before rejecting.
        if c.sessionChan != nil {
            newChannel.Reject(ssh.ResourceShortage, "Already opened a session channel")
            continue
        }
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Noticef("Could not accept channel: %v", err)
		}
        //defer channel.Close()
        //Currently only a single session channel is supported,
        //others will be rejected
        c.sessionChan = channel
        //NOTE What do I do with a channel if there is no incoming shell request?
        //E.g., when do I close it? Do I read anything from it?

        go c.handleRequests(requests)
	}
}
