//go:build shell

package main

import (
	"golang.org/x/crypto/ssh"
	//"os/signal"
	"syscall"
    "encoding/binary"
	"io"
	"os/exec"
    "fmt"
)

func init() {
      features["shell"] = spawnShell
      features["exec"] = execCommand
      features["pty-req"] = handlePTYReq
}

func spawnShell(self *Client) (res bool, reply []byte) {
	var cmd *exec.Cmd
	var err error
	if self.pts != nil {
		cmd, err = self.runPTYCommand([]string{})
	} else {
		cmd, err = runCommand(self, []string{})
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

func execCommand(self *Client, payload []byte) {
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
		cmd, err = runCommand(self, []string{payloadCmd})
	}
	err = cmd.Wait()

	if err != nil {
		log.Errorf("Client '%s': Command exit error: %v\n", self.identifier, err)
	}
	log.Debugf("Client '%s': Spawned process exited\n", self.identifier)
}


func runCommand(self *Client, args []string) (cmd *exec.Cmd, err error) {
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

func handlePTYReq(self *Client, payload []byte) (bool, []byte) {
	pr := ptyRequestMsg{}
	if err := ssh.Unmarshal(payload, &pr); err != nil {
		log.Errorf("Client '%s': Failed to parse pty-req payload: %v\n", self.identifier, err)
        return false, nil
	}
	log.Debugf("Client '%s': Received request to allocated a PTY with term: %s\n", self.identifier, pr.Term)
	if self.ptm != nil {
		log.Noticef("Client '%s': Received another request to spawn pty. Ignoring.\n", self.identifier)
        return false, nil
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
		Col:    uint16(pr.Columns),
		Row:    uint16(pr.Rows),
		Xpixel: uint16(pr.Width),
		Ypixel: uint16(pr.Height),
	}
	self.ws = ws

	ptm, pts, err := newPTY()
	if err != nil {
		log.Errorf("Client '%s': Failed to spawn new PTY: %v\n", self.identifier, err)
        return false, nil
	}
	self.ptm = ptm
	self.pts = pts

    return true, nil
}
