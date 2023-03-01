package main

import (
	"os"
	"os/exec"
	//"os/signal"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"strconv"
)


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
	//log.Debugf("Attempting to get ptsname of slave PTS for PTM: %s with FD: %d\n", f.Name(), int(f.Fd()))
	fd, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPTN)
	if err != nil {
		log.Errorf("Failed on ioctl(2) to get file descriptor of PTS: %v", err)
		return "", err
	}
	sname = "/dev/pts/" + strconv.Itoa(fd)
	//log.Debugf("PTS has sname: %s\n", sname)
	return
}

func unlockpt(f *os.File) (err error) {
	ret, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCSPTLCK)
	if (err == nil) && (ret != 0) {
		log.Errorf("Received no error but return code was non-zero which, indicates an error?")
		err = fmt.Errorf("nil error but non-zero return code. Strange")
	}
	return
}

func (self *Client) runPTYCommand(args []string) (cmd *exec.Cmd, err error) {
	if len(args) == 0 {
		// No args so a normal shell
		cmd = exec.Command(PTY_SHELL, PTY_SHELL_FLAG)
	} else {
		args = append([]string{PTY_EXEC_FLAG}, args...)
		cmd = exec.Command(PTY_EXEC, args...)
	}

	cmd.Env = append(cmd.Environ(), self.term)
	cmd.Stdout = self.pts
	cmd.Stderr = self.pts
	cmd.Stdin = self.pts
	// Setting Setsid and Setctty to connect PTS to process properly with a process group
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}
	go func() {
		io.Copy(self.sessionChan, self.ptm)
		log.Debugf("Client '%s': Stopped io.Copy from PTY to session channel", self.identifier)
	}()
	go func() {
		io.Copy(self.ptm, self.sessionChan)
		log.Debugf("Client '%s': Stopped io.Copy from session channel to PTY", self.identifier)
	}()
	err = cmd.Start()
	if err != nil {
		log.Errorf("Client '%s': Error: %v\n", self.identifier, err)
		return
	}
	self.wsch = make(chan os.Signal, 1)
	//signal.Notify(self.wsch, unix.SIGWINCH) //NOTE Needed?
	go func() {
		for range self.wsch {
			unixWS := unix.Winsize{Row: self.ws.Row, Col: self.ws.Col, Xpixel: self.ws.Xpixel, Ypixel: self.ws.Ypixel}
			err := unix.IoctlSetWinsize(int(self.pts.Fd()), unix.TIOCSWINSZ, &unixWS)
			if err != nil {
				log.Errorf("Client '%s': Failed to resize pty of process: %v\n", self.identifier, err)
			}
			if (cmd != nil) && (cmd.Process != nil) {
				cmd.Process.Signal(unix.SIGWINCH)
			}
		}
	}()
	// Send initial resize
	self.wsch <- unix.SIGWINCH // Can probably use any type of channel here since I only handle one type of signal

	return
}
