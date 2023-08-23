package main

import (
	"fmt"
	"os"
	"os/exec"
)

func newPTY() (ptm, pts *os.File, err error) {
	return nil, nil, fmt.Errorf("PTY not supported on Windows")
}

func (self *Client) runPTYCommand(args []string) (cmd *exec.Cmd, err error) {
	return nil, fmt.Errorf("Running PTY commands are not supported on Windows")
}
