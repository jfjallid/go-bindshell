package main

/*
An authenticated bind shell built upon SSH with support for dynamic (socks)
and static port forwarding.
Supports certificate, public key, and password authentication.
Due to some dependencies on spawning a PTY, this will only work on linux
distributions. Limitations are in the opening of the /dev/ptmx device.

Use this program at your own risk.

Created: 2022
Author:
Jimmy Fjällid
*/

import (
	_ "embed"
	"fmt"
	"github.com/jfjallid/golog"
	"os"
	"strconv"
	"time"
)

var (
	bindPortStr = "2022"
	log         = golog.Get("")
)

func watchdog(duration time.Duration) {
	t := time.NewTimer(duration)
	<-t.C
	log.Infoln("Watchdog fired! Exiting process")
	os.Exit(0)
}

func main() {

	//// Run max 1 week
	//watchdogDuration, err := time.ParseDuration("168h")
	//if err != nil {
	//	log.Criticalln(err)
	//	return
	//}
	//go watchdog(watchdogDuration)

	log.SetLogLevel(golog.LevelNotice)
	//log.SetFlags(golog.LstdFlags | golog.Lshortfile)
	//log.SetLogLevel(golog.LevelDebug)

	bindPort, err := strconv.Atoi(bindPortStr)
	if err != nil {
		log.Errorln(err)
		return
	}

	NewServer(fmt.Sprintf("0.0.0.0:%d", bindPort))
}
