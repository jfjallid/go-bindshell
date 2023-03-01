package main

/*
An authenticated bind shell using SSH and public key authentication
with support for dynamic (socks) and static port forwarding
Due to some dependencies on spawning a PTY, this will only work on linux
distributions. Limitations are in the opening of the /dev/ptmx device.

Use this program at your own risk.

Created: 2022
Author:
Jimmy Fjällid
*/

import (
	"fmt"
	"strconv"

	"github.com/jfjallid/golog"

	_ "embed"
	"os"
	"time"
)

var (
    bindPortStr = "2022"
    log = golog.Get("")
)


func watchdog(duration time.Duration) {
	t := time.NewTimer(duration)
	<-t.C
	log.Infoln("Watchdog fired! Exiting process")
	os.Exit(0)
}

func main() {
	//    // Don't run after
	//    longForm := "Jan 2, 2006 at 3:04pm (MST)"
	//    tPree, err := time.Parse(longForm, "Feb 17, 2023 at 11:45am (CET)")
	//    if err != nil {
	//        return
	//    }
	//    tAfter, err := time.Parse(longForm, "Feb 17, 2023 at 4:00pm (CET)")
	//    if err != nil {
	//        return
	//    }
	//    currentTime := time.Now()
	//    if (currentTime.After(tAfter)) || (currentTime.Before(tPree)) {
	//        return
	//    }

	// Run max 1 week
	watchdogDuration, err := time.ParseDuration("168h")
	if err != nil {
		log.Criticalln(err)
		return
	}
	go watchdog(watchdogDuration)

	log.SetFlags(golog.LstdFlags | golog.Lshortfile)
	log.SetLogLevel(golog.LevelNotice)
	//log.SetLogLevel(log.LevelDebug)

    bindPort, err := strconv.Atoi(bindPortStr)
    if err != nil {
        log.Errorln(err)
        return
    }

    NewServer(fmt.Sprintf("0.0.0.0:%d", bindPort))
}
