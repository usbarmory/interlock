// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"log"
	"log/syslog"
	"os"
	"path/filepath"
)

func EnableSyslog() {
	if conf.logFile != nil {
		conf.logFile.Close()
	}

	log.Println("switching to syslog")
	logwriter, err := syslog.New(syslog.LOG_INFO, "interlock")

	if err != nil {
		log.Fatal(err)
	}

	log.SetFlags(0)
	log.SetOutput(logwriter)
}

func EnableFileLog() {
	if conf.logFile != nil {
		conf.logFile.Close()
	}

	logPath := filepath.Join(conf.MountPoint, ".interlock.log")
	log.Printf("switching to log file %s", logPath)
	logwriter, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)

	if err != nil {
		status.Log(syslog.LOG_ERR, "could not switch to log file %s: %v", logPath, err)
	}

	conf.logFile = logwriter
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(conf.logFile)
}
