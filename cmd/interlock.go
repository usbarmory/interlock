// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/inversepath/interlock/internal"
)

var configPath = flag.String("c", "interlock.conf", "configuration file path")

var debug bool
var test bool
var addr string

func init() {
	if os.Geteuid() == 0 {
		log.Fatal("Please do not run this application with administrative privileges")
	}

	flag.BoolVar(&debug, "d", false, "debug mode")
	flag.BoolVar(&test, "t", false, "test mode (WARNING: disables authentication)")
	flag.StringVar(&addr, "b", "0.0.0.0:4430", "binding address:port pair")
}

func main() {
	conf := interlock.GetConfig()
	conf.SetDefaults()

	// Ensure that no temporary file from Go internal functions end up in
	// unencrypted space (relevant only after luksMount() but applied
	// ASAP).
	os.Setenv("TMPDIR", conf.MountPoint)

	flag.Parse()

	conf.Debug = debug
	conf.TestMode = test
	conf.BindAddress = addr

	if conf.TestMode {
		log.Println("*** WARNING *** authentication disabled (test mode switch enabled)")
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(os.Stdout)

	log.Printf("starting INTERLOCK %s - %s\n", interlock.Revision, interlock.Build)

	if *configPath != "" {
		err := conf.Set(*configPath)

		if err != nil {
			log.Fatal(err)
		}

		log.Printf("configuration file %s successfully parsed", *configPath)
	}

	err := conf.SetMountPoint()

	if err != nil {
		log.Fatal(err)
	}

	err = conf.EnableCiphers()

	if err != nil {
		log.Fatal(err)
	}

	err = conf.EnableHSM()

	if err != nil {
		log.Fatal(err)
	}

	conf.Print()

	if conf.Debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		log.Println("debug mode enabled")
	} else {
		interlock.EnableSyslog()
	}

	err = interlock.StartServer()

	if err != nil {
		fmt.Println(err)
		log.Fatal(err)
	}
}
