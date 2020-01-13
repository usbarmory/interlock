// INTERLOCK | https://github.com/f-secure-foundry/interlock
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

	"github.com/f-secure-foundry/interlock/internal"
)

var configPath = flag.String("c", "interlock.conf", "configuration file path")

var debug bool
var test bool
var addr string
var op string

func init() {
	flag.BoolVar(&debug, "d", false, "debug mode")
	flag.BoolVar(&test, "t", false, "test mode (WARNING: disables authentication)")
	flag.StringVar(&addr, "b", "0.0.0.0:4430", "binding address:port pair")
	flag.StringVar(&op, "o", "", "operation ((open:<volume>)|close|derive:<data>)")

	log.SetOutput(os.Stdout)
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

	if op == "" {
		if os.Geteuid() == 0 {
			log.Fatal("Please do not run this application with administrative privileges")
		}

		if conf.TestMode {
			log.Println("*** WARNING *** authentication disabled (test mode switch enabled)")
		}

		log.SetFlags(log.Ldate | log.Ltime)

		if interlock.Revision == "" && interlock.Build == "" {
			log.Printf("starting INTERLOCK\n")
		} else {
			log.Printf("starting INTERLOCK %s - %s\n", interlock.Revision, interlock.Build)
		}
	} else {
		log.SetFlags(0)
	}

	if *configPath != "" {
		err := conf.Set(*configPath)

		if err != nil {
			log.Fatal(err)
		}

		if op == "" {
			log.Printf("configuration file %s successfully parsed", *configPath)
		}
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

	if op != "" {
		err = interlock.Op(op)
	} else {
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
		}
	}

	if err != nil {
		log.Fatal(err)
	}
}
