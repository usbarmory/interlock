// INTERLOCK | https://github.com/usbarmory/interlock
// Copyright (c) WithSecure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

// +build linux

package main

import (
	"flag"
	"log"
	"os"

	"github.com/usbarmory/interlock/internal"
)

func init() {
	log.SetOutput(os.Stdout)
}

func main() {
	var op string

	conf := interlock.GetConfig()
	conf.SetDefaults()

	flag.BoolVar(&conf.Debug, "d", false, "debug mode")
	flag.BoolVar(&conf.TestMode, "t", false, "test mode (WARNING: disables authentication)")
	flag.StringVar(&conf.BindAddress, "b", interlock.BindAddress, "binding address:port pair")
	flag.StringVar(&op, "o", "", "operation ((open:<volume>)|close|derive:<data>)")

	var configPath = flag.String("c", "interlock.conf", "configuration file path")

	// Ensure that no temporary file from Go internal functions end up in
	// unencrypted space (relevant only after luksMount() but applied
	// ASAP).
	os.Setenv("TMPDIR", conf.MountPoint)

	flag.Parse()

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

	if err := conf.SetMountPoint(); err != nil {
		log.Fatal(err)
	}

	if err := conf.EnableCiphers(); err != nil {
		log.Fatal(err)
	}

	if err := conf.EnableHSM(); err != nil {
		log.Fatal(err)
	}

	if op != "" {
		if err := interlock.Op(op); err != nil {
			log.Fatal(err)
		}

		return
	}

	conf.Print()

	if conf.Debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		log.Println("debug mode enabled")
	} else {
		interlock.EnableSyslog()
	}

	srv, err := interlock.ConfigureServer()

	if err != nil {
		log.Fatal(err)
	}

	if err := interlock.StartServer(srv); err != nil {
		log.Fatal(err)
	}
}
