// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"syscall"
)

var configPath = flag.String("c", "", "configuration file path")

func init() {
	if syscall.Geteuid() == 0 {
		log.Fatal("Please do not run this application with administrative privileges")
	}

	conf.SetDefaults()

	// ensure that no temporary file from Go internal functions end up in
	// unencrypted space (relevant only after luksMount() but applied asap)
	os.Setenv("TMPDIR", conf.mountPoint)

	flag.BoolVar(&conf.Debug, "d", false, "debug mode")
	flag.BoolVar(&conf.testMode, "t", false, "test mode (WARNING: disables authentication)")
	flag.StringVar(&conf.BindAddress, "b", "127.0.0.1:4430", "binding address:port pair")

	flag.Parse()

	if conf.testMode {
		log.Println("*** WARNING *** authentication disabled (test mode switch enabled)")
	}
}

func main() {
	var err error

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(os.Stdout)

	if err != nil {
		fmt.Println(err)
		return
	}

	if *configPath != "" {
		err = conf.Set(*configPath)

		if err != nil {
			log.Fatalf("%s", err)
		}

		log.Printf("configuration file %s successfully parsed", *configPath)
	}

	conf.EnableCiphers()
	conf.Print()

	log.Printf("starting server on %s", conf.BindAddress)

	if conf.Debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		log.Println("debug mode enabled")
	} else {
		log.Println("switching to syslog")

		logwriter, err := syslog.New(syslog.LOG_INFO, "interlock")

		if err != nil {
			log.Fatalf("%s", err)
			return
		}

		log.SetFlags(0)
		log.SetOutput(logwriter)
		log.Printf("starting server on %s", conf.BindAddress)
	}

	registerHandlers()
	err = http.ListenAndServeTLS(conf.BindAddress, "certs/cert.pem", "certs/key.pem", nil)

	if err != nil {
		log.Fatalf("%s", err)
	}
}
