// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

var configPath = flag.String("c", "", "configuration file path")

func init() {
	if os.Geteuid() == 0 {
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

func enableSyslog() {
	if conf.logFile != nil {
		conf.logFile.Close()
	}

	log.Println("switching to syslog")
	logwriter, err := syslog.New(syslog.LOG_INFO, "interlock")

	if err != nil {
		log.Fatalf("%s", err)
	}

	log.SetFlags(0)
	log.SetOutput(logwriter)
}

func enableFilelog() {
	if conf.logFile != nil {
		conf.logFile.Close()
	}

	logPath := filepath.Join(conf.mountPoint, ".interlock.log")
	log.Printf("switching to log file %s", logPath)
	logwriter, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)

	if err != nil {
		status.Error(fmt.Errorf("could not switch to log file %s: %s", logPath, err.Error()))
	}

	conf.logFile = logwriter
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(conf.logFile)
}

func main() {
	err := os.Chdir(path.Dir(os.Args[0]))

	if err != nil {
		log.Fatalf("%s", err)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(os.Stdout)

	log.Printf("starting INTERLOCK %s (%s)\n", InterlockVersion, InterlockBuild)

	if *configPath != "" {
		err := conf.Set(*configPath)

		if err != nil {
			log.Fatalf("%s", err)
		}

		log.Printf("configuration file %s successfully parsed", *configPath)
	}

	err = conf.SetMountPoint()

	if err != nil {
		log.Fatalf("%s", err)
	}

	conf.EnableCiphers()
	conf.Print()

	if conf.Debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		log.Println("debug mode enabled")
	} else {
		enableSyslog()
	}

	log.Printf("starting server on %s", conf.BindAddress)

	registerHandlers()

	if conf.TLSClientCA != "" {
		certPool := x509.NewCertPool()
		{
			clientCert, err := ioutil.ReadFile(conf.TLSClientCA)

			if err != nil {
				log.Fatalf("%s", err)
			}

			if ok := certPool.AppendCertsFromPEM(clientCert); !ok {
				log.Fatal("could not parse client certificate authority")
			}
		}

		server := &http.Server{
			Addr: conf.BindAddress,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  certPool,
			},
		}

		err = server.ListenAndServeTLS(conf.TLSCert, conf.TLSKey)
	} else {
		err = http.ListenAndServeTLS(conf.BindAddress, conf.TLSCert, conf.TLSKey, nil)
	}

	if err != nil {
		log.Fatalf("%s", err)
	}
}
