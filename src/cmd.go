// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015-2016 Inverse Path S.r.l.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func execCommand(cmd string, args []string, root bool, input string) (output string, err error) {
	var c *exec.Cmd

	if root {
		c = exec.Command("/usr/bin/sudo", append([]string{cmd}, args...)...)
	} else {
		c = exec.Command(cmd, args...)
	}

	var stdin bytes.Buffer
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if input != "" {
		_, err = stdin.WriteString(input)
		c.Stdin = &stdin

		if err != nil {
			err = errors.New("error writing to stdin")
		}
	}

	c.Stdout = &stdout
	c.Stderr = &stderr

	if conf.Debug {
		log.Printf("executing system command, sudo: %v, cmd: %s, args: %v\n", root, cmd, args)
	}

	err = c.Run()

	if err != nil {
		err = errors.New(stderr.String())
	}

	return stdout.String(), err
}

func readLine(prompt string) string {
	var input string

	fmt.Print(prompt)
	fmt.Scanln(&input)

	return input
}

func readPasswd(prompt string, masked bool) string {
	var pwd, bs, mask []byte

	if masked {
		bs = []byte("\b \b")
		mask = []byte("*")
	}

	fmt.Print(prompt)

	for {
		if v := getch(); v == 127 || v == 8 {
			if l := len(pwd); l > 0 {
				pwd = pwd[:l-1]
				os.Stdout.Write(bs)
			}
		} else if v == 13 || v == 10 {
			break
		} else if v != 0 {
			pwd = append(pwd, v)
			os.Stdout.Write(mask)
		}
	}

	println()

	return string(pwd)
}

func getch() byte {
	var buf [1]byte

	if oldState, err := terminal.MakeRaw(0); err != nil {
		panic(err)
	} else {
		defer terminal.Restore(0, oldState)
	}

	if n, err := syscall.Read(0, buf[:]); n == 0 || err != nil {
		panic(err)
	}

	return buf[0]
}
