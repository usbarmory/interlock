// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.
//
//+build linux

package interlock

import (
	"bytes"
	"errors"
	"log"
	"os/exec"
	"syscall"
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
			return
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

func ioctl(fd, cmd, arg uintptr) (err error) {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, arg)

	if e != 0 {
		return syscall.Errno(e)
	}

	return
}
