// INTERLOCK | https://github.com/usbarmory/interlock
// Copyright (c) The INTERLOCK authors. All Rights Reserved.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

//go:build linux

package interlock

import (
	"bytes"
	"errors"
	"log"
	"os/exec"
	"strconv"
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

func setTime(epoch int64) (err error) {
	args := []string{"-s", "@" + strconv.FormatInt(epoch, 10)}
	_, err = execCommand("/bin/date", args, true, "")

	return
}

func cp(src string, dst string) (err error) {
	args := []string{"-ra", src, dst}
	_, err = execCommand("/bin/cp", args, false, "")

	return
}

func mv(src string, dst string) (err error) {
	args := []string{src, dst}
	_, err = execCommand("/bin/mv", args, false, "")

	return
}

func poweroff() {
	go func() {
		_, _ = execCommand("/sbin/poweroff", []string{}, true, "")
	}()
}

func ioctl(fd, cmd, arg uintptr) (err error) {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, arg)

	if e != 0 {
		return syscall.Errno(e)
	}

	return
}
