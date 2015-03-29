// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"log/syslog"
	"net/http"
	"syscall"
)

const mapping = "interlockfs"

const (
	_change = iota
	_add
	_remove
)

func passwordRequest(w http.ResponseWriter, r *http.Request, mode int) (res jsonObject) {
	var newpassword string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	switch mode {
	case _change, _add:
		err = validateRequest(req, []string{"volume", "password", "newpassword"})
		newpassword = req["newpassword"].(string)
	case _remove:
		err = validateRequest(req, []string{"volume", "password"})
	default:
		err = errors.New("unsupported operation")
	}

	if err != nil {
		return errorResponse(err, "")
	}

	err = luksKeyOp(req["volume"].(string), req["password"].(string), newpassword, mode)

	if err != nil {
		return errorResponse(err, "")
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func luksOpen(volume string, password string) (err error) {
	args := []string{"luksOpen", "/dev/lvmvolume/" + volume, mapping}
	cmd := "/sbin/cryptsetup"

	status.Log(syslog.LOG_NOTICE, "unlocking encrypted volume %s", volume)

	_, err = execCommand(cmd, args, true, password+"\n")

	return
}

func luksMount() (err error) {
	args := []string{"/dev/mapper/" + mapping, conf.mountPoint}
	cmd := "/bin/mount"

	status.Log(syslog.LOG_NOTICE, "mounting encrypted volume to %s", conf.mountPoint)

	_, err = execCommand(cmd, args, true, "")

	return
}

func luksUnmount() (err error) {
	args := []string{conf.mountPoint}
	cmd := "/bin/umount"

	status.Log(syslog.LOG_NOTICE, "unmounting encrypted volume on %s", conf.mountPoint)

	syscall.Sync()
	_, err = execCommand(cmd, args, true, "")

	return
}

func luksClose() (err error) {
	args := []string{"luksClose", "/dev/mapper/" + mapping}
	cmd := "/sbin/cryptsetup"

	status.Log(syslog.LOG_NOTICE, "locking encrypted volume")

	_, err = execCommand(cmd, args, true, "")

	return
}

func luksKeyOp(volume string, password string, newpassword string, mode int) (err error) {
	var action string
	var input string

	switch mode {
	case _change:
		action = "luksChangeKey"
		input = password + "\n" + newpassword + "\n"
	case _add:
		action = "luksAddKey"
		input = password + "\n" + newpassword + "\n" + newpassword + "\n"
	case _remove:
		action = "luksRemoveKey"
		input = password + "\n"
	default:
		err = errors.New("unsupported operation")
	}

	args := []string{action, "/dev/lvmvolume/" + volume}
	cmd := "/sbin/cryptsetup"

	status.Log(syslog.LOG_NOTICE, "performing LUKS key action %s", action)

	_, err = execCommand(cmd, args, true, input)

	return
}
