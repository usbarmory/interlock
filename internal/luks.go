// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.
//
//+build linux

package interlock

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"io"
	"log/syslog"
	"net/http"
	"os/user"
	"strings"
	"syscall"
)

const mapping = "interlockfs"

const (
	_change = iota
	_add
	_remove
)

func passwordRequest(r *http.Request, mode int) (res jsonObject) {
	var newPassword string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	switch mode {
	case _change, _add:
		err = validateRequest(req, []string{"volume:s", "password:s", "newpassword:s"})
		newPassword = req["newpassword"].(string)
	case _remove:
		err = validateRequest(req, []string{"volume:s", "password:s"})
	default:
		err = errors.New("unsupported operation")
	}

	if err != nil {
		return errorResponse(err, "")
	}

	err = luksKeyOp(req["volume"].(string), req["password"].(string), newPassword, mode)

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
	var key string

	if strings.Contains(volume, traversalPattern) {
		return errors.New("path traversal detected")
	}

	if conf.authHSM != nil {
		key, err = deriveKey(password)

		if err != nil {
			return
		}
	}

	args := []string{"luksOpen", "/dev/" + conf.VolumeGroup + "/" + volume, mapping}
	cmd := "/sbin/cryptsetup"

	status.Log(syslog.LOG_NOTICE, "unlocking encrypted volume %s", volume)

	if conf.authHSM != nil {
		_, err = execCommand(cmd, args, true, key+"\n")

		if err == nil {
			return
		}
		// fallback to original password to allow pre-HSM migration
	}

	_, err = execCommand(cmd, args, true, password+"\n")

	return
}

func luksMount() (err error) {
	args := []string{"/dev/mapper/" + mapping, conf.MountPoint}
	cmd := "/bin/mount"

	status.Log(syslog.LOG_NOTICE, "mounting encrypted volume to %s", conf.MountPoint)

	_, err = execCommand(cmd, args, true, "")

	if err != nil {
		return
	}

	u, err := user.Current()

	if err != nil {
		return
	}

	args = []string{u.Username, conf.MountPoint}
	cmd = "/bin/chown"

	status.Log(syslog.LOG_NOTICE, "setting mount point permissions for user %s", u.Username)

	_, err = execCommand(cmd, args, true, "")

	return
}

func luksUnmount() (err error) {
	args := []string{conf.MountPoint}
	cmd := "/bin/umount"

	status.Log(syslog.LOG_NOTICE, "unmounting encrypted volume on %s", conf.MountPoint)

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

func luksKeyOp(volume string, password string, newPassword string, mode int) (err error) {
	var action string
	var input string
	var key string
	var newKey string
	var keyInputs []string

	if strings.Contains(volume, traversalPattern) {
		return errors.New("path traversal detected")
	}

	if conf.authHSM != nil {
		key, err = deriveKey(password)

		if err != nil {
			return
		}

		if mode == _change || mode == _add {
			newKey, err = deriveKey(newPassword)

			if err != nil {
				return
			}
		}
	}

	switch mode {
	case _change:
		action = "luksChangeKey"
		input = password + "\n" + newPassword + "\n"

		if conf.authHSM != nil {
			keyInputs = append(keyInputs, key+"\n"+newKey+"\n")
			keyInputs = append(keyInputs, password+"\n"+newKey+"\n")
		}
	case _add:
		action = "luksAddKey"
		input = password + "\n" + newPassword + "\n" + newPassword + "\n"

		if conf.authHSM != nil {
			keyInputs = append(keyInputs, key+"\n"+newKey+"\n"+newKey+"\n")
			keyInputs = append(keyInputs, password+"\n"+newKey+"\n"+newKey+"\n")
		}
	case _remove:
		action = "luksRemoveKey"
		input = password + "\n"

		if conf.authHSM != nil {
			keyInputs = append(keyInputs, key+"\n")
			keyInputs = append(keyInputs, password+"\n")
		}
	default:
		err = errors.New("unsupported operation")
		return
	}

	args := []string{action, "/dev/" + conf.VolumeGroup + "/" + volume}
	cmd := "/sbin/cryptsetup"

	status.Log(syslog.LOG_NOTICE, "performing LUKS key action %s", action)

	if conf.authHSM != nil {
		for i := 0; i < len(keyInputs); i++ {
			_, err = execCommand(cmd, args, true, keyInputs[i])

			if err == nil {
				return
			}
			// fallback to original password to allow pre-HSM migration
		}
	} else {
		_, err = execCommand(cmd, args, true, input)
	}

	return
}

func deriveKey(password string) (derivedKey string, err error) {
	h := md5.New()
	io.WriteString(h, password)
	key, err := conf.authHSM.DeriveKey([]byte(password), h.Sum(nil))

	if err != nil {
		return
	}

	derivedKey = base64.StdEncoding.EncodeToString(key)

	return
}
