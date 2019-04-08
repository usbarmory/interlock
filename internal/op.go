// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"errors"
	"fmt"
	"regexp"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

var opPattern = regexp.MustCompile("^(open|close|derive)(:.+)?$")

func Op(op string) (err error) {
	var cmd string
	var arg string

	m := opPattern.FindStringSubmatch(op)

	if len(m) != 3 {
		return errors.New("invalid operation")
	}

	cmd = m[1]

	if m[2] != "" {
		if m[2] == ":" {
			return errors.New("invalid operation")
		}

		arg = m[2][1:]
	}

	switch cmd {
	case "open":
		var password string

		if arg == "" {
			return errors.New("invalid operation")
		}

		password, err = promptPassword(false)

		if err != nil {
			return
		}

		err = luksOpen(arg, password)
	case "close":
		err = luksClose()
	case "derive":
		var data string
		var derivedKey string

		if conf.authHSM == nil {
			return errors.New("HSM is required for key derivation")
		}

		if arg == "" {
			data, err = promptPassword(true)

			if err != nil {
				return
			}
		} else {
			data = arg
		}

		derivedKey, err = deriveKey(data)

		if err != nil {
			return
		}

		fmt.Println(derivedKey)
	}

	return
}

func promptPassword(confirm bool) (string, error) {
	fmt.Print("Password: ")
	password, _ := terminal.ReadPassword(int(syscall.Stdin))

	if confirm {
		fmt.Printf("\nConfirm password: ")
		confirmation, _ := terminal.ReadPassword(int(syscall.Stdin))

		if string(password) != string(confirmation) {
			fmt.Println()
			//lint:ignore ST1005 we want capitalization and punctuation in this error
			return "", errors.New("Password mismatch!")
		}
	}

	fmt.Println()

	return string(password), nil
}
