// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestTOTP(t *testing.T) {
	conf.mountPoint = "/tmp"
	timestamp := int64(1430051641)
	testSecKey := "this is a TOTP test k"
	t := &tOTP{}

	secKeyFile, _ := ioutil.TempFile("", "totp_test_seed-")
	secKeyFile.Write([]byte(testSecKey))
	secKeyFile.Seek(0, 0)

	secKey := key{
		Identifier: "TOTP test key",
		KeyFormat:  "base32",
		Cipher:     "TOTP",
		Private:    true,
		Path:       path.Base(secKeyFile.Name()),
	}

	err := t.SetKey(secKey)

	if err != nil {
		t.Error(err)
		return
	}

	otp, exp, err := t.GenOTP(timestamp)

	if err != nil {
		t.Error(err)
		return
	}

	if otp != "695028" {
		t.Errorf("invalid code (%v at %v, expires in %v)", otp, timestamp, exp)
	}

	secKeyFile.Close()
	os.Remove(secKeyFile.Name())
}
