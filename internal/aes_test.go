// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
)

func TestAes(t *testing.T) {
	password := "interlocktest"
	cleartext := "01234567890ABCDEFGHILMNOPQRSTUVZ!@#"

	input, _ := ioutil.TempFile("", "aes_test_input-")
	input.Write([]byte(cleartext))
	input.Seek(0, 0)

	ciphertext, _ := ioutil.TempFile("", "aes_test_ciphertext-")
	decrypted, _ := ioutil.TempFile("", "aes_test_decrypted-")

	a := &aes256OFB{}
	a.SetPassword(password)

	err := a.Encrypt(input, ciphertext, false)

	if err != nil {
		t.Error(err)
	}

	ciphertext.Seek(0, 0)
	err = a.Decrypt(ciphertext, decrypted, false)

	if err != nil {
		t.Error(err)
		return
	}

	decrypted.Seek(0, 0)
	compare, _ := ioutil.ReadAll(decrypted)

	if !bytes.Equal([]byte(cleartext), compare) {
		t.Error("cleartext and ciphertext differ")
	}

	input.Close()
	os.Remove(input.Name())

	ciphertext.Close()
	os.Remove(ciphertext.Name())

	decrypted.Close()
	os.Remove(decrypted.Name())
}
