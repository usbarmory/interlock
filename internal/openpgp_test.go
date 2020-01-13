// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestOpenPGP(t *testing.T) {
	conf.MountPoint = "/tmp"
	password := "interlocktest"
	cleartext := "01234567890ABCDEFGHILMNOPQRSTUVZ!@#"
	o := &openPGP{}

	fmt.Println("openpgp_test is generating a test keypair, this might take a while")

	testPubKey, testSecKey, err := o.GenKey("openpgp_test_key", "testonly@example.com")

	if err != nil {
		t.Error(err)
		return
	}

	pubKeyFile, _ := ioutil.TempFile("", "openpgp_test_pubkey-")
	pubKeyFile.Write([]byte(testPubKey))
	pubKeyFile.Seek(0, 0)

	secKeyFile, _ := ioutil.TempFile("", "openpgp_test_seckey-")
	secKeyFile.Write([]byte(testSecKey))
	secKeyFile.Seek(0, 0)

	input, _ := ioutil.TempFile("", "openaes_test_input-")
	input.Write([]byte(cleartext))
	input.Seek(0, 0)

	ciphertext, _ := ioutil.TempFile("", "openpgp_test_ciphertext-")
	decrypted, _ := ioutil.TempFile("", "openpgp_test_decrypted-")
	signature, _ := ioutil.TempFile("", "openpgp_test_signature-")

	pubKey := key{
		Identifier: "OpenPGP test public key",
		KeyFormat:  "armor",
		Cipher:     "OpenPGP",
		Private:    false,
		Path:       path.Base(pubKeyFile.Name()),
	}

	secKey := key{
		Identifier: "OpenPGP test public key",
		KeyFormat:  "armor",
		Cipher:     "OpenPGP",
		Private:    true,
		Path:       path.Base(secKeyFile.Name()),
	}

	err = o.SetKey(pubKey)

	if err != nil {
		t.Error(err)
		return
	}

	err = o.SetKey(secKey)

	if err != nil {
		t.Error(err)
		return
	}

	err = o.SetPassword(password)

	if err != nil {
		t.Error(err)
		return
	}

	err = o.Encrypt(input, ciphertext, true)

	if err != nil {
		t.Error(err)
		return
	}

	ciphertext.Seek(0, 0)
	err = o.Decrypt(ciphertext, decrypted, true)

	if err != nil {
		t.Error(err)
		return
	}

	decrypted.Seek(0, 0)
	compare, _ := ioutil.ReadAll(decrypted)

	if !bytes.Equal([]byte(cleartext), compare) {
		t.Error("cleartext and ciphertext differ")
	}

	input.Seek(0, 0)
	err = o.Sign(input, signature)

	if err != nil {
		t.Error(err)
		return
	}

	input.Seek(0, 0)
	signature.Seek(0, 0)
	err = o.Verify(input, signature)

	if err != nil {
		t.Error(err)
		return
	}

	pubKeyFile.Close()
	os.Remove(pubKeyFile.Name())

	secKeyFile.Close()
	os.Remove(secKeyFile.Name())

	input.Close()
	os.Remove(input.Name())

	ciphertext.Close()
	os.Remove(ciphertext.Name())

	decrypted.Close()
	os.Remove(decrypted.Name())

	signature.Close()
	os.Remove(signature.Name())
}
