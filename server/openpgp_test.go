// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

const testPubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

mI0EVQXNEAEEAJgrzwrvcG/mRUu8GHTd+v1dj+CGT0e4e+R6F1TUNvJgiv8c0+sJ
mfRszkI+rsqtnFQZZgIv1rSukOh9q5op7mct1zmOUAiZOttvBT5mfX+MXsG3nOOk
xKyXDywwdRjDD+LiJUgy1U+aUEdrB0Uqd+W6SmMJ8DI+I/OM2ATMZuMfABEBAAG0
S0ludGVybG9jayBUZXN0IChUZXN0IEtleSBmb3IgSW50ZXJsb2NrIE9wZW5QR1Ag
dGVzdCkgPHRlc3Rvbmx5QGV4YW1wbGUuY29tPoi4BBMBAgAiBQJVBc0QAhsDBgsJ
CAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRAxRmQehCEy8L5FA/9B6yQkkd4epeC/
XTOCpXj5FBnd2bhtfg6kIE5QdeNy7yzafO2wReWvAilJC90MvEYGwq3iUMK/yXqu
EjTZx/szk5AR6/EDr+J6LnYCH5rP2143v57yz3cFwxG4owXQ95DRoqZgXIIEOjY1
TAcB2GfyRfWIzc3DA/GlWjKnpD5x17iNBFUFzRABBADFSSfLEf6+P5jsz6Vr8I3k
Xl4PdNBYIC2YHnohP7Wd3X8fPQrCI//B8FFURNkAXRMokH+6R1Pi1Sloj2j5M9Rp
F9jrB/ucZ/QU8jlOJ1K3fa5rkYGDZ0UhyzAFkGmATU7ZhYXSA3GdsDhY3JtAHh30
I4bgvoMst9uD+nuDGz8Z7wARAQABiJ8EGAECAAkFAlUFzRACGwwACgkQMUZkHoQh
MvBLzQP+OrIYkAT86xWLfJo0N5+lH5ZmtTxy0R2vJA2+o21j9vMkj4mz94pfJFLe
YxyqevCrWJAXGS+R/zpXnW52jkXRDA03qmVd/ySI+SYpY8rbzgn0/pfVItqb4fLo
XApXHTDGISROTgUvfCq6+RuimbtdLx131C+9fiSEUrLZxE4y+tw=
=W8Yd
-----END PGP PUBLIC KEY BLOCK-----
`

const testSecKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

lQH+BFUFzRABBACYK88K73Bv5kVLvBh03fr9XY/ghk9HuHvkehdU1DbyYIr/HNPr
CZn0bM5CPq7KrZxUGWYCL9a0rpDofauaKe5nLdc5jlAImTrbbwU+Zn1/jF7Bt5zj
pMSslw8sMHUYww/i4iVIMtVPmlBHawdFKnflukpjCfAyPiPzjNgEzGbjHwARAQAB
/gMDAlW8NG9CmflgYCq8Xmf9olIK6to02yb4dLhUQiWW1sxFcEl+fsDRgVl5dZck
S+he8f/2oPno5uLpam64szi5MD9ra92XR2tVzorfCld4G6BH750CqeF0wN8FlGtA
SivrvVMhWXxJhKpxaX284LRIR7LAmfGsfUWWctKW8WHu0+MSKXGnCpXAehyr/LJf
KgS8zRVOWC3Vr70Fp/z8bIuP88K2KkX293czL9rmThb+mDz+m3WAW7FVLHgZdn19
tTGv4Rm31+i/TEIaK8A0lfUFXdJJnTirkzxoipopqizlcICmBnnMlBXx3yuSynUB
leMnD4kNvnmJDDcSs9ZXl63n1b7ydHyGoQNgWLgmyJbKgFZS9avgPZaRGiItFNVI
FCRdPf5hJ2B3SL4P4uweAAPyV/RnARQoCwR4QUv2XNajrBd0NiDHDcF5kM8AKMfP
b87c+Um/NmhZjsfS4HhQW93AqgsjvsZdMLEerB+WZvJutEtJbnRlcmxvY2sgVGVz
dCAoVGVzdCBLZXkgZm9yIEludGVybG9jayBPcGVuUEdQIHRlc3QpIDx0ZXN0b25s
eUBleGFtcGxlLmNvbT6IuAQTAQIAIgUCVQXNEAIbAwYLCQgHAwIGFQgCCQoLBBYC
AwECHgECF4AACgkQMUZkHoQhMvC+RQP/QeskJJHeHqXgv10zgqV4+RQZ3dm4bX4O
pCBOUHXjcu8s2nztsEXlrwIpSQvdDLxGBsKt4lDCv8l6rhI02cf7M5OQEevxA6/i
ei52Ah+az9teN7+e8s93BcMRuKMF0PeQ0aKmYFyCBDo2NUwHAdhn8kX1iM3NwwPx
pVoyp6Q+cdedAf4EVQXNEAEEAMVJJ8sR/r4/mOzPpWvwjeReXg900FggLZgeeiE/
tZ3dfx89CsIj/8HwUVRE2QBdEyiQf7pHU+LVKWiPaPkz1GkX2OsH+5xn9BTyOU4n
Urd9rmuRgYNnRSHLMAWQaYBNTtmFhdIDcZ2wOFjcm0AeHfQjhuC+gyy324P6e4Mb
PxnvABEBAAH+AwMCVbw0b0KZ+WBgxwJeP6yGLrEhLZYxsLifwS3LcDiroY/YZHFR
Lvtk/YYD8EiVn0rUYRGZ6rYXhLS+RNLVLeUa6rQvmeJuz3XVyxsklwJX+4h3rbpL
1J/raoP3x3ICRGIGJYPLhcXpnq/KpbxRRf8Mjd2x6kPJfJg9Xre/HIdsf9ZNM1v3
6qNO+hkBZ2quA4rJ6LHzO5ijEfkUtfIDz4Jivfvx8u8LRlkqFGLzo3IQYLvU4ro4
WsiMtE+UA6YMfKU7GRXOU0Tnuk1Rq3Rvl5ZwruRpdQvaj7mxri7nwN0mOZOENObV
yea3CfDkzib2DCezKjRnk5dMSWHfFjMqVt2i11cyg60PJOi4JyTHDT+AxA9bB102
CcSJ/mwAf9Udg2hV9EC/XzZ2lN2n4VwUfQ4Cbq9VvFujwegLFln43dE0Iyzq+Nwa
OJf06afkxXwE1+RrK0j4KxlmgzqfbovVDaxQ9nY8QG48k3GJdXmeE3GInwQYAQIA
CQUCVQXNEAIbDAAKCRAxRmQehCEy8EvNA/46shiQBPzrFYt8mjQ3n6Uflma1PHLR
Ha8kDb6jbWP28ySPibP3il8kUt5jHKp68KtYkBcZL5H/OledbnaORdEMDTeqZV3/
JIj5JiljytvOCfT+l9Ui2pvh8uhcClcdMMYhJE5OBS98Krr5G6KZu10vHXfUL71+
JIRSstnETjL63A==
=/75s
-----END PGP PRIVATE KEY BLOCK-----
`

func TestOpenPGP(t *testing.T) {
	password := "interlocktest"
	cleartext := "01234567890ABCDEFGHILMNOPQRSTUVZ!@#"

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

	o := &openPGP{}

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

	err := o.SetKey(pubKey)

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

	if bytes.Compare([]byte(cleartext), compare) != 0 {
		t.Error("cleartext and decrypted text differ")
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
