// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type tOTP struct {
	info   cipherInfo
	secKey []byte

	cipherInterface
}

func init() {
	conf.SetAvailableCipher(new(tOTP).Init())
}

func (t *tOTP) Init() cipherInterface {
	t.info = cipherInfo{
		Name:        "TOTP",
		Description: "Time-Based One-Time Password Algorithm (RFC6238, a.k.a. Google Authenticator)",
		KeyFormat:   "base32",
		Enc:         false,
		Dec:         false,
		Sig:         false,
		OTP:         true,
		Msg:         false,
		Extension:   "totp",
	}

	return t
}

func (t *tOTP) New() cipherInterface {
	return new(tOTP).Init()
}

func (t *tOTP) Activate(activate bool) (err error) {
	// no activation required
	return
}

func (t *tOTP) GetInfo() cipherInfo {
	return t.info
}

func (t *tOTP) GetKeyInfo(k key) (info string, err error) {
	err = t.SetKey(k)

	if err != nil {
		return
	}

	otp, exp, err := t.GenOTP(time.Now().Unix())

	if err != nil {
		return
	}

	info = fmt.Sprintf("Code (expires in %v seconds)\n\t%v\n", exp, otp)

	return
}

func (t *tOTP) SetKey(k key) (err error) {
	keyPath := filepath.Join(conf.MountPoint, k.Path)
	s, err := ioutil.ReadFile(keyPath)

	if err != nil {
		return
	}

	seed := strings.ToUpper(string(s))
	seed = strings.Replace(seed, " ", "", -1)
	seed = strings.Replace(seed, "-", "", -1)

	t.secKey, err = base32.StdEncoding.DecodeString(seed)

	if err != nil {
		return
	}

	return
}

func (t *tOTP) GenOTP(timestamp int64) (code string, exp int64, err error) {
	interval := int64(30)
	message := timestamp / interval

	buf := bytes.Buffer{}
	err = binary.Write(&buf, binary.BigEndian, message)

	if err != nil {
		return
	}

	mac := hmac.New(sha1.New, t.secKey)
	mac.Write(buf.Bytes())

	hash := mac.Sum(nil)
	offset := hash[len(hash)-1] & 0x0f
	truncatedHash := hash[offset : offset+4]

	var c int32
	err = binary.Read(bytes.NewReader(truncatedHash), binary.BigEndian, &c)

	if err != nil {
		return
	}

	c = c & 0x7fffffff
	c = c % 1000000

	code = fmt.Sprintf("%06d", c)
	exp = interval - (timestamp % interval)

	return
}

func (t *tOTP) GenKey(i string, e string) (p string, s string, err error) {
	err = errors.New("cipher does not support key generation")
	return
}

func (t *tOTP) SetPassword(password string) error {
	return errors.New("cipher does not support passwords")
}

func (t *tOTP) Encrypt(input *os.File, output *os.File, _ bool) error {
	return errors.New("cipher does not support encryption")
}

func (t *tOTP) Decrypt(input *os.File, output *os.File, verify bool) error {
	return errors.New("cipher does not support decryption")
}

func (t *tOTP) Sign(input *os.File, output *os.File) error {
	return errors.New("cipher does not support signin")
}

func (t *tOTP) Verify(input *os.File, signature *os.File) error {
	return errors.New("cipher does not support signature verification")
}

func (t *tOTP) HandleRequest(r *http.Request) (res jsonObject) {
	res = notFound()
	return
}
