// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"syscall"
	"unsafe"
)

const sccDevice = "/dev/scc2_aes"

// scc2_cmd
const (
	setMode = 0
	setIV   = 1
)

// scc2_mode
const (
	encryptCBC = 0
)

// Identical to AES-256-OFB (see aes.go) but the derived key is encrypted,
// before use, with AES-256-CBC using the NXP Security Controller (SCCv2) with
// its device specific secret key. This uniquely ties the derived key to the
// specific hardware unit being used.
//
// See https://github.com/inversepath/mxc-scc2 for detailed information on the
// SCCv2 encryption process.

type aes256SCC struct {
	info     cipherInfo
	password string

	cipherInterface
}

type SCC struct {
	HSMInterface
}

func init() {
	conf.SetAvailableHSM("mxc-scc2", new(SCC).Init())
}

func (h *SCC) Init() HSMInterface {
	return h
}

func (h *SCC) New() HSMInterface {
	scc, err := os.OpenFile(sccDevice, os.O_RDWR, 0600)

	if err != nil {
		log.Fatal(err)
	}
	defer scc.Close()

	return new(SCC).Init()
}

func (h *SCC) Cipher() cipherInterface {
	return new(aes256SCC).Init()
}

func (a *aes256SCC) Init() (c cipherInterface) {
	a.info = cipherInfo{
		Name:        "AES-256-SCC",
		Description: "AES OFB w/ 256 bit key derived using PBKDF2 and SCCv2 device specific secret key",
		KeyFormat:   "password",
		Enc:         true,
		Dec:         true,
		Sig:         false,
		OTP:         false,
		Msg:         false,
		Extension:   "aes256scc",
	}

	return a
}

func (a *aes256SCC) New() cipherInterface {
	return new(aes256SCC).Init()
}

func (a *aes256SCC) Activate(activate bool) (err error) {
	// no activation required
	return
}

func (a *aes256SCC) GetInfo() cipherInfo {
	return a.info
}

func (a *aes256SCC) SetPassword(password string) (err error) {
	if len(password) < 8 {
		return errors.New("password < 8 characters")
	}

	a.password = password

	return
}

func (a *aes256SCC) Encrypt(input *os.File, output *os.File, sign bool) (err error) {
	if sign {
		return errors.New("symmetric cipher does not support signing")
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)

	if err != nil {
		return
	}

	salt, key, err := DeriveKeyPBKDF2(nil, a.password)

	if err != nil {
		return
	}

	deviceKey, err := SCCDeriveKey(key, iv)

	if err != nil {
		return
	}

	err = EncryptOFB(deviceKey, salt, iv, input, output)

	return
}

func (a *aes256SCC) Decrypt(input *os.File, output *os.File, verify bool) (err error) {
	if verify {
		return errors.New("symmetric cipher does not support signature verification")
	}

	salt := make([]byte, 8)
	_, err = io.ReadFull(input, salt)

	if err != nil {
		return
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(input, iv)

	if err != nil {
		return
	}

	_, key, err := DeriveKeyPBKDF2(salt, a.password)

	if err != nil {
		return
	}

	deviceKey, err := SCCDeriveKey(key, iv)

	if err != nil {
		return
	}

	err = DecryptOFB(deviceKey, salt, iv, input, output)

	return
}

func (a *aes256SCC) GenKey(i string, e string) (p string, s string, err error) {
	err = errors.New("symmetric cipher does not support key generation")
	return
}

func (a *aes256SCC) GetKeyInfo(k key) (i string, err error) {
	err = errors.New("symmetric cipher does not support key")
	return
}

func (a *aes256SCC) SetKey(k key) error {
	return errors.New("symmetric cipher does not support key")
}

func (a *aes256SCC) Sign(i *os.File, o *os.File) error {
	return errors.New("symmetric cipher does not support signing")
}

func (a *aes256SCC) Verify(i *os.File, s *os.File) error {
	return errors.New("symmetric cipher does not support signature verification")
}

func (a *aes256SCC) GenOTP(timestamp int64) (otp string, exp int64, err error) {
	err = errors.New("cipher does not support OTP generation")
	return
}

func (a *aes256SCC) HandleRequest(r *http.Request) (res jsonObject) {
	res = notFound()
	return
}

func (h *SCC) DeriveKey(plaintext []byte, iv []byte) (ciphertext []byte, err error) {
	return SCCDeriveKey(plaintext, iv)
}

// equivalent to PKCS#11 C_DeriveKey with CKM_AES_CBC_ENCRYPT_DATA
func SCCDeriveKey(baseKey []byte, iv []byte) (derivedKey []byte, err error) {
	var ivPtr [16]byte
	copy(ivPtr[:], iv[:])

	scc, err := os.OpenFile(sccDevice, os.O_RDWR, 0600)

	if err != nil {
		return
	}

	syscall.Flock(int(scc.Fd()), syscall.LOCK_EX)
	defer syscall.Flock(int(scc.Fd()), syscall.LOCK_UN)
	defer scc.Close()

	err = ioctl(scc.Fd(), setMode, encryptCBC)

	if err != nil {
		return
	}

	err = ioctl(scc.Fd(), setIV, uintptr(unsafe.Pointer(&ivPtr)))

	if err != nil {
		return
	}

	r := len(baseKey) % 16

	if r != 0 {
		padLen := aes.BlockSize - r
		padding := []byte{(byte)(padLen)}
		padding = bytes.Repeat(padding, padLen)
		baseKey = append(baseKey, padding...)
	}

	if len(baseKey) > aes.BlockSize*256 {
		err = errors.New("input key exceeds maximum length for SCC key derivation")
		return
	}

	_, err = scc.Write(baseKey)

	if err != nil {
		err = errors.New("SCC key derivation input length exceeded")
		return
	}

	buf := make([]byte, len(baseKey))
	_, err = scc.Read(buf)

	if err != nil {
		return
	}

	derivedKey = buf

	return
}
