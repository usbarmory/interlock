// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.
//
//+build linux,arm

package interlock

import (
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

// Symmetric file encryption using AES-256-OFB.
//
// A first key is derived from password using PBKDF2 with SHA256 and 4096
// rounds, this key is then encrypted with AES-256-CBC using the NXP Security
// Controller (SCCv2) with its device specific secret key.
//
// This uniquely ties the derived key to the specific hardware unit being used,
// as well as the authentication password.
//
// See https://github.com/f-secure-foundry/mxs-scc2 for detailed information on
// the SCCv2 encryption process.
//
// The salt, initialization vector are prepended to the encrypted file, the
// HMAC for authentication is appended:
//
// salt (8 bytes) || iv (16 bytes) || ciphertext || hmac (32 bytes)

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

	salt, key, err := deriveKeyPBKDF2(nil, a.password, derivedKeySize)

	if err != nil {
		return
	}

	deviceKey, err := SCCDeriveKey(key, iv)

	if err != nil {
		return
	}

	err = encryptOFB(deviceKey, salt, iv, input, output)

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

	_, key, err := deriveKeyPBKDF2(salt, a.password, derivedKeySize)

	if err != nil {
		return
	}

	deviceKey, err := SCCDeriveKey(key, iv)

	if err != nil {
		return
	}

	err = decryptOFB(deviceKey, salt, iv, input, output)

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

func (h *SCC) DeriveKey(diversifier []byte, iv []byte) (key []byte, err error) {
	return SCCDeriveKey(diversifier, iv)
}

// equivalent to PKCS#11 C_DeriveKey with CKM_AES_CBC_ENCRYPT_DATA
func SCCDeriveKey(diversifier []byte, iv []byte) (key []byte, err error) {
	var ivPtr [aes.BlockSize]byte
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

	diversifier = PKCS7Pad(diversifier, false)

	if len(diversifier) > aes.BlockSize*256 {
		err = errors.New("input diversifier exceeds maximum length for SCC key derivation")
		return
	}

	_, err = scc.Write(diversifier)

	if err != nil {
		err = errors.New("SCC key derivation input length exceeded")
		return
	}

	buf := make([]byte, len(diversifier))
	_, err = scc.Read(buf)

	if err != nil {
		return
	}

	key = buf

	return
}
