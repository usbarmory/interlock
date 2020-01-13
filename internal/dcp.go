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

	"golang.org/x/sys/unix"
)

const ALG_TYPE = "skcipher"
const ALG_NAME = "cbc-aes-dcp"

type af_alg_iv struct {
	ivlen uint32
	iv    [aes.BlockSize]byte
}

// Symmetric file encryption using AES-128-OFB.
//
// A first key is derived from password using PBKDF2 with SHA256 and 4096
// rounds, this key is then encrypted with AES-128-CBC using the NXP Data
// Co-Processor (DCP) with its device specific secret key.
//
// This uniquely ties the derived key to the specific hardware unit being used,
// as well as the authentication password.
//
// See https://github.com/f-secure-foundry/mxs-dcp for detailed information on
// the DCP encryption process.
//
// The salt, initialization vector are prepended to the encrypted file, the
// HMAC for authentication is appended:
//
// salt (8 bytes) || iv (16 bytes) || ciphertext || hmac (32 bytes)

type aes128DCP struct {
	info     cipherInfo
	password string

	cipherInterface
}

type DCP struct {
	HSMInterface
}

func init() {
	conf.SetAvailableHSM("mxs-dcp", new(DCP).Init())
}

func (h *DCP) Init() HSMInterface {
	return h
}

func (h *DCP) New() HSMInterface {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)

	if err != nil {
		log.Fatal(err)
	}
	defer unix.Close(fd)

	err = unix.Bind(fd, &unix.SockaddrALG{Type: ALG_TYPE, Name: ALG_NAME})

	if err != nil {
		log.Fatal(err)
	}

	return new(DCP).Init()
}

func (h *DCP) Cipher() cipherInterface {
	return new(aes128DCP).Init()
}

func (a *aes128DCP) Init() (c cipherInterface) {
	a.info = cipherInfo{
		Name:        "AES-128-DCP",
		Description: "AES OFB w/ 128 bit key derived using PBKDF2 and DCP device specific secret key",
		KeyFormat:   "password",
		Enc:         true,
		Dec:         true,
		Sig:         false,
		OTP:         false,
		Msg:         false,
		Extension:   "aes128dcp",
	}

	return a
}

func (a *aes128DCP) New() cipherInterface {
	return new(aes128DCP).Init()
}

func (a *aes128DCP) Activate(activate bool) (err error) {
	// no activation required
	return
}

func (a *aes128DCP) GetInfo() cipherInfo {
	return a.info
}

func (a *aes128DCP) SetPassword(password string) (err error) {
	if len(password) < 8 {
		return errors.New("password < 8 characters")
	}

	a.password = password

	return
}

func (a *aes128DCP) Encrypt(input *os.File, output *os.File, sign bool) (err error) {
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

	deviceKey, err := DCPDeriveKey(key, iv)

	if err != nil {
		return
	}

	err = encryptOFB(deviceKey, salt, iv, input, output)

	return
}

func (a *aes128DCP) Decrypt(input *os.File, output *os.File, verify bool) (err error) {
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

	deviceKey, err := DCPDeriveKey(key, iv)

	if err != nil {
		return
	}

	err = decryptOFB(deviceKey, salt, iv, input, output)

	return
}

func (a *aes128DCP) GenKey(i string, e string) (p string, s string, err error) {
	err = errors.New("symmetric cipher does not support key generation")
	return
}

func (a *aes128DCP) GetKeyInfo(k key) (i string, err error) {
	err = errors.New("symmetric cipher does not support key")
	return
}

func (a *aes128DCP) SetKey(k key) error {
	return errors.New("symmetric cipher does not support key")
}

func (a *aes128DCP) Sign(i *os.File, o *os.File) error {
	return errors.New("symmetric cipher does not support signing")
}

func (a *aes128DCP) Verify(i *os.File, s *os.File) error {
	return errors.New("symmetric cipher does not support signature verification")
}

func (a *aes128DCP) GenOTP(timestamp int64) (otp string, exp int64, err error) {
	err = errors.New("cipher does not support OTP generation")
	return
}

func (a *aes128DCP) HandleRequest(r *http.Request) (res jsonObject) {
	res = notFound()
	return
}

func (h *DCP) DeriveKey(diversifier []byte, iv []byte) (key []byte, err error) {
	return DCPDeriveKey(diversifier, iv)
}

// equivalent to PKCS#11 C_DeriveKey with CKM_AES_CBC_ENCRYPT_DATA
func DCPDeriveKey(diversifier []byte, iv []byte) (key []byte, err error) {
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)

	if err != nil {
		return
	}
	defer unix.Close(fd)

	err = unix.Bind(fd, &unix.SockaddrALG{Type: ALG_TYPE, Name: ALG_NAME})

	if err != nil {
		return
	}

	// https://github.com/golang/go/issues/31277
	// SetsockoptString does allow empty strings, so we work it around
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), uintptr(unix.SOL_ALG), uintptr(unix.ALG_SET_KEY), uintptr(0), uintptr(0), 0)

	if e1 != 0 {
		err = errors.New("setsockopt failed")
		return
	}

	if err != nil {
		return
	}

	diversifier = PKCS7Pad(diversifier, false)
	apifd, _, _ := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)
	key, err = cryptoAPI(apifd, unix.ALG_OP_ENCRYPT, iv, diversifier)

	return
}

func cryptoAPI(fd uintptr, mode uint32, iv []byte, input []byte) (output []byte, err error) {
	api := os.NewFile(fd, "INTERLOCK-CryptoAPI")

	cmsg := buildCmsg(mode, iv)

	output = make([]byte, len(input))
	err = syscall.Sendmsg(int(fd), input, cmsg, nil, 0)

	if err != nil {
		return
	}

	_, err = api.Read(output)

	return
}

func buildCmsg(mode uint32, iv []byte) []byte {
	cbuf := make([]byte, syscall.CmsgSpace(4)+syscall.CmsgSpace(20))

	cmsg := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	cmsg.Level = unix.SOL_ALG
	cmsg.Type = unix.ALG_SET_OP
	cmsg.SetLen(syscall.CmsgLen(4))

	op := (*uint32)(unsafe.Pointer(CMSG_DATA(cmsg)))
	*op = mode

	cmsg = (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[syscall.CmsgSpace(4)]))
	cmsg.Level = unix.SOL_ALG
	cmsg.Type = unix.ALG_SET_IV
	cmsg.SetLen(syscall.CmsgLen(20))

	alg_iv := (*af_alg_iv)(unsafe.Pointer(CMSG_DATA(cmsg)))
	alg_iv.ivlen = uint32(len(iv))
	copy(alg_iv.iv[:], iv)

	return cbuf
}

func CMSG_DATA(cmsg *syscall.Cmsghdr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + uintptr(syscall.SizeofCmsghdr))
}
