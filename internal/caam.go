// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.
//
//+build linux,arm

package interlock

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"syscall"
	"unsafe"
)

const caamDevice = "/dev/caam_kb"
const luksBlobPath = ".luks_kb" // directory created in $HOME

const (
	KEYMOD_LEN    = 16
	BLOB_OVERHEAD = 32 + 16
)

// Portability note: the 0x18 within the two CAAM_KB_* constants and the uint32
// types in caam_kb_data reflect a 32-bit architecture.

const (
	// _IOWR(CAAM_KB_MAGIC, 0, struct caam_kb_data)
	CAAM_KB_ENCRYPT = 0xc0184900
	// _IOWR(CAAM_KB_MAGIC, 1, struct caam_kb_data)
	CAAM_KB_DECRYPT = 0xc0184901
)

// C compatible struct of caam_kb_data from caam_keyblob.h
type caam_kb_data struct {
	RawKey     *byte
	RawKeyLen  uint32
	KeyBlob    *byte
	KeyBlobLen uint32
	Keymod     *byte
	KeymodLen  uint32
}

func (kb *caam_kb_data) set(key, blob, keymod *[]byte) {
	if len(*key) == 0 {
		*key = make([]byte, derivedKeySize)
	}

	if len(*blob) == 0 {
		*blob = make([]byte, len(*key)+BLOB_OVERHEAD)
	}

	kb.RawKeyLen = uint32(len(*key))
	kb.RawKey = &(*key)[0]

	kb.KeyBlobLen = uint32(len(*blob))
	kb.KeyBlob = &(*blob)[0]

	if len(*keymod) == 0 {
		*keymod = bytes.Repeat([]byte{0x00}, KEYMOD_LEN)
	}

	kb.Keymod = &(*keymod)[0]
	kb.KeymodLen = uint32(len(*keymod))
}

// Symmetric file encryption using AES-256-OFB.
//
// A first key is derived from password using PBKDF2 with SHA256 and 4096
// rounds, this key is then encrypted with AES-256-CCM using the NXP
// Cryptographic Acceleration and Assurance Module (CAAM) with its device
// specific secret key.
//
// The user password is used as key modifier to the CAAM operation, to ensure
// derived key decryption only with the specific hardware and user that
// performed the encryption.
//
// See https://github.com/f-secure-foundry/caam-keyblob for detailed
// information on the CAAM encryption process.
//
// The derived key encrypted blob, salt, initialization vector are prepended to
// the encrypted file, the HMAC for authentication is appended:
//
// keyblob (80 bytes) || salt (8 bytes) || iv (16 bytes) || ciphertext || hmac (32 bytes)

type aes256CAAM struct {
	info     cipherInfo
	password string

	cipherInterface
}

type CAAM struct {
	HSMInterface
}

func init() {
	conf.SetAvailableHSM("caam-keyblob", new(CAAM).Init())
}

func (h *CAAM) Init() HSMInterface {
	return h
}

func (h *CAAM) New() HSMInterface {
	caam, err := os.OpenFile(caamDevice, os.O_RDWR, 0600)

	if err != nil {
		log.Fatal(err)
	}
	defer caam.Close()

	return new(CAAM).Init()
}

func (h *CAAM) Cipher() cipherInterface {
	return new(aes256CAAM).Init()
}

func (a *aes256CAAM) Init() (c cipherInterface) {
	a.info = cipherInfo{
		Name:        "AES-256-CAAM",
		Description: "AES OFB w/ 256 bit key derived using PBKDF2 and CAAM device specific secret key",
		KeyFormat:   "password",
		Enc:         true,
		Dec:         true,
		Sig:         false,
		OTP:         false,
		Msg:         false,
		Extension:   "aes256caam",
	}

	return a
}

func (a *aes256CAAM) New() cipherInterface {
	return new(aes256CAAM).Init()
}

func (a *aes256CAAM) Activate(activate bool) (err error) {
	// no activation required
	return
}

func (a *aes256CAAM) GetInfo() cipherInfo {
	return a.info
}

func (a *aes256CAAM) SetPassword(password string) (err error) {
	if len(password) < 8 {
		return errors.New("password < 8 characters")
	}

	a.password = password

	return
}

func (a *aes256CAAM) Encrypt(input *os.File, output *os.File, sign bool) (err error) {
	if sign {
		return errors.New("symmetric cipher does not support signing")
	}

	return CAAMEncrypt(a.password, input, output)
}

func (a *aes256CAAM) Decrypt(input *os.File, output *os.File, verify bool) (err error) {
	if verify {
		return errors.New("symmetric cipher does not support signature verification")
	}

	return CAAMDecrypt(a.password, input, output)
}

func (a *aes256CAAM) GenKey(i string, e string) (p string, s string, err error) {
	err = errors.New("symmetric cipher does not support key generation")
	return
}

func (a *aes256CAAM) GetKeyInfo(k key) (i string, err error) {
	err = errors.New("symmetric cipher does not support key")
	return
}

func (a *aes256CAAM) SetKey(k key) error {
	return errors.New("symmetric cipher does not support key")
}

func (a *aes256CAAM) Sign(i *os.File, o *os.File) error {
	return errors.New("symmetric cipher does not support signing")
}

func (a *aes256CAAM) Verify(i *os.File, s *os.File) error {
	return errors.New("symmetric cipher does not support signature verification")
}

func (a *aes256CAAM) GenOTP(timestamp int64) (otp string, exp int64, err error) {
	err = errors.New("cipher does not support OTP generation")
	return
}

func (a *aes256CAAM) HandleRequest(r *http.Request) (res jsonObject) {
	res = notFound()
	return
}

func (h *CAAM) DeriveKey(diversifier []byte, iv []byte) (key []byte, err error) {
	return CAAMDeriveKey(diversifier, iv)
}

func CAAMDeriveKey(diversifier []byte, iv []byte) (key []byte, err error) {
	var newKey []byte
	var blob []byte

	var output *os.File
	var input *os.File

	_, keymod, err := deriveKeyPBKDF2(iv, string(diversifier), KEYMOD_LEN)

	if err != nil {
		return
	}

	outputPath := os.Getenv("HOME")
	outputPath = path.Join(outputPath, luksBlobPath)

	err = os.MkdirAll(outputPath, 0700)

	if err != nil {
		return
	}

	// Multiple keys are supported, therefore we need to maintain 1:1
	// association between key:blob. The downside of this is that invalid,
	// or deleted, passphrases create leftovers which are never removed,
	// however we do not care as, despite being a little inelegant, there
	// is no harm.
	h := sha256.New()
	h.Write(diversifier)
	h.Write(iv)
	outputPath = path.Join(outputPath, "."+fmt.Sprintf("%x", h.Sum(nil)))

	stat, err := os.Stat(outputPath)

	if err == nil && stat.IsDir() {
		err = fmt.Errorf("%s is not supposed to be a directory", outputPath)
		return
	} else if err != nil {
		output, err = os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

		if err != nil {
			return
		}
		defer output.Close()

		// We initialize a random key and wrap it in a hardware
		// specific encrypted blob, using the password as key
		// diversifier, for later re-use.
		newKey = make([]byte, derivedKeySize)
		_, err = io.ReadFull(rand.Reader, newKey)

		if err != nil {
			return
		}

		kb := &caam_kb_data{}
		kb.set(&newKey, &blob, &keymod)

		err = CAAMOp(CAAM_KB_ENCRYPT, uintptr(unsafe.Pointer(kb)))

		if err != nil {
			return
		}

		_, err = output.Write(blob)

		output.Close()

		// We do not simply return here to explicitly test if
		// decryption of our generated key matches it.
	}

	input, err = os.OpenFile(outputPath, os.O_RDONLY|os.O_EXCL|os.O_SYNC, 0600)

	if err != nil {
		return
	}
	defer input.Close()

	kb := &caam_kb_data{}
	kb.set(&key, &blob, &keymod)

	_, err = io.ReadFull(input, blob)

	if err != nil {
		return
	}

	err = CAAMOp(CAAM_KB_DECRYPT, uintptr(unsafe.Pointer(kb)))

	if err != nil {
		return
	}

	if len(newKey) != 0 && !bytes.Equal(newKey, key) {
		err = fmt.Errorf("key initialization and decryption mismatch")
	}

	return
}

func CAAMEncrypt(password string, input *os.File, output *os.File) (err error) {
	var blob []byte

	// Generate a random AES-256-OFB file encryption key, to be protected
	// by the CAAM in an encrypted blob.
	key := make([]byte, derivedKeySize)
	_, err = io.ReadFull(rand.Reader, key)

	if err != nil {
		return
	}

	// Derive the key modifier from user password, to ensure encrypted blob
	// decryption only with the specific hardware and user.
	salt, keymod, err := deriveKeyPBKDF2(nil, password, KEYMOD_LEN)

	if err != nil {
		return
	}

	kb := &caam_kb_data{}
	kb.set(&key, &blob, &keymod)

	err = CAAMOp(CAAM_KB_ENCRYPT, uintptr(unsafe.Pointer(kb)))

	if err != nil {
		return
	}

	_, err = output.Write(blob)

	if err != nil {
		return
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)

	if err != nil {
		return
	}

	return encryptOFB(key, salt, iv, input, output)
}

func CAAMDecrypt(password string, input *os.File, output *os.File) (err error) {
	var key []byte

	blob := make([]byte, derivedKeySize+BLOB_OVERHEAD)
	_, err = io.ReadFull(input, blob)

	if err != nil {
		return
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

	_, keymod, err := deriveKeyPBKDF2(salt, password, KEYMOD_LEN)

	if err != nil {
		return
	}

	kb := &caam_kb_data{}
	kb.set(&key, &blob, &keymod)

	err = CAAMOp(CAAM_KB_DECRYPT, uintptr(unsafe.Pointer(kb)))

	if err != nil {
		return
	}

	return decryptOFB(key, salt, iv, input, output)
}

func CAAMOp(mode, arg uintptr) (err error) {
	caam, err := os.OpenFile(caamDevice, os.O_RDWR, 0600)

	if err != nil {
		return
	}

	syscall.Flock(int(caam.Fd()), syscall.LOCK_EX)
	defer syscall.Flock(int(caam.Fd()), syscall.LOCK_UN)
	defer caam.Close()

	err = ioctl(caam.Fd(), mode, arg)

	if err != nil {
		return
	}
	defer caam.Close()

	return
}
