// INTERLOCK | https://github.com/usbarmory/interlock
// Copyright (c) WithSecure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

// Symmetric file encryption using AES-256-CTR, key is derived from password
// using PBKDF2 with SHA256 and 4096 rounds. The salt, initialization vector
// are prepended to the encrypted file, the HMAC for authentication is
// appended:
//
// salt (8 bytes) || iv (16 bytes) || ciphertext || hmac (32 bytes)

type aes256CTR struct {
	info     cipherInfo
	password string

	cipherInterface
}

func init() {
	conf.SetAvailableCipher(new(aes256CTR).Init())
}

func (a *aes256CTR) Init() cipherInterface {
	a.info = cipherInfo{
		Name:        "AES-256-CTR",
		Description: "AES CTR w/ 256 bit key derived using PBKDF2",
		KeyFormat:   "password",
		Enc:         true,
		Dec:         true,
		Sig:         false,
		OTP:         false,
		Msg:         false,
		Extension:   "aes256ofb",
	}

	return a
}

func (a *aes256CTR) New() cipherInterface {
	return new(aes256CTR).Init()
}

func (a *aes256CTR) GetInfo() cipherInfo {
	return a.info
}

func (a *aes256CTR) SetPassword(password string) (err error) {
	if len(password) < 8 {
		return errors.New("password < 8 characters")
	}

	a.password = password

	return
}

func (a *aes256CTR) Encrypt(input *os.File, output *os.File, sign bool) (err error) {
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

	err = encryptCTR(key, salt, iv, input, output)

	return
}

func (a *aes256CTR) Decrypt(input *os.File, output *os.File, verify bool) (err error) {
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

	err = decryptCTR(key, salt, iv, input, output)

	return
}

func (a *aes256CTR) GenKey(i string, e string) (p string, s string, err error) {
	err = errors.New("symmetric cipher does not support key generation")
	return
}

func (a *aes256CTR) GetKeyInfo(k key) (i string, err error) {
	err = errors.New("symmetric cipher does not support key")
	return
}

func (a *aes256CTR) SetKey(k key) error {
	return errors.New("symmetric cipher does not support key")
}

func (a *aes256CTR) Sign(i *os.File, o *os.File) error {
	return errors.New("symmetric cipher does not support signing")
}

func (a *aes256CTR) Verify(i *os.File, s *os.File) error {
	return errors.New("symmetric cipher does not support signature verification")
}

func (a *aes256CTR) GenOTP(timestamp int64) (otp string, exp int64, err error) {
	err = errors.New("cipher does not support OTP generation")
	return
}

func encryptCTR(key []byte, salt []byte, iv []byte, input *os.File, output *os.File) (err error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return
	}

	_, err = output.Write(salt)

	if err != nil {
		return
	}

	_, err = output.Write(iv)

	if err != nil {
		return
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(salt)
	mac.Write(iv)

	stream := cipher.NewCTR(block, iv)
	buf := make([]byte, 32*1024)

	for {
		n, er := input.Read(buf)

		if n > 0 {
			c := make([]byte, n)
			stream.XORKeyStream(c, buf[0:n])

			mac.Write(c)
			output.Write(c)
		}

		if er == io.EOF {
			break
		}

		if er != nil {
			err = er
			break
		}
	}

	if err != nil {
		return
	}

	_, err = output.Write(mac.Sum(nil))

	return
}

func decryptCTR(key []byte, salt []byte, iv []byte, input *os.File, output *os.File) (err error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return
	}

	stat, err := input.Stat()

	if err != nil {
		return
	}

	headerSize, err := input.Seek(0, 1)

	if err != nil {
		return
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(salt)
	mac.Write(iv)

	macSize := int64(mac.Size())
	limit := stat.Size() - headerSize - macSize

	ciphertextReader := io.LimitReader(input, limit)
	_, err = io.Copy(mac, ciphertextReader)

	if err != nil {
		return
	}

	inputMac := make([]byte, mac.Size())
	_, err = input.ReadAt(inputMac, stat.Size()-macSize)

	if err != nil {
		return
	}

	if !hmac.Equal(inputMac, mac.Sum(nil)) {
		return errors.New("invalid HMAC")
	}

	stream := cipher.NewCTR(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: output}

	_, err = input.Seek(headerSize, 0)

	if err != nil {
		return
	}

	ciphertextReader = io.LimitReader(input, limit)

	_, err = io.Copy(writer, ciphertextReader)

	return
}

func PKCS7Pad(buf []byte, extraBlock bool) []byte {
	padLen := 0
	r := len(buf) % aes.BlockSize

	if r != 0 {
		padLen = aes.BlockSize - r
	} else if extraBlock {
		padLen = aes.BlockSize
	}

	padding := []byte{(byte)(padLen)}
	padding = bytes.Repeat(padding, padLen)
	buf = append(buf, padding...)

	return buf
}

func PKCS7Unpad(buf []byte) []byte {
	return buf[:(len(buf) - int(buf[len(buf)-1]))]
}
