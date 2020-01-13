// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const derivedKeySize = 32

type key struct {
	Identifier string `json:"identifier"`
	KeyFormat  string `json:"key_format"`
	Cipher     string `json:"cipher"`
	Private    bool   `json:"private"`
	Path       string `json:"path"`
}

type cipherInfo struct {
	Name        string `json:"name"`
	Description string `json:"info"`
	KeyFormat   string `json:"key_format"`
	Enc         bool   `json:"enc"`
	Dec         bool   `json:"dec"`
	Sig         bool   `json:"sig"`
	OTP         bool   `json:"otp"`
	Msg         bool   `json:"msg"`
	Extension   string `json:"ext"`
}

type cipherInterface interface {
	// return a fresh cipher instance
	New() cipherInterface
	// initialize cipher
	Init() cipherInterface
	// post-auth cipher activation
	Activate(active bool) error
	// provide cipher information
	GetInfo() cipherInfo
	// generate key
	GenKey(identifier string, email string) (pub string, sec string, err error)
	// provide key information
	GetKeyInfo(key) (string, error)
	// set symmetric or asymmetric key password
	SetPassword(string) error
	// set encryption, decryption or signing key
	SetKey(key) error
	// encryption
	Encrypt(src *os.File, dst *os.File, sign bool) error
	// decryption
	Decrypt(src *os.File, dst *os.File, verify bool) error
	// signing
	Sign(src *os.File, dst *os.File) error
	// signature verification
	Verify(src *os.File, sig *os.File) error
	// One Time Password
	GenOTP(timestamp int64) (otp string, exp int64, err error)
	// cipher specific API request handler
	HandleRequest(*http.Request) jsonObject
}

type HSMInterface interface {
	// return a fresh HSM instance
	New() HSMInterface
	// return a fresh cipher instance
	Cipher() cipherInterface
	// derive key
	DeriveKey(diversifier []byte, iv []byte) (derivedKey []byte, err error)
}

func ciphers() (res jsonObject) {
	ciphers := []cipherInfo{}

	for _, v := range conf.enabledCiphers {
		ciphers = append(ciphers, v.GetInfo())
	}

	res = jsonObject{
		"status":   "OK",
		"response": ciphers,
	}

	return
}

func (k *key) Store(cipher cipherInterface, data string) (err error) {
	var subdir string

	fileName := fmt.Sprintf("%s.%s", k.Identifier, k.KeyFormat)

	if k.Private {
		subdir = "private"
	} else {
		subdir = "public"
	}

	k.Path = filepath.Join(conf.KeyPath, cipher.GetInfo().Extension, subdir, fileName)
	keyPath := filepath.Join(conf.MountPoint, k.Path)

	err = os.MkdirAll(path.Dir(keyPath), 0700)

	if err != nil {
		return
	}

	output, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		return
	}
	defer output.Close()

	written, err := io.Copy(output, strings.NewReader(data))

	if err != nil {
		return
	}

	status.Log(syslog.LOG_INFO, "stored %s %s key %s (%v bytes)", subdir, cipher.GetInfo().Name, k.Identifier, written)

	return
}

func keyInfo(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"path:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	path, err := absolutePath(req["path"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	key, cipher, err := getKey(path)

	if err != nil {
		return errorResponse(err, "")
	}

	info, err := cipher.GetKeyInfo(key)

	if err != nil {
		return errorResponse(err, "")
	}

	res = jsonObject{
		"status":   "OK",
		"response": info,
	}

	return
}

func getKey(path string) (k key, cipher cipherInterface, err error) {
	var private bool

	fileInfo, err := os.Stat(path)

	if err != nil {
		return
	}

	if fileInfo.IsDir() {
		err = errors.New("cannot parse directory as key file")
		return
	}

	name := fileInfo.Name()
	format := filepath.Ext(name)
	identifier := name[0 : len(name)-len(format)]

	if format == "" {
		format = "N/A"
	} else {
		format = format[1:]
	}

	relativePath := relativePath(path)
	keyPath, err := filepath.Rel("/"+conf.KeyPath, relativePath)

	if err != nil {
		return
	}

	pathList := strings.Split(keyPath, "/")

	if len(pathList) < 3 {
		err = fmt.Errorf("invalid file in key path: %s", path)
		return
	}

	cipherExt := pathList[0]
	typeInfo := pathList[1]

	switch typeInfo {
	case "private":
		private = true
	case "public":
		private = false
	default:
		private = true
	}

	cipher, err = conf.GetCipherByExt(cipherExt)

	if err != nil {
		return
	}

	k = key{
		Identifier: identifier,
		KeyFormat:  format,
		Cipher:     cipher.GetInfo().Name,
		Private:    private,
		Path:       relativePath,
	}

	return
}

func getKeys(cipher cipherInterface, private bool, filter string) (keys []key, err error) {
	var subdir string

	basePath := filepath.Join(conf.MountPoint, conf.KeyPath, cipher.GetInfo().Extension)

	if private {
		subdir = "private"
	} else {
		subdir = "public"
	}

	basePath = filepath.Join(basePath, subdir)

	walkFn := func(path string, fileInfo os.FileInfo, e error) (err error) {
		if fileInfo == nil {
			return
		}

		if fileInfo.IsDir() {
			return
		}

		k, _, err := getKey(path)

		if err != nil {
			return
		}

		if filter != "" {
			var info string

			info, err = cipher.GetKeyInfo(k)

			if err != nil {
				return
			}

			if !strings.Contains(info, filter) {
				return
			}
		}

		keys = append(keys, k)

		return
	}

	err = filepath.Walk(basePath, walkFn)

	return
}

func keys(r *http.Request) (res jsonObject) {
	var filter string
	var cipherName string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"public:b", "private:b"})

	if err != nil {
		return errorResponse(err, "")
	}

	if f, ok := req["filter"]; ok {
		filter = f.(string)
	}

	if c, ok := req["cipher"]; ok {
		cipherName = c.(string)
	}

	keys := []key{}

	for _, cipher := range conf.enabledCiphers {
		if cipherName != "" && !strings.Contains(cipher.GetInfo().Name, cipherName) {
			continue
		}

		if cipher.GetInfo().KeyFormat == "password" {
			continue
		}

		if req["public"].(bool) {
			publicKeys, _ := getKeys(cipher, false, filter)
			keys = append(keys, publicKeys...)
		}

		if req["private"].(bool) {
			privateKeys, _ := getKeys(cipher, true, filter)
			keys = append(keys, privateKeys...)
		}
	}

	res = jsonObject{
		"status":   "OK",
		"response": keys,
	}

	return
}

func genKey(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"identifier:s", "key_format:s", "cipher:s", "email:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	identifier := req["identifier"].(string)
	email := req["email"].(string)
	cipherName := req["cipher"].(string)

	cipher, err := conf.GetCipher(cipherName)

	if err != nil || cipher.GetInfo().KeyFormat == "password" {
		return errorResponse(errors.New("could not identify compatible key cipher"), "")
	}

	go func() {
		n := status.Notify(syslog.LOG_INFO, "generating %s keypair %s", cipher.GetInfo().Name, identifier)
		defer status.Remove(n)

		pub, sec, err := cipher.GenKey(identifier, email)

		if err != nil {
			status.Error(err)
			return
		}

		pubKey := key{
			Identifier: identifier,
			KeyFormat:  cipher.GetInfo().KeyFormat,
			Cipher:     cipher.GetInfo().Name,
			Private:    false,
		}

		err = pubKey.Store(cipher, pub)

		if err != nil {
			status.Error(err)
			return
		}

		secKey := key{
			Identifier: identifier,
			KeyFormat:  cipher.GetInfo().KeyFormat,
			Cipher:     cipher.GetInfo().Name,
			Private:    true,
		}

		err = secKey.Store(cipher, sec)

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "generated %s keypair %s", cipher.GetInfo().Name, identifier)
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func uploadKey(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"key:i", "data:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	k := key{}

	// we re-marsahal and unmarshal to avoid having to assign struct
	// elements individually
	s, _ := json.Marshal(req["key"])
	err = json.Unmarshal(s, &k)

	if err != nil {
		return errorResponse(err, "")
	}

	cipher, err := conf.GetCipher(k.Cipher)

	if err != nil || cipher.GetInfo().KeyFormat == "password" {
		return errorResponse(errors.New("could not identify compatible key cipher"), "")
	}

	err = k.Store(cipher, req["data"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	// test the key
	err = cipher.SetKey(k)

	if err != nil {
		return errorResponse(fmt.Errorf("saved key is unusable: %s", err.Error()), "")
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func deriveKeyPBKDF2(salt []byte, password string, size int) (randSalt []byte, key []byte, err error) {
	if len(salt) == 0 {
		randSalt = make([]byte, 8)
		_, err = io.ReadFull(rand.Reader, randSalt)

		if err != nil {
			return
		}

		salt = randSalt
	}

	key = pbkdf2.Key([]byte(password), salt, 4096, size, sha256.New)

	return
}
