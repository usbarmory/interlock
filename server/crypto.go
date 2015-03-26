// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

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
	Extension   string `json:"ext"`
}

type cipherInterface interface {
	// provides cipher information
	GetInfo() cipherInfo
	// provides key information
	GetKeyInfo(key) (string, error)
	// sets symmetric or asymmetric key password
	SetPassword(string) error
	// sets encryption, decryption or signing key
	SetKey(key) error
	// encryption method
	Encrypt(src *os.File, dst *os.File, sign bool) error
	// decryption method
	Decrypt(src *os.File, dst *os.File, verify bool) error
	// signing method
	Sign(src *os.File, dst *os.File) error
	// signature verification method
	Verify(src *os.File, sig *os.File) error
	// clears previously set key material and password
	Reset()
}

func ciphers(w http.ResponseWriter) (res jsonObject) {
	ciphers := []cipherInfo{}

	for _, v := range conf.availableCiphers {
		ciphers = append(ciphers, v.GetInfo())
	}

	res = jsonObject{
		"status":   "OK",
		"response": ciphers,
	}

	return
}

func (k *key) BuildPath(cipher cipherInterface) (path string) {
	var subdir string

	fileName := fmt.Sprintf("%s.%s", k.Identifier, k.KeyFormat)

	if k.Private {
		subdir = "private"
	} else {
		subdir = "public"
	}

	path = filepath.Join(conf.KeyPath, cipher.GetInfo().Extension, subdir, fileName)

	return
}

func keyInfo(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"path"})

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

	pathList := strings.Split(path, "/")

	if len(pathList) < 3 {
		err = fmt.Errorf("invalid file in key path: %s", path)
		return
	}

	cipherExt := pathList[len(pathList)-3]
	typeInfo := pathList[len(pathList)-2]

	switch typeInfo {
	case "private":
		private = true
	case "public":
		private = false
	default:
		err = errors.New("missing private/public path entry")
		return
	}

	cipher = conf.FindCipherByExt(cipherExt)

	if cipher == nil {
		err = errors.New("could not identify compatible key cipher")
	}

	k = key{
		Identifier: identifier,
		KeyFormat:  format[1:],
		Cipher:     cipher.GetInfo().Name,
		Private:    private,
		Path:       filepath.Join("/", conf.KeyPath, cipherExt, typeInfo, name),
	}

	return
}

func getKeys(cipher cipherInterface, private bool, filter string) (keys []key, err error) {
	var subdir string

	basePath := filepath.Join(conf.mountPoint, conf.KeyPath, cipher.GetInfo().Extension)

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

func keys(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	var filter string
	var cipherName string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"public", "private"})

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

func uploadKey(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	var k key
	var cipher cipherInterface

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"key", "data"})

	if err != nil {
		return errorResponse(err, "")
	}

	err = json.Unmarshal(req["key"].([]byte), &k)

	if err != nil {
		return errorResponse(err, "")
	}

	for _, c := range conf.enabledCiphers {
		if c.GetInfo().Name == k.Cipher {
			cipher = c
			break
		}

		if cipher.GetInfo().KeyFormat == "password" {
			err = errors.New("specified cipher does not support key format")
			break
		}
	}

	if cipher == nil {
		err = errors.New("could not identify compatible key cipher")
	}

	if err != nil {
		return errorResponse(err, "")
	}

	keyPath := filepath.Join(conf.mountPoint, k.BuildPath(cipher))
	output, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)
	defer output.Close()

	if err != nil {
		return errorResponse(err, "")
	}

	written, err := io.Copy(output, strings.NewReader(req["data"].(string)))

	if err != nil {
		return errorResponse(err, "")
	}

	status.Log(syslog.LOG_INFO, "uploaded %s key %s (%v bytes)", cipher.GetInfo().Name, k.Identifier, written)

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}
