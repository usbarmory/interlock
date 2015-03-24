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
	GetInfo() cipherInfo
	GetKeyInfo(key) (string, error)
	SetPassword(string) error
	SetKey(key) error
	Encrypt(src *os.File, dst *os.File) error
	Decrypt(src *os.File, dst *os.File) error
	Reset() error // FIXME
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

	path := req["path"].(string)
	key, err := getKey(path)

	if err != nil {
		return errorResponse(err, "")
	}

	cipher := conf.FindCipherByExt(key.Cipher)

	if cipher == nil {
		err = errors.New("could not identify compatible key cipher")
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

func getKey(path string) (k key, err error) {
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

	k = key{
		Identifier: identifier,
		KeyFormat:  format[1:],
		Cipher:     conf.FindCipherByExt(cipherExt).GetInfo().Name,
		Private:    private,
		Path:       filepath.Join("/", conf.KeyPath, cipherExt, typeInfo, name),
	}

	return
}

func getKeys(cipher cipherInterface, private bool) (keys []key, err error) {
	var subdir string

	basePath := filepath.Join(conf.mountPoint, conf.KeyPath, cipher.GetInfo().Extension)

	if private {
		subdir = "private"
	} else {
		subdir = "public"
	}

	basePath = filepath.Join(basePath, subdir)

	walkFn := func(path string, info os.FileInfo, e error) (err error) {
		if info == nil {
			return
		}

		if info.IsDir() {
			return
		}

		k, err := getKey(path)

		if err != nil {
			return
		}

		keys = append(keys, k)

		return
	}

	err = filepath.Walk(basePath, walkFn)

	return
}

func keys(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"public", "private"})

	if err != nil {
		return errorResponse(err, "")
	}

	keys := []key{}

	for _, cipher := range conf.enabledCiphers {
		if cipher.GetInfo().KeyFormat == "password" {
			continue
		}

		if req["public"].(bool) {
			publicKeys, _ := getKeys(cipher, false)
			keys = append(keys, publicKeys...)
		}

		if req["private"].(bool) {
			privateKeys, _ := getKeys(cipher, true)
			keys = append(keys, privateKeys...)
		}
	}

	res = jsonObject{
		"status":   "OK",
		"response": keys,
	}

	return
}

// FIXME: untested
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

	for _, cipher = range conf.enabledCiphers {
		if cipher.GetInfo().Name == k.Cipher {
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
