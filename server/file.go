// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

const (
	_move = iota
	_copy
	_mkdir
	_delete
)

type inode struct {
	Name    string `json:"name"`
	Dir     bool   `json:"dir"`
	Size    int64  `json:"size"`
	Mtime   int64  `json:"mtime"`
	KeyPath bool   `json:"key_path"`
	Key     *key   `json:"key"`
}

type downloadCache struct {
	sync.Mutex
	cache map[string]string
}

var download = downloadCache{
	cache: make(map[string]string),
}

var traversalPattern = regexp.MustCompile("\\.\\./")

func (d *downloadCache) Add(id string, path string) {
	d.Lock()
	defer d.Unlock()

	// an abusive client can potentially add download entries at will,
	// given the non persistent nature of the server, this is not
	// considered to be an issue

	d.cache[id] = path
}

func (d *downloadCache) Remove(id string) (path string, err error) {
	d.Lock()
	defer d.Unlock()
	defer delete(d.cache, id)

	if v, ok := d.cache[id]; ok {
		path = v
	} else {
		err = errors.New("download id not found")
	}

	return
}

func absolutePath(subPath string) (path string, err error) {
	if traversalPattern.MatchString(subPath) {
		err = errors.New("path traversal detected")
	}

	path = filepath.Join(conf.mountPoint, subPath)

	return
}

func relativePath(path string) (subPath string, err error) {
	if !strings.HasPrefix(path, conf.mountPoint) {
		err = errors.New("invalid path")
		return
	}

	subPath = path[len(conf.mountPoint):]

	return
}

func fileMove(w http.ResponseWriter, r *http.Request) jsonObject {
	return fileOp(w, r, _move)
}

func fileCopy(w http.ResponseWriter, r *http.Request) jsonObject {
	return fileOp(w, r, _copy)
}

func fileMkdir(w http.ResponseWriter, r *http.Request) jsonObject {
	return fileOp(w, r, _mkdir)
}

func fileDelete(w http.ResponseWriter, r *http.Request) jsonObject {
	return fileOp(w, r, _delete)
}

func fileOp(w http.ResponseWriter, r *http.Request, mode int) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	switch mode {
	case _move, _copy:
		err = validateRequest(req, []string{"src", "dst"})

		if err != nil {
			return errorResponse(err, "")
		}

		src, err := absolutePath(req["src"].(string))

		if err != nil {
			return errorResponse(err, "")
		}

		dst, err := absolutePath(req["dst"].(string))

		if err != nil {
			return errorResponse(err, "")
		}

		if mode == _move {
			err = os.Rename(src, dst)
		} else { // _copy
			args := []string{"-ra", src, dst}
			cmd := "/bin/cp"

			_, err = execCommand(cmd, args, false, "")

			if err != nil {
				return errorResponse(err, "")
			}
		}
	case _mkdir, _delete:
		err = validateRequest(req, []string{"path"})

		if err != nil {
			return errorResponse(err, "")
		}

		if mode == _mkdir {
			path, err := absolutePath(req["path"].(string))

			if err != nil {
				return errorResponse(err, "")
			}

			err = os.MkdirAll(path, 0700)
		} else { // _delete
			path := req["path"].([]interface{})

			for _, file := range path {
				p, err := absolutePath(file.(string))

				if err != nil {
					return errorResponse(err, "")
				}

				err = os.RemoveAll(p)

				status.Log(syslog.LOG_NOTICE, "deleted %s", file)

				if err != nil {
					return errorResponse(err, "")
				}
			}
		}
	default:
		err = errors.New("unsupported operation")
	}

	if err != nil {
		return errorResponse(err, "")
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileList(w http.ResponseWriter, r *http.Request) (res jsonObject) {
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

	fileInfo, err := ioutil.ReadDir(path)

	if err != nil {
		return errorResponse(err, "")
	}

	var stat syscall.Statfs_t
	err = syscall.Statfs(path, &stat)

	if err != nil {
		return errorResponse(err, "")
	}

	totalSpace := stat.Blocks * uint64(stat.Bsize)
	freeSpace := stat.Bavail * uint64(stat.Bsize)

	inKeyPath := false
	absoluteKeyPath := filepath.Join(conf.mountPoint, conf.KeyPath)

	if strings.HasPrefix(path, absoluteKeyPath) {
		inKeyPath = true
	}

	inodes := []inode{}

	for _, file := range fileInfo {
		if file.Name() == "lost+found" {
			continue
		}

		inode := inode{
			Name:    file.Name(),
			Dir:     file.IsDir(),
			Size:    file.Size(),
			Mtime:   file.ModTime().Unix(),
			KeyPath: inKeyPath,
		}

		if !file.IsDir() && inKeyPath {
			key, _, err := getKey(filepath.Join(path, file.Name()))

			if err == nil {
				inode.Key = &key
			} else {
				inode.Key = nil
			}
		}

		inodes = append(inodes, inode)
	}

	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"total_space": totalSpace,
			"free_space":  freeSpace,
			"inodes":      inodes},
	}

	return
}

func fileUpload(w http.ResponseWriter, r *http.Request) {
	var err error

	defer func() {
		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), 400)
		}
	}()

	fileName := r.Header.Get("X-Uploadfilename")
	overwrite := r.Header.Get("X-Forceoverwrite")

	osPath, err := absolutePath(fileName)

	if err != nil {
		return
	}

	osDir := path.Dir(osPath)

	_, err = os.Stat(osPath)

	if err == nil && overwrite != "true" {
		err = fmt.Errorf("path %s exists but overwrite is false", osPath)
		return
	}

	err = os.MkdirAll(osDir, 0700)

	if err != nil {
		return
	}

	osFile, err := os.Create(osPath)
	defer osFile.Close()

	if err != nil {
		return
	}

	n := status.Notify(syslog.LOG_NOTICE, "uploading to %s", path.Base(osPath))
	defer status.Remove(n)

	written, err := io.Copy(osFile, r.Body)

	if err != nil {
		return
	}

	status.Log(syslog.LOG_INFO, "uploaded %v bytes to %s", written, path.Base(osPath))
}

func fileDownload(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"path"})

	if err != nil {
		return errorResponse(err, "")
	}

	osPath, err := absolutePath(req["path"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	_, err = os.Stat(osPath)

	if err != nil {
		return errorResponse(err, "")
	}

	id, err := randomString(16)

	if err != nil {
		return errorResponse(err, "")
	}

	download.Add(id, osPath)

	res = jsonObject{
		"status":   "OK",
		"response": id,
	}

	return
}

func fileDownloadByID(w http.ResponseWriter, id string) {
	var err error
	var written int64

	defer func() {
		if err != nil {
			log.Print(err)
			http.Error(w, err.Error(), 400)
		}
	}()

	osPath, err := download.Remove(id)

	if err != nil {
		return
	}

	stat, err := os.Stat(osPath)

	if err != nil {
		return
	}

	fileName := path.Base(osPath)

	n := status.Notify(syslog.LOG_NOTICE, "downloading %s", fileName)
	defer status.Remove(n)

	if stat.IsDir() {
		fileName += ".zip"
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+fileName+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")

	if stat.IsDir() {
		written, err = zipDir(w, osPath)
	} else {
		var input *os.File

		input, err = os.Open(osPath)
		defer input.Close()

		written, err = io.Copy(w, input)
	}

	if err != nil {
		return
	}

	status.Log(syslog.LOG_INFO, "downloaded %s (%v bytes)", fileName, written)
}

func zipDir(w http.ResponseWriter, dirPath string) (written int64, err error) {
	zw := zip.NewWriter(w)
	defer zw.Close()

	walkFn := func(osPath string, info os.FileInfo, e error) (err error) {
		var w int64
		var f io.Writer
		var input io.Reader

		if info == nil {
			return
		}

		if info.IsDir() {
			return
		}

		n := status.Notify(syslog.LOG_NOTICE, "adding %s to archive", path.Base(osPath))
		defer status.Remove(n)

		relPath, err := relativePath(osPath)

		if err != nil {
			return
		}

		f, err = zw.Create(relPath)

		if err != nil {
			return
		}

		input, err = os.Open(osPath)

		if err != nil {
			return
		}

		w, err = io.Copy(f, input)
		written += w

		if err != nil {
			return
		}

		return
	}

	n := status.Notify(syslog.LOG_NOTICE, "zipping %s", path.Base(dirPath))
	defer status.Remove(n)

	err = filepath.Walk(dirPath, walkFn)

	return
}

func fileEncrypt(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src", "cipher", "wipe_src", "sign", "password", "key", "sig_key"})

	if err != nil {
		return errorResponse(err, "")
	}

	src, err := absolutePath(req["src"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	wipe := req["wipe_src"].(bool)
	sign := req["sign"].(bool)
	password := req["password"].(string)
	keyPath := req["key"].(string)
	sigKeyPath := req["sig_key"].(string)

	cipher, ok := conf.enabledCiphers[req["cipher"].(string)]

	if !ok {
		return errorResponse(errors.New("invalid cipher"), "")
	}

	input, err := os.Open(src)

	if err != nil {
		input.Close()
		return errorResponse(err, "")
	}

	if cipher.GetInfo().Enc {
		if cipher.GetInfo().KeyFormat != "password" {
			keyPath = filepath.Join(conf.mountPoint, keyPath)
			key, _, err := getKey(keyPath)

			if err != nil {
				return errorResponse(err, "")
			}

			err = cipher.SetKey(key)

			if err != nil {
				return errorResponse(err, "")
			}
		}
	} else {
		err = errors.New("encryption requested but not supported by cipher")

		return errorResponse(err, "")
	}

	if sign && cipher.GetInfo().Sig {
		sigKeyPath = filepath.Join(conf.mountPoint, sigKeyPath)
		key, _, err := getKey(sigKeyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	} else if sign && !cipher.GetInfo().Sig {
		cipher.Reset()
		err = errors.New("signing requested but not supported by cipher")

		return errorResponse(err, "")
	}

	if password != "" {
		cipher.Reset()
		err = cipher.SetPassword(password)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	outputPath := src + "." + cipher.GetInfo().Extension
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		output.Close()
		cipher.Reset()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()
		defer cipher.Reset()

		n := status.Notify(syslog.LOG_INFO, "encrypting %s", path.Base(src))
		defer status.Remove(n)

		err = cipher.Encrypt(input, output, sign)

		if err != nil {
			status.Error(err)
			return
		}

		if wipe {
			err = os.Remove(src)
		}

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "completed encryption of %s", path.Base(src))
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileDecrypt(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	var cipher cipherInterface
	var outputPath string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src", "password", "verify", "key", "sig_key"})

	if err != nil {
		return errorResponse(err, "")
	}

	src, err := absolutePath(req["src"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	password := req["password"].(string)
	verify := req["verify"].(bool)
	keyPath := req["key"].(string)
	sigKeyPath := req["sig_key"].(string)

	if c, ok := req["cipher"]; ok {
		cipher, ok = conf.enabledCiphers[c.(string)]

		if !ok {
			return errorResponse(errors.New("invalid cipher"), "KO")
		}

		suffix := "." + cipher.GetInfo().Extension

		if strings.HasSuffix(src, suffix) {
			outputPath = strings.TrimSuffix(src, suffix)
		} else {
			outputPath = src + ".decrypted"
		}
	} else {
		ext := filepath.Ext(src)
		cipher = conf.FindCipherByExt(ext[1:len(ext)])
		outputPath = src[0 : len(src)-len(ext)]

		if cipher == nil {
			return errorResponse(fmt.Errorf("file extension %s does not match valid cipher", ext), "")
		}
	}

	input, err := os.Open(src)

	if err != nil {
		input.Close()
		return errorResponse(err, "")
	}

	if cipher.GetInfo().Dec {
		if cipher.GetInfo().KeyFormat != "password" {
			keyPath = filepath.Join(conf.mountPoint, keyPath)
			key, _, err := getKey(keyPath)

			if err != nil {
				return errorResponse(err, "")
			}

			err = cipher.SetKey(key)

			if err != nil {
				cipher.Reset()
				return errorResponse(err, "")
			}
		}

		err = cipher.SetPassword(password)

		if err != nil {
			cipher.Reset()
			return errorResponse(err, "")
		}
	} else {
		err = errors.New("decryption requested but not supported by cipher")

		return errorResponse(err, "")
	}

	if verify && cipher.GetInfo().Sig {
		sigKeyPath = filepath.Join(conf.mountPoint, sigKeyPath)
		key, _, err := getKey(sigKeyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	} else if verify && !cipher.GetInfo().Sig {
		cipher.Reset()
		err = errors.New("signature verification requested but not supported by cipher")

		return errorResponse(err, "")
	}

	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		output.Close()
		cipher.Reset()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()
		defer cipher.Reset()

		n := status.Notify(syslog.LOG_INFO, "decrypting %s", path.Base(src))
		defer status.Remove(n)

		err = cipher.Decrypt(input, output, verify)

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "completed decryption of %s", path.Base(src))
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileSign(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src", "cipher", "password", "key"})

	if err != nil {
		return errorResponse(err, "")
	}

	src, err := absolutePath(req["src"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	password := req["password"].(string)
	keyPath := req["key"].(string)

	cipher, ok := conf.enabledCiphers[req["cipher"].(string)]

	if !ok {
		return errorResponse(errors.New("invalid cipher"), "")
	}

	input, err := os.Open(src)

	if err != nil {
		input.Close()
		return errorResponse(err, "")
	}

	if cipher.GetInfo().Sig {
		keyPath = filepath.Join(conf.mountPoint, keyPath)
		key, _, err := getKey(keyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	} else {
		cipher.Reset()
		err = errors.New("signing requested but not supported by cipher")

		return errorResponse(err, "")
	}

	if password != "" {
		cipher.Reset()
		err = cipher.SetPassword(password)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	outputPath := src + "." + cipher.GetInfo().Extension + "-signature"
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		output.Close()
		cipher.Reset()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()
		defer cipher.Reset()

		n := status.Notify(syslog.LOG_INFO, "signing %s", path.Base(src))
		defer status.Remove(n)

		err = cipher.Sign(input, output)

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "completed signing of %s", path.Base(src))
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileVerify(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	var cipher cipherInterface

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src", "sig", "key"})

	if err != nil {
		return errorResponse(err, "")
	}

	src, err := absolutePath(req["src"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	sigPath, err := absolutePath(req["sig"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	sigKeyPath := req["key"].(string)

	if c, ok := req["cipher"]; ok {
		cipher, ok = conf.enabledCiphers[c.(string)]

		if !ok {
			return errorResponse(errors.New("invalid cipher"), "KO")
		}
	} else {
		ext := filepath.Ext(sigPath)
		ext = strings.TrimSuffix(ext, "-signature")
		cipher = conf.FindCipherByExt(ext[1:len(ext)])

		if cipher == nil {
			return errorResponse(fmt.Errorf("file extension %s does not match valid cipher", ext), "")
		}
	}

	input, err := os.Open(src)
	defer input.Close()

	if err != nil {
		return errorResponse(err, "")
	}

	defer cipher.Reset()

	if cipher.GetInfo().Sig {
		if cipher.GetInfo().KeyFormat != "password" {
			sigKeyPath = filepath.Join(conf.mountPoint, sigKeyPath)
			key, _, err := getKey(sigKeyPath)

			if err != nil {
				return errorResponse(err, "")
			}

			err = cipher.SetKey(key)

			if err != nil {
				cipher.Reset()
				return errorResponse(err, "")
			}
		}

		if err != nil {
			return errorResponse(err, "")
		}
	} else {
		err = errors.New("signature verification requested but not supported by cipher")

		return errorResponse(err, "")
	}

	if cipher.GetInfo().Sig {
		sigKeyPath = filepath.Join(conf.mountPoint, sigKeyPath)
		key, _, err := getKey(sigKeyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	} else {
		err = errors.New("signature verification requested but not supported by cipher")

		return errorResponse(err, "")
	}

	sig, err := os.Open(sigPath)
	defer sig.Close()

	if err != nil {
		return errorResponse(err, "")
	}

	err = cipher.Verify(input, sig)

	if err != nil {
		status.Error(err)
		return
	}

	status.Log(syslog.LOG_NOTICE, "completed verification of %s", path.Base(src))

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}
