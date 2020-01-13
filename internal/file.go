// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.
//
//+build linux

package interlock

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	_move = iota
	_copy
	_mkdir
	_extract
	_delete
)

type inode struct {
	Name    string `json:"name"`
	Dir     bool   `json:"dir"`
	Size    int64  `json:"size"`
	Mtime   int64  `json:"mtime"`
	KeyPath bool   `json:"key_path"`
	Private bool   `json:"private"`
	Key     *key   `json:"key"`
	SHA256  string `json:"sha256"`
}

type downloadCache struct {
	sync.Mutex
	cache map[string]string
}

var download = downloadCache{
	cache: make(map[string]string),
}

const traversalPattern = "../"

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
	if strings.Contains(subPath, traversalPattern) {
		err = errors.New("path traversal detected")
	}

	path = filepath.Join(conf.MountPoint, subPath)

	return
}

func relativePath(p string) (subPath string) {
	if !strings.HasPrefix(p, conf.MountPoint) {
		subPath = path.Base(p)
	} else {
		subPath = p[len(conf.MountPoint):]
	}

	return
}

func detectKeyPath(path string) (inKeyPath bool, private bool) {
	inKeyPath = false
	absoluteKeyPath := filepath.Join(conf.MountPoint, conf.KeyPath)

	if strings.HasPrefix(path, absoluteKeyPath) {
		inKeyPath = true
		private = true

		if strings.HasSuffix(filepath.Dir(path), "public") {
			private = false
		}
	}

	return
}

func fileMove(r *http.Request) jsonObject {
	return fileMultiOp(r, _move)
}

func fileCopy(r *http.Request) jsonObject {
	return fileMultiOp(r, _copy)
}

func fileNewfile(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"path:s", "contents:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	path, err := absolutePath(req["path"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	inKeyPath, _ := detectKeyPath(path)

	if inKeyPath {
		return errorResponse(errors.New("creating files within key storage is not allowed"), "")
	}

	_, err = os.Stat(path)

	if err == nil {
		return errorResponse(fmt.Errorf("path %s exists, not overwriting", relativePath(path)), "")
	}

	contents := req["contents"].(string)
	err = ioutil.WriteFile(path, []byte(contents), 0644)

	if err != nil {
		return errorResponse(errors.New("cannot create file"), "")
	}

	status.Log(syslog.LOG_NOTICE, "created file %s (%d bytes)", relativePath(path), len(contents))

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileMkdir(r *http.Request) jsonObject {
	return fileMultiOp(r, _mkdir)
}

func fileExtract(r *http.Request) jsonObject {
	return fileMultiOp(r, _extract)
}

func fileDelete(r *http.Request) jsonObject {
	return fileMultiOp(r, _delete)
}

func fileCompress(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src:a", "dst:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	dst, err := absolutePath(req["dst"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	switch filepath.Ext(dst) {
	case ".zip", ".ZIP":
		src := req["src"].([]interface{})
		s := make([]string, len(src))

		for i := range src {
			s[i], err = absolutePath(src[i].(string))

			if err != nil {
				return errorResponse(err, "")
			}
		}

		err = zipPath(s, dst)
	default:
		err = errors.New("unsupported archive format")
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

func fileMultiOp(r *http.Request, mode int) (res jsonObject) {
	var srcAttr string
	var dst string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	switch mode {
	case _move, _copy, _extract:
		err = validateRequest(req, []string{"src:a", "dst:s"})
		srcAttr = "src"

		if err != nil {
			return errorResponse(err, "")
		}

		dst, err = absolutePath(req["dst"].(string))

		if err != nil {
			return errorResponse(err, "")
		}
	case _mkdir, _delete:
		err = validateRequest(req, []string{"path:a"})
		srcAttr = "path"
	default:
		err = errors.New("unsupported operation")
	}

	if err != nil {
		return errorResponse(err, "")
	}

	for _, file := range req[srcAttr].([]interface{}) {
		path, err := absolutePath(file.(string))

		if err != nil {
			return errorResponse(err, "")
		}

		err = fileOp(path, dst, mode)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileOp(src string, dst string, mode int) (err error) {
	switch mode {
	case _move, _copy, _extract:
		inKeyPath, private := detectKeyPath(src)

		if inKeyPath && private {
			err = errors.New("cannot move or copy private key(s)")
			break
		}

		switch mode {
		case _copy, _move:
			var stat os.FileInfo
			var args []string
			var cmd string

			stat, err = os.Stat(dst)

			if err == nil && !stat.IsDir() {
				err = fmt.Errorf("path %s exists", relativePath(dst))
				break
			}

			if err == nil && stat.IsDir() {
				d := filepath.Join(dst, path.Base(src))
				_, err = os.Stat(d)

				if err == nil {
					err = fmt.Errorf("path %s exists", relativePath(d))
					break
				}
			}

			if mode == _copy {
				args = []string{"-ra", src, dst}
				cmd = "/bin/cp"
			} else { // _move
				args = []string{src, dst}
				cmd = "/bin/mv"
			}

			_, err = execCommand(cmd, args, false, "")
		case _extract:
			switch filepath.Ext(src) {
			case ".zip", ".ZIP":
				err = unzipFile(src, dst)
			default:
				err = errors.New("unsupported archive format")
			}
		}
	case _mkdir, _delete:
		if mode == _mkdir {
			err = os.MkdirAll(src, 0700)
		} else { // _delete
			err = os.RemoveAll(src)

			if err != nil {
				break
			}

			status.Log(syslog.LOG_NOTICE, "deleted %s", relativePath(src))
		}
	default:
		err = errors.New("unsupported operation")
	}

	return
}

func fileList(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"path:s", "sha256:b"})

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

	inodes := []inode{}

	for _, file := range fileInfo {
		if file.Name() == "lost+found" {
			continue
		}

		filePath := filepath.Join(path, file.Name())
		inKeyPath, private := detectKeyPath(filePath)

		inode := inode{
			Name:    file.Name(),
			Dir:     file.IsDir(),
			Size:    file.Size(),
			Mtime:   file.ModTime().Unix(),
			KeyPath: inKeyPath,
			Private: private,
		}

		if !file.IsDir() && inKeyPath {
			key, _, err := getKey(filePath)

			if err == nil {
				inode.Key = &key
			} else {
				status.Log(syslog.LOG_ERR, "error parsing %s, %s", file.Name(), err.Error())
				inode.Key = nil
			}
		}

		if !file.IsDir() && req["sha256"].(bool) {
			f, err := os.Open(filePath)

			if err == nil {
				defer f.Close()

				h := sha256.New()

				if _, err := io.Copy(h, f); err == nil {
					inode.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
				}
			}
		}

		inodes = append(inodes, inode)
	}

	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"total_space": totalSpace,
			"free_space":  freeSpace,
			"inodes":      inodes,
		},
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

	encodedFileName := r.Header.Get("X-Uploadfilename")
	overwrite := r.Header.Get("X-Forceoverwrite")

	// the path is URL encoded to support non-US-ASCII
	fileName, err := url.QueryUnescape(encodedFileName)

	if err != nil {
		return
	}

	osPath, err := absolutePath(fileName)

	if err != nil {
		return
	}

	osDir := path.Dir(osPath)

	_, err = os.Stat(osPath)

	if err == nil && overwrite != "true" {
		err = fmt.Errorf("path %s exists, not overwriting", osPath)
		return
	}

	err = os.MkdirAll(osDir, 0700)

	if err != nil {
		return
	}

	osFile, err := os.Create(osPath)
	_ = osFile.Chmod(0600)

	if err != nil {
		return
	}
	defer osFile.Close()

	n := status.Notify(syslog.LOG_NOTICE, "uploading %s", relativePath(osPath))
	defer status.Remove(n)

	written, err := io.Copy(osFile, r.Body)

	if err != nil {
		return
	}

	status.Log(syslog.LOG_INFO, "uploaded %s (%v bytes)", relativePath(osPath), written)
}

func fileDownload(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"path:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	osPath, err := absolutePath(req["path"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	inKeyPath, private := detectKeyPath(osPath)

	if inKeyPath && private {
		return errorResponse(errors.New("downloading private key(s) is not allowed"), "")
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

	n := status.Notify(syslog.LOG_NOTICE, "downloading %s", relativePath(osPath))
	defer status.Remove(n)

	if stat.IsDir() {
		fileName += ".zip"
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+fileName+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")

	if stat.IsDir() {
		written, err = zipWriter([]string{osPath}, w)
	} else {
		var input *os.File
		input, err = os.Open(osPath)

		if err != nil {
			return
		}
		defer input.Close()

		written, err = io.Copy(w, input)
	}

	if err != nil {
		return
	}

	status.Log(syslog.LOG_INFO, "downloaded %s (%v bytes)", fileName, written)
}

func fileEncrypt(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src:s", "cipher:s", "wipe_src:b", "sign:b", "password:s", "key:s", "sig_key:s"})

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
	cipherName := req["cipher"].(string)

	cipher, err := conf.GetCipher(cipherName)

	if err != nil {
		return errorResponse(err, "")
	}

	if !cipher.GetInfo().Enc {
		return errorResponse(errors.New("encryption requested but not supported by cipher"), "")
	}

	if cipher.GetInfo().KeyFormat != "password" && keyPath == "" {
		return errorResponse(errors.New("encryption key not specified"), "")
	}

	if cipher.GetInfo().KeyFormat != "password" {
		keyPath = filepath.Join(conf.MountPoint, keyPath)
		key, _, err := getKey(keyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	if sign && cipher.GetInfo().Sig {
		sigKeyPath = filepath.Join(conf.MountPoint, sigKeyPath)
		key, _, err := getKey(sigKeyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	} else if sign && !cipher.GetInfo().Sig {
		return errorResponse(errors.New("signing requested but not supported by cipher"), "")
	}

	if password != "" {
		err = cipher.SetPassword(password)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	input, err := os.Open(src)

	if err != nil {
		input.Close()
		return errorResponse(err, "")
	}

	outputPath := src + "." + cipher.GetInfo().Extension
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		input.Close()
		output.Close()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()

		n := status.Notify(syslog.LOG_INFO, "encrypting %s", relativePath(src))
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

		status.Log(syslog.LOG_NOTICE, "completed encryption of %s", relativePath(src))
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileDecrypt(r *http.Request) (res jsonObject) {
	var outputPath string

	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src:s", "password:s", "verify:b", "key:s", "sig_key:s", "cipher:s"})

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
	cipherName := req["cipher"].(string)

	cipher, err := conf.GetCipher(cipherName)

	if err != nil {
		return errorResponse(err, "")
	}

	if !cipher.GetInfo().Dec {
		return errorResponse(errors.New("decryption requested but not supported by cipher"), "")
	}

	if cipher.GetInfo().KeyFormat != "password" && keyPath == "" {
		return errorResponse(errors.New("decryption key not specified"), "")
	}

	suffix := "." + cipher.GetInfo().Extension

	if strings.HasSuffix(src, suffix) {
		outputPath = strings.TrimSuffix(src, suffix)
	} else {
		outputPath = src + ".decrypted"
	}

	if cipher.GetInfo().KeyFormat != "password" {
		keyPath = filepath.Join(conf.MountPoint, keyPath)
		key, _, err := getKey(keyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	err = cipher.SetPassword(password)

	if err != nil {
		return errorResponse(err, "")
	}

	if verify && cipher.GetInfo().Sig {
		sigKeyPath = filepath.Join(conf.MountPoint, sigKeyPath)
		key, _, err := getKey(sigKeyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	} else if verify && !cipher.GetInfo().Sig {
		return errorResponse(errors.New("signature verification requested but not supported by cipher"), "")
	}

	input, err := os.Open(src)

	if err != nil {
		input.Close()
		return errorResponse(err, "")
	}

	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		input.Close()
		output.Close()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()

		n := status.Notify(syslog.LOG_INFO, "decrypting %s", relativePath(src))
		defer status.Remove(n)

		err = cipher.Decrypt(input, output, verify)

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "completed decryption of %s", relativePath(src))
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileSign(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src:s", "cipher:s", "password:s", "key:s"})

	if err != nil {
		return errorResponse(err, "")
	}

	src, err := absolutePath(req["src"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	password := req["password"].(string)
	keyPath := req["key"].(string)
	cipherName := req["cipher"].(string)

	cipher, err := conf.GetCipher(cipherName)

	if err != nil {
		return errorResponse(err, "")
	}

	if !cipher.GetInfo().Sig {
		return errorResponse(errors.New("signing requested but not supported by cipher"), "")
	}

	keyPath = filepath.Join(conf.MountPoint, keyPath)
	key, _, err := getKey(keyPath)

	if err != nil {
		return errorResponse(err, "")
	}

	err = cipher.SetKey(key)

	if err != nil {
		return errorResponse(err, "")
	}

	if password != "" {
		err = cipher.SetPassword(password)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	input, err := os.Open(src)

	if err != nil {
		input.Close()
		return errorResponse(err, "")
	}

	outputPath := src + "." + cipher.GetInfo().Extension + "-signature"
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		input.Close()
		output.Close()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()

		n := status.Notify(syslog.LOG_INFO, "signing %s", relativePath(src))
		defer status.Remove(n)

		err = cipher.Sign(input, output)

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "completed signing of %s", relativePath(src))
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}

func fileVerify(r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"src:s", "sig:s", "key:s", "cipher:s"})

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
	cipherName := req["cipher"].(string)

	cipher, err := conf.GetCipher(cipherName)

	if err != nil {
		return errorResponse(err, "")
	}

	if !cipher.GetInfo().Sig {
		return errorResponse(errors.New("signature verification requested but not supported by cipher"), "")
	}

	if cipher.GetInfo().KeyFormat != "password" {
		sigKeyPath = filepath.Join(conf.MountPoint, sigKeyPath)
		key, _, err := getKey(sigKeyPath)

		if err != nil {
			return errorResponse(err, "")
		}

		err = cipher.SetKey(key)

		if err != nil {
			return errorResponse(err, "")
		}
	}

	input, err := os.Open(src)

	if err != nil {
		return errorResponse(err, "")
	}

	sig, err := os.Open(sigPath)

	if err != nil {
		input.Close()
		sig.Close()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer sig.Close()

		n := status.Notify(syslog.LOG_INFO, "verifying %s", relativePath(src))
		defer status.Remove(n)

		err = cipher.Verify(input, sig)

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "successful verification of %s", relativePath(src))
	}()

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	return
}
