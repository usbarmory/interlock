package main

import (
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
	Name  string `json:"name"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"`
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

			_, err = execCommand(cmd, args, true, "")

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

	inodes := []inode{}

	for _, f := range fileInfo {
		if f.Name() == "lost+found" {
			continue
		}

		inode := inode{
			Name:  f.Name(),
			Dir:   f.IsDir(),
			Size:  f.Size(),
			Mtime: f.ModTime().Unix(),
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

	stat, err := os.Stat(osPath)

	if err != nil {
		return errorResponse(err, "")
	}

	if stat.IsDir() {
		return errorResponse(errors.New("unsupported"), "") // FIXME
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

	if stat.IsDir() {
		err = errors.New("unsupported") // FIXME
		return
	}

	input, err := os.Open(osPath)
	defer input.Close()

	if err != nil {
		return
	}

	n := status.Notify(syslog.LOG_NOTICE, "downloading %s", path.Base(osPath))
	defer status.Remove(n)

	w.Header().Set("Content-Disposition", "attachment; filename=\""+path.Base(osPath)+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")

	written, err := io.Copy(w, input)

	if err != nil {
		return
	}

	status.Log(syslog.LOG_INFO, "downloaded %v bytes to %s", written, osPath)
}

func fileEncrypt(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	// FIXME: signing not yet implemented
	err = validateRequest(req, []string{"src", "cipher", "wipe_src", "encrypt", "password", "key"})

	if err != nil {
		return errorResponse(err, "")
	}

	src, err := absolutePath(req["src"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	wipe := req["wipe_src"].(bool)
	encrypt := req["encrypt"].(bool)
	password := req["password"].(string)
	keyPath := req["key"].(string)

	cipher, ok := conf.enabledCiphers[req["cipher"].(string)]

	if !ok {
		return errorResponse(errors.New("invalid cipher"), "")
	}

	if encrypt && cipher.GetInfo().Enc {
		if cipher.GetInfo().KeyFormat != "password" {
			keyPath = filepath.Join(conf.mountPoint, keyPath)
			key, err := getKey(keyPath)

			if err != nil {
				return errorResponse(err, "")
			}

			err = cipher.SetKey(key)

			if err != nil {
				return errorResponse(err, "")
			}
		} else {
			err = cipher.SetPassword(password)

			if err != nil {
				return errorResponse(err, "")
			}
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
		output.Close()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()

		n := status.Notify(syslog.LOG_INFO, "encrypting %s", path.Base(src))
		defer status.Remove(n)

		err = cipher.Encrypt(input, output)

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

	// FIXME: signature verification not yet implemented
	err = validateRequest(req, []string{"src", "password", "key"})

	if err != nil {
		return errorResponse(err, "")
	}

	src, err := absolutePath(req["src"].(string))

	if err != nil {
		return errorResponse(err, "")
	}

	password := req["password"].(string)
	keyPath := req["key"].(string)

	if c, ok := req["cipher"]; ok {
		cipher, ok = conf.enabledCiphers[c.(string)]

		if !ok {
			return errorResponse(errors.New("invalid cipher"), "KO")
		}

		outputPath = src + ".decrypted"
	} else {
		ext := filepath.Ext(src)
		cipher = conf.FindCipherByExt(ext[1:len(ext)])
		outputPath = src[0 : len(src)-len(ext)]

		if cipher == nil {
			return errorResponse(fmt.Errorf("file extension %s does not match valid cipher", ext), "")
		}
	}

	if cipher.GetInfo().Dec {
		if cipher.GetInfo().KeyFormat != "password" {
			keyPath = filepath.Join(conf.mountPoint, keyPath)
			key, err := getKey(keyPath)

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

	}

	input, err := os.Open(src)

	if err != nil {
		input.Close()
		return errorResponse(err, "")
	}

	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		output.Close()
		return errorResponse(err, "")
	}

	go func() {
		defer input.Close()
		defer output.Close()

		n := status.Notify(syslog.LOG_INFO, "decrypting %s", path.Base(src))
		defer status.Remove(n)

		err = cipher.Decrypt(input, output)

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
