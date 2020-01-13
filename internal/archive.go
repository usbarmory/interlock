// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"archive/zip"
	"errors"
	"io"
	"log/syslog"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func zipWriter(src []string, dst io.Writer) (written int64, err error) {
	writer := zip.NewWriter(dst)
	defer writer.Close()

	walkFn := func(osPath string, info os.FileInfo, e error) (err error) {
		var w int64
		var f io.Writer

		if info == nil {
			return
		}

		if info.IsDir() {
			// the downside of this optimization is that
			// directories mtime is not preserved
			return
		}

		n := status.Notify(syslog.LOG_NOTICE, "adding %s to archive", path.Base(osPath))
		defer status.Remove(n)

		fileHeader, err := zip.FileInfoHeader(info)

		if err != nil {
			return
		}

		relPath := strings.TrimPrefix(relativePath(osPath), "/")
		fileHeader.Name = relPath

		f, err = writer.CreateHeader(fileHeader)

		if err != nil {
			return
		}

		input, err := os.Open(osPath)

		if err != nil {
			return
		}
		defer input.Close()

		w, err = io.Copy(f, input)
		written += w

		if err != nil {
			return
		}

		return
	}

	for _, s := range src {
		n := status.Notify(syslog.LOG_NOTICE, "compressing %s", path.Base(s))
		defer status.Remove(n)

		err = filepath.Walk(s, walkFn)

		if err != nil {
			break
		}
	}

	return
}

func zipPath(src []string, dst string) (err error) {
	output, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)

	if err != nil {
		return
	}

	go func() {
		defer output.Close()

		_, err = zipWriter(src, output)

		if err != nil {
			status.Error(err)
			return
		}

		status.Log(syslog.LOG_NOTICE, "completed compression to %s", relativePath(dst))
	}()

	return
}

func unzipFile(src string, dst string) (err error) {
	reader, err := zip.OpenReader(src)

	if err != nil {
		return
	}

	err = os.MkdirAll(dst, 0700)

	if err != nil {
		defer reader.Close()
		return
	}

	go func() {
		defer reader.Close()

		n := status.Notify(syslog.LOG_NOTICE, "extracting %s", relativePath(src))
		defer status.Remove(n)

		for _, f := range reader.Reader.File {
			if strings.Contains(f.Name, traversalPattern) {
				status.Error(errors.New("path traversal detected"))
				return
			}

			dstPath := filepath.Join(dst, f.Name)

			if f.FileInfo().IsDir() {
				err = os.MkdirAll(dstPath, f.Mode())

				if err != nil {
					status.Error(err)
					return
				}
			} else {
				err = os.MkdirAll(path.Dir(dstPath), 0700)

				if err != nil {
					status.Error(err)
					return
				}

				n := status.Notify(syslog.LOG_NOTICE, "extracting %s from archive", f.Name)
				defer status.Remove(n)

				output, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_TRUNC, f.Mode())

				if err != nil {
					status.Error(err)
					return
				}
				defer output.Close()

				input, err := f.Open()

				if err != nil {
					status.Error(err)
					return
				}
				defer input.Close()

				_, err = io.Copy(output, input)

				if err != nil {
					status.Error(err)
					return
				}

				output.Close()
				//lint:ignore SA1019 incorrectly matches zip:*FileHeader.ModTime()
				os.Chtimes(dstPath, f.ModTime(), f.ModTime())
			}
		}

		status.Log(syslog.LOG_NOTICE, "completed extraction of %s", relativePath(src))
	}()

	return
}
