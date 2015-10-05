// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
)

const cookieSize = 64
const cookieAge = 8 * 60 * 60

func randomString(size int) (c string, err error) {
	rb := make([]byte, size)

	_, err = rand.Read(rb)

	c = base64.URLEncoding.EncodeToString(rb)

	return
}

func authenticate(volume string, password string, dispose bool) (err error) {
	if conf.testMode {
		return
	}

	if volume == "" {
		err = errors.New("empty volume name")
	}

	if password == "" {
		err = errors.New("empty password")
	}

	if err != nil {
		return
	}

	err = luksOpen(volume, password)

	if err != nil {
		return
	}

	err = luksMount()

	if err != nil {
		return
	}

	err = os.MkdirAll(filepath.Join(conf.mountPoint, conf.KeyPath), 0700)

	if err != nil {
		return
	}

	if dispose {
		err = luksKeyOp(volume, password, "", _remove)

		if err != nil {
			return
		}
	}

	err = conf.ActivateCiphers(true)

	return
}

func refresh(w http.ResponseWriter) (res jsonObject) {
	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"volume":    session.Volume,
			"XSRFToken": session.XSRFToken},
	}

	return
}

func login(w http.ResponseWriter, r *http.Request) (res jsonObject) {
	req, err := parseRequest(r)

	if err != nil {
		return errorResponse(err, "")
	}

	err = validateRequest(req, []string{"volume:s", "password:s", "dispose:b"})

	if err != nil {
		return errorResponse(err, "")
	}

	if session.SessionID != "" {
		return errorResponse(errors.New("existing session"), "INVALID_SESSION")
	}

	err = authenticate(req["volume"].(string), req["password"].(string), req["dispose"].(bool))

	if err != nil {
		_ = luksUnmount()
		_ = luksClose()
		return errorResponse(err, "INVALID_SESSION")
	}

	sessionID, err := randomString(cookieSize)

	if err != nil {
		return errorResponse(err, "")
	}

	sessionCookie := &http.Cookie{
		Name:     "Interlock-Token",
		Value:    sessionID,
		Path:     "/api",
		MaxAge:   cookieAge,
		Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, sessionCookie)

	XSRFToken, err := randomString(cookieSize)

	if err != nil {
		_ = luksUnmount()
		_ = luksClose()
		return errorResponse(err, "")
	}

	if !conf.Debug {
		// switch logging to encrypted partition
		enableFileLog()
	}

	session.Set(req["volume"].(string), sessionID, XSRFToken)

	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"volume":    session.Volume,
			"XSRFToken": session.XSRFToken},
	}

	return
}

func logout(w http.ResponseWriter) (res jsonObject) {
	session.Clear()

	if !conf.Debug {
		// restore logging to syslog before unmounting encrypted partition
		enableSyslog()
	}

	sessionCookie := &http.Cookie{
		Name:     "Interlock-Token",
		Value:    "delete",
		Path:     "/api",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, sessionCookie)

	res = jsonObject{
		"status":   "OK",
		"response": nil,
	}

	conf.ActivateCiphers(false)

	err := luksUnmount()

	if err != nil {
		return errorResponse(err, "")
	}

	err = luksClose()

	if err != nil {
		return errorResponse(err, "")
	}

	return
}

func poweroff(w http.ResponseWriter) (res jsonObject) {
	res = logout(w)

	go func() {
		_, _ = execCommand("/sbin/poweroff", []string{}, true, "")
	}()

	return
}
