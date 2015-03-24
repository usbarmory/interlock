// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015 Inverse Path S.r.l.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"net/url"
)

func registerHandlers() {
	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/api/", apiHandler)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	var res jsonObject

	if conf.Debug {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	}

	w.Header().Set("Content-Type", "application/json")

	if r.RequestURI == "/api/auth/login" {
		if validSessionID, _, _ := session.Validate(r); validSessionID {
			// The session is validated using a single session cookie, we re-send the
			// XSRF token if authenticated user lands again on login page (e.g. different
			// tab).
			res = refreshXSRFToken(w)
		} else {
			// On a successful login the "Interlock-Token" is returned as cookie via the
			// "Set-Cookie" header in HTTP response.
			//
			// The XSRF protection token "X-SRFToken" is returned in the response payload.
			// This token must be included by the client as HTTP header in every request to
			// the backend.
			res = login(w, r)
		}
	} else {
		if validSessionID, validXSRFToken, err := session.Validate(r); !(validSessionID && validXSRFToken) {
			u, _ := url.Parse(r.RequestURI)

			switch u.Path {
			case "/api/file/upload":
				http.Error(w, err.Error(), 401)
			case "/api/file/download":
				// download is an exception as it is already
				// protected from XSRF with its own unique
				// handshake
				if validSessionID || conf.testMode {
					p, _ := url.ParseQuery(u.RawQuery)
					fileDownloadByID(w, p["id"][0])
					break
				}
				fallthrough
			default:
				res = errorResponse(err, "INVALID_SESSION")
			}
		} else {
			switch r.RequestURI {
			case "/api/auth/logout":
				res = logout(w)
			case "/api/luks/change":
				res = passwordRequest(w, r, _change)
			case "/api/luks/add":
				res = passwordRequest(w, r, _add)
			case "/api/luks/remove":
				res = passwordRequest(w, r, _remove)
			case "/api/config/time":
				res = setTime(w, r)
			case "/api/file/list":
				res = fileList(w, r)
			case "/api/file/upload":
				fileUpload(w, r)
			case "/api/file/download":
				res = fileDownload(w, r)
			case "/api/file/delete":
				res = fileDelete(w, r)
			case "/api/file/move":
				res = fileMove(w, r)
			case "/api/file/copy":
				res = fileCopy(w, r)
			case "/api/file/mkdir":
				res = fileMkdir(w, r)
			case "/api/file/encrypt":
				res = fileEncrypt(w, r)
			case "/api/file/decrypt":
				res = fileDecrypt(w, r)
			case "/api/crypto/ciphers":
				res = ciphers(w)
			case "/api/crypto/keys":
				res = keys(w, r)
			case "/api/crypto/upload_key":
				res = uploadKey(w, r)
			case "/api/crypto/key_info":
				res = keyInfo(w, r)
			case "/api/status/version":
				res = versionStatus(w)
			case "/api/status/running":
				res = runningStatus(w)
			default:
				res = notFound(w)
			}
		}
	}

	if res != nil {
		sendResponse(w, res)
	}
}

func notFound(w http.ResponseWriter) (res jsonObject) {
	res = jsonObject{
		"status":   "INVALID",
		"response": []string{"invalid method"},
	}

	return
}

func sendResponse(w http.ResponseWriter, res jsonObject) {
	if conf.Debug {
		log.Printf(res.String())
	}

	fmt.Fprint(w, res.String())
}

func errorResponse(err error, statusCode string) (res jsonObject) {
	status.Log(syslog.LOG_ERR, err.Error())

	if statusCode == "" {
		statusCode = "KO"
	}

	res = jsonObject{
		"status":   statusCode,
		"response": []string{err.Error()},
	}

	return
}
