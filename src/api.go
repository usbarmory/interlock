// INTERLOCK | https://github.com/inversepath/interlock
// Copyright (c) 2015-2016 Inverse Path S.r.l.
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

var URIPattern = regexp.MustCompile("/api/([A-Za-z0-9]+)/([a-z0-9_]+)")

func registerHandlers(staticPath string) (err error) {
	_, err = os.Stat(conf.StaticPath)

	if err != nil {
		return fmt.Errorf("invalid path for static files: %v", err)
	}

	http.Handle("/", http.StripPrefix("/", http.FileServer(http.Dir(staticPath))))
	http.HandleFunc("/api/", apiHandler)

	return
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	if conf.Debug {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.RequestURI)
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.RequestURI {
	case "/api/auth/login":
		// On a successful login the "INTERLOCK-Token" is returned as cookie via the
		// "Set-Cookie" header in HTTP response.
		//
		// The XSRF protection token "X-SRFToken" is returned in the response payload.
		// This token must be included by the client as HTTP header in every request to
		// the backend.
		sendResponse(w, login(w, r))
	case "/api/auth/refresh":
		if validSessionID, _, _ := session.Validate(r); validSessionID {
			// The session is validated using a single session cookie, we re-send the
			// XSRF token if authenticated user lands again on login page (e.g. different
			// tab).
			sendResponse(w, refresh(w))
		} else {
			sendResponse(w, jsonObject{"status": "INVALID_SESSION", "response": nil})
		}
	default:
		validSessionID, validXSRFToken, err := session.Validate(r)

		if !(validSessionID && validXSRFToken) {
			u, _ := url.Parse(r.RequestURI)

			switch u.Path {
			case "/api/file/upload":
				http.Error(w, err.Error(), 401)
			case "/api/file/download":
				// download is an exception as it is already
				// protected from XSRF with its own unique
				// handshake
				if validSessionID {
					p, _ := url.ParseQuery(u.RawQuery)
					fileDownloadByID(w, p["id"][0])
					break
				}
				fallthrough
			default:
				sendResponse(w, jsonObject{"status": "INVALID_SESSION", "response": nil})
			}
		} else if validSessionID && validXSRFToken {
			handleRequest(w, r)
		} else {
			sendResponse(w, jsonObject{"status": "INVALID_SESSION", "response": nil})
		}
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	var res jsonObject

	switch r.RequestURI {
	case "/api/auth/logout":
		res = logout(w)
	case "/api/auth/poweroff":
		res = poweroff(w)
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
	case "/api/file/extract":
		res = fileExtract(w, r)
	case "/api/file/compress":
		res = fileCompress(w, r)
	case "/api/file/encrypt":
		res = fileEncrypt(w, r)
	case "/api/file/decrypt":
		res = fileDecrypt(w, r)
	case "/api/file/sign":
		res = fileSign(w, r)
	case "/api/file/verify":
		res = fileVerify(w, r)
	case "/api/crypto/ciphers":
		res = ciphers(w)
	case "/api/crypto/keys":
		res = keys(w, r)
	case "/api/crypto/gen_key":
		res = genKey(w, r)
	case "/api/crypto/upload_key":
		res = uploadKey(w, r)
	case "/api/crypto/key_info":
		res = keyInfo(w, r)
	case "/api/status/version":
		res = versionStatus(w)
	case "/api/status/running":
		res = runningStatus(w)
	default:
		m := URIPattern.FindStringSubmatch(r.RequestURI)

		if len(m) == 3 {
			cipher, err := conf.GetAvailableCipher(m[1])

			if err != nil {
				res = notFound(w)
			} else {
				res = cipher.HandleRequest(w, r)
			}
		} else {
			res = notFound(w)
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
	status.Error(err)

	if statusCode == "" {
		statusCode = "KO"
	}

	res = jsonObject{
		"status":   statusCode,
		"response": []string{err.Error()},
	}

	return
}
