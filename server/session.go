package main

import (
	"errors"
	"log"
	"net/http"
	"sync"
	"time"
)

// Only a single session can be active at any time
type sessionData struct {
	sync.Mutex
	Volume    string
	SessionID string
	XSRFToken string
	createdAt *time.Time
}

var session sessionData

func (s *sessionData) Validate(r *http.Request) (validSessionID bool, validXSRFToken bool, err error) {
	validSessionID = false
	validXSRFToken = false

	sessionID, err := r.Cookie("Interlock-Token")

	if err != nil {
		return
	}

	XSRFToken := r.Header.Get("X-XSRFToken")

	session.Lock()
	defer session.Unlock()

	if session.SessionID == sessionID.Value {
		validSessionID = true
	} else {
		err = errors.New("invalid session")
	}

	if session.XSRFToken == XSRFToken {
		validXSRFToken = true
	} else {
		err = errors.New("missing XSRFToken")
	}

	return
}

func (s *sessionData) Set(volume string, sessionID string, XSRFToken string) {
	session.Lock()
	defer session.Unlock()

	if session.createdAt != nil {
		log.Printf("invalidating session opened at %v", session.createdAt)
	}

	log.Printf("new session")

	now := time.Now()
	session.Volume = volume
	session.SessionID = sessionID
	session.XSRFToken = XSRFToken
	session.createdAt = &now
}

func (s *sessionData) Clear() {
	session.Lock()
	defer session.Unlock()

	session.Volume = ""
	session.SessionID = ""
	session.XSRFToken = ""
}
