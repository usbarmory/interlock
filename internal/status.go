// INTERLOCK | https://github.com/f-secure-foundry/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

package interlock

import (
	"container/ring"
	"fmt"
	"log"
	"log/syslog"
	"sort"
	"sync"
	"syscall"
	"time"
)

const bufferSize = 20

// build information, initialized at compile time (see Makefile)
var Build string
var Revision string

type statusBuffer struct {
	sync.Mutex
	LogBuf       *ring.Ring
	Notification map[int]statusEntry
	n            int
}

type statusEntry struct {
	Epoch   int64           `json:"epoch"`
	Code    syslog.Priority `json:"code"`
	Message string          `json:"msg"`
}

var status = statusBuffer{
	LogBuf:       ring.New(bufferSize),
	Notification: make(map[int]statusEntry),
	n:            0,
}

func (s *statusBuffer) Log(code syslog.Priority, format string, a ...interface{}) {
	s.Lock()
	defer s.Unlock()

	log.Printf(format, a...)

	s.LogBuf = s.LogBuf.Prev()
	s.LogBuf.Value = statusEntry{Epoch: time.Now().Unix(), Code: code, Message: fmt.Sprintf(format, a...)}
}

func (s *statusBuffer) Error(err error) {
	s.Lock()
	defer s.Unlock()

	log.Print(err.Error())

	s.LogBuf = s.LogBuf.Prev()
	s.LogBuf.Value = statusEntry{Epoch: time.Now().Unix(), Code: syslog.LOG_ERR, Message: err.Error()}
}

func (s *statusBuffer) Notify(code syslog.Priority, format string, a ...interface{}) int {
	s.Lock()
	defer s.Unlock()

	s.n++
	s.Notification[s.n] = statusEntry{Epoch: time.Now().Unix(), Code: code, Message: fmt.Sprintf(format, a...)}

	return s.n
}

func (s *statusBuffer) Remove(n int) {
	s.Lock()
	defer s.Unlock()

	delete(s.Notification, n)
}

func (s *statusBuffer) Notifications() (notifications []statusEntry) {
	var keys []int

	for k := range s.Notification {
		keys = append(keys, k)
	}

	sort.Ints(keys)

	for _, k := range keys {
		notifications = append(notifications, s.Notification[k])
	}

	return
}

func versionStatus() (res jsonObject) {
	build := Build

	if conf.HSM != "off" {
		build += " " + conf.HSM
	}

	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"revision": Revision,
			"build":    build,
			"key_path": conf.KeyPath,
		},
	}

	return
}

func runningStatus() (res jsonObject) {
	sys := &syscall.Sysinfo_t{}
	_ = syscall.Sysinfo(sys)

	log := []statusEntry{}

	status.LogBuf.Do(func(v interface{}) {
		if v != nil {
			log = append(log, v.(statusEntry))
		}
	})

	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"uptime":       sys.Uptime,
			"load_1":       sys.Loads[0],
			"load_5":       sys.Loads[1],
			"load_15":      sys.Loads[2],
			"freeram":      sys.Freeram,
			"log":          log,
			"notification": status.Notifications(),
		},
	}

	return
}
