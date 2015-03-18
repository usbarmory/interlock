package main

import (
	"container/ring"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"sync"
	"time"
)

const bufferSize = 20

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
	for k := range s.Notification {
		notifications = append(notifications, s.Notification[k])
	}

	return
}

func (s *statusBuffer) Test(format string, a ...interface{}) {
	fmt.Printf(format, a)
}

func interlockStatus(w http.ResponseWriter) (res jsonObject) {
	log := []statusEntry{}

	status.LogBuf.Do(func(v interface{}) {
		if v != nil {
			log = append(log, v.(statusEntry))
		}
	})

	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"log":          log,
			"notification": status.Notifications(),
		},
	}

	return
}

func deviceStatus(w http.ResponseWriter) (res jsonObject) {
	versionArgs := []string{"-a"}
	versionCommand := "/bin/uname"

	versionOutput, err := execCommand(versionCommand, versionArgs, false, "")

	if err != nil {
		return errorResponse(err, "")
	}

	uptimeCommand := "/usr/bin/uptime"

	uptimeOutput, err := execCommand(uptimeCommand, []string{}, false, "")

	if err != nil {
		return errorResponse(err, "")
	}

	res = jsonObject{
		"status": "OK",
		"response": map[string]interface{}{
			"kernel": versionOutput,
			"uptine": uptimeOutput,
		},
	}

	return
}
