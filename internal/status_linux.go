// INTERLOCK | https://github.com/usbarmory/interlock
// Copyright (c) F-Secure Corporation
//
// Use of this source code is governed by the license
// that can be found in the LICENSE file.

// +build linux

package interlock

import (
	"syscall"
)

func fsStatus(path string) (total uint64, free uint64, err error) {
	var stat syscall.Statfs_t

	if err = syscall.Statfs(path, &stat); err != nil {
		return
	}

	total = stat.Blocks * uint64(stat.Bsize)
	free = stat.Bavail * uint64(stat.Bsize)

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
