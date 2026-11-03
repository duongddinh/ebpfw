// SPDX-License-Identifier: Apache-2.0
package firewall

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

type heartbeat struct {
	PID  int    `json:"pid"`
	Root string `json:"root"`
	Time uint64 `json:"time_ns"`
}

func heartbeatPath() string {
	n, _ := Namespace()
	return fmt.Sprintf("/run/ebpfw/ns-%d.agent.json", n)
}
func (m *Manager) beat() error {
	var now unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); e != nil {
		return e
	}
	b, _ := json.Marshal(heartbeat{os.Getpid(), m.Root, uint64(now.Nano())})
	return os.WriteFile(heartbeatPath(), b, 0600)
}
func (m *Manager) agent() (bool, int) {
	var h heartbeat
	b, e := os.ReadFile(heartbeatPath())
	if e != nil || json.Unmarshal(b, &h) != nil || h.Root != m.Root || h.PID < 1 {
		return false, 0
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &now) != nil {
		return false, 0
	}
	alive := uint64(now.Nano()) >= h.Time && uint64(now.Nano())-h.Time < 3e9 && unix.Kill(h.PID, 0) == nil
	return alive, h.PID
}
