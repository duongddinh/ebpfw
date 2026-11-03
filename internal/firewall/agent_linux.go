// SPDX-License-Identifier: Apache-2.0
package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/duongddinh/ebpfw/internal/config"
)

func logPath() string { n, _ := Namespace(); return fmt.Sprintf("/run/ebpfw/ns-%d.events.jsonl", n) }
func (m *Manager) Logs(out io.Writer) error {
	f, e := os.Open(logPath())
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = io.Copy(out, io.LimitReader(f, 4<<20))
	return e
}

type Event struct {
	Time            uint64     `json:"time_monotonic_ns"`
	Rule            uint32     `json:"rule"`
	Generation      uint32     `json:"generation"`
	Length          uint32     `json:"length"`
	Captured        uint32     `json:"-"`
	Family          uint8      `json:"family"`
	Protocol        uint8      `json:"protocol"`
	Action          uint8      `json:"action"`
	Direction       uint8      `json:"direction"`
	SourcePort      uint16     `json:"source_port"`
	DestinationPort uint16     `json:"destination_port"`
	Source          [16]byte   `json:"source_bytes"`
	Destination     [16]byte   `json:"destination_bytes"`
	InInterface     [16]byte   `json:"in_interface_bytes"`
	OutInterface    [16]byte   `json:"out_interface_bytes"`
	Packet          [1280]byte `json:"-"`
}

func (m *Manager) Run(path string, out io.Writer) error {
	c, e := config.Load(path)
	if e != nil {
		return e
	}
	if !c.Enabled {
		return errors.New("saved firewall is disabled")
	}
	if e = m.Apply(c); e != nil {
		return e
	}
	n, e := Namespace()
	if e != nil {
		return e
	}
	lock, e := os.OpenFile(fmt.Sprintf("/run/ebpfw/ns-%d.agent.lock", n), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("an event agent already owns this namespace")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	events, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "events"), nil)
	if e != nil {
		return e
	}
	defer events.Close()
	reader, e := ringbuf.NewReader(events)
	if e != nil {
		return e
	}
	defer reader.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); reader.Close() }()
	if e = m.beat(); e != nil {
		return e
	}
	defer os.Remove(heartbeatPath())
	applied, _ := Compile(c, binary.NativeEndian)
	errEvents := make(chan error, 1)
	go func() { errEvents <- m.consume(reader, out) }()
	ticks := 0
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case e = <-errEvents:
			if errors.Is(e, ringbuf.ErrClosed) {
				return nil
			}
			return e
		case <-timer.C:
			if e = m.beat(); e != nil {
				fmt.Fprintln(out, "Agent heartbeat failed:", e)
			}
			ticks++
			if ticks%10 == 0 {
				if e = m.expire(applied.Config); e != nil {
					fmt.Fprintln(out, "State expiry failed:", e)
				}
			}
			next, e := config.Load(path)
			if e != nil {
				fmt.Fprintln(out, "Reload rejected; keeping the active policy:", e)
				continue
			}
			if !next.Enabled {
				return m.Apply(next)
			}
			p, e := Compile(next, binary.NativeEndian)
			if e != nil {
				continue
			}
			if p.SHA256 != applied.SHA256 {
				if e = m.Apply(next); e != nil {
					fmt.Fprintln(out, "Reload rejected; keeping the active policy:", e)
				} else {
					applied = p
					fmt.Fprintln(out, "Applied:", p.Summary())
				}
			}
		}
	}
}
func (m *Manager) consume(reader *ringbuf.Reader, out io.Writer) error {
	for {
		record, e := reader.Read()
		if e != nil {
			return e
		}
		if len(record.RawSample) != 1376 {
			fmt.Fprintln(out, "Rejected incompatible event size")
			continue
		}
		var event Event
		if e = binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &event); e != nil {
			return e
		}
		logRequested := event.Action&0x80 != 0
		noReply := event.Action&0x40 != 0
		event.Action &= 0x3f
		if event.Action == 3 && !noReply {
			if e = m.reject(event); e != nil {
				fmt.Fprintln(out, "Reject response failed (packet remains blocked):", e)
			}
		}
		if logRequested {
			if e = appendEvent(event); e != nil {
				fmt.Fprintln(out, "Packet log write failed:", e)
			}
		}
	}
}
func appendEvent(event Event) error {
	p := logPath()
	if st, e := os.Stat(p); e == nil && st.Size() >= 4<<20 {
		os.Remove(p + ".1")
		if e = os.Rename(p, p+".1"); e != nil {
			return e
		}
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(event)
}
