// SPDX-License-Identifier: Apache-2.0
package firewall

import (
	"encoding/binary"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/duongddinh/ebpfw/internal/config"
	"golang.org/x/sys/unix"
)

func (m *Manager) expire(c config.Config) error {
	var ts unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); e != nil {
		return e
	}
	return m.expireAt(c, uint64(ts.Nano()))
}

func (m *Manager) expireAt(c config.Config, now uint64) error {
	flows, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "flows"), nil)
	if e != nil {
		return e
	}
	defer flows.Close()
	it := flows.Iterate()
	var key [40]byte
	var value [48]byte
	visited := 0
	for it.Next(&key, &value) {
		visited++
		if visited > 65536 {
			break
		}
		if e = flows.LookupWithFlags(key, &value, ebpf.LookupLock); e != nil {
			continue
		}
		last := binary.NativeEndian.Uint64(value[8:])
		state := binary.NativeEndian.Uint32(value[4:])
		age := 30 * time.Second
		if key[37] == 6 {
			age = 60 * time.Second
			if state == 3 {
				age = 120 * time.Hour
			}
			if value[43] != 0 {
				age = 30 * time.Second
			}
			if state == 4 {
				age = 5 * time.Second
			}
		} else if state == 3 {
			age = 180 * time.Second
		}
		if now >= last && now-last > uint64(age) {
			flows.Delete(key)
		}
	}
	if e = it.Err(); e != nil {
		return e
	}
	plan, e := Compile(c, binary.NativeEndian)
	if e != nil {
		return e
	}
	rates, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "rates"), nil)
	if e != nil {
		return e
	}
	defer rates.Close()
	ri := rates.Iterate()
	var rk [28]byte
	var rv [24]byte
	visited = 0
	for ri.Next(&rk, &rv) {
		visited++
		if visited > 16384 {
			break
		}
		generation := binary.NativeEndian.Uint32(rk[24:])
		index := binary.NativeEndian.Uint32(rk[16:])
		if generation != plan.Generation || index >= uint32(len(c.Rules)) {
			rates.Delete(rk)
			continue
		}
		r := c.Rules[index]
		rate, burst := r.Rate, r.Burst
		if rate == 0 {
			rate = 12
		}
		if burst == 0 {
			burst = 6
		}
		full := uint64(burst) * (uint64(time.Minute) / rate)
		last := binary.NativeEndian.Uint64(rv[8:])
		if now >= last && now-last > full {
			rates.Delete(rk)
		}
	}
	return ri.Err()
}
