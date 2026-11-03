// SPDX-License-Identifier: Apache-2.0
package firewall

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/duongddinh/ebpfw/internal/config"
)

func (m *Manager) pauseEarly() error {
	p, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "early_enabled"), nil)
	if e != nil {
		return e
	}
	defer p.Close()
	return p.Update(uint32(0), uint32(0), ebpf.UpdateAny)
}
func (m *Manager) refreshEarly(c config.Config) error {
	maps := make(map[bool]*ebpf.Map)
	for _, v := range []struct {
		name string
		v4   bool
	}{{"early4", true}, {"early6", false}} {
		p, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, v.name), nil)
		if e != nil {
			return e
		}
		defer p.Close()
		maps[v.v4] = p
		var next [20]byte
		for {
			e = p.NextKey(nil, &next)
			if errors.Is(e, ebpf.ErrKeyNotExist) {
				break
			}
			if e != nil {
				return e
			}
			if e = p.Delete(next); e != nil {
				return e
			}
		}
	}
	for i, r := range c.Rules {
		if r.Action != "block" {
			continue
		}
		p, _ := config.Prefix(r.Source)
		key := make([]byte, 20)
		binary.NativeEndian.PutUint32(key, uint32(p.Bits()))
		v4 := p.Addr().Is4()
		if v4 {
			a := p.Addr().As4()
			copy(key[4:], a[:])
		} else {
			a := p.Addr().As16()
			copy(key[4:], a[:])
		}
		if e := maps[v4].Update(key, uint32(i), ebpf.UpdateAny); e != nil {
			return e
		}
	}
	if c.Logging {
		return nil
	} // Keep packet logs complete by using the full eBPF hook.
	enabled, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "early_enabled"), nil)
	if e != nil {
		return e
	}
	defer enabled.Close()
	return enabled.Update(uint32(0), uint32(1), ebpf.UpdateAny)
}
func (m *Manager) Accelerate(name, mode string) error {
	if !config.ValidInterface(name) {
		return errors.New("invalid interface")
	}
	if e := m.owner(true); e != nil {
		return e
	}
	release, e := m.lock()
	if e != nil {
		return e
	}
	defer release()
	s, e := m.Status()
	if e != nil {
		return e
	}
	if !s.Enabled {
		return errors.New("enable full host enforcement first")
	}
	nic, e := net.InterfaceByName(name)
	if e != nil {
		return e
	}
	if nic.Flags&net.FlagLoopback != 0 {
		return errors.New("loopback is covered by full enforcement; XDP acceleration requires an Ethernet interface")
	}
	flags := link.XDPDriverMode
	switch mode {
	case "native":
	case "generic":
		flags = link.XDPGenericMode
	default:
		return errors.New("mode must be native or generic")
	}
	path := filepath.Join(m.Root, "xdp_"+name)
	if _, e = os.Stat(path); e == nil {
		return errors.New("this interface is already accelerated")
	}
	prog, e := ebpf.LoadPinnedProgram(filepath.Join(m.Root, "early_program"), nil)
	if e != nil {
		return e
	}
	defer prog.Close()
	l, e := link.AttachXDP(link.XDPOptions{Program: prog, Interface: nic.Index, Flags: flags})
	if e != nil {
		return fmt.Errorf("attach without replacing any existing XDP owner: %w", e)
	}
	defer l.Close()
	return l.Pin(path)
}
func (m *Manager) Deaccelerate(name string) error {
	if !config.ValidInterface(name) {
		return errors.New("invalid interface")
	}
	if e := m.owner(false); e != nil {
		return e
	}
	release, e := m.lock()
	if e != nil {
		return e
	}
	defer release()
	return os.Remove(filepath.Join(m.Root, "xdp_"+name))
}
