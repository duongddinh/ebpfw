// SPDX-License-Identifier: Apache-2.0
package firewall

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/duongddinh/ebpfw/internal/config"
	"golang.org/x/sys/unix"
)

const ownerMagic uint64 = 0x4542504657000002

var mapNames = []string{"active", "flows", "rates", "stats", "events", "work", "cursors", "log_clock", "reply_clock", "early4", "early6", "early_enabled", "reject_wait"}
var hookNames = []string{"ipv4_in", "ipv4_out", "ipv4_route", "ipv6_in", "ipv6_out", "ipv6_route"}

type Manager struct{ Root, Object string }

func Namespace() (uint64, error) {
	var st syscall.Stat_t
	e := syscall.Stat("/proc/self/ns/net", &st)
	return st.Ino, e
}
func DefaultRoot() string { n, _ := Namespace(); return fmt.Sprintf("/sys/fs/bpf/ebpfw/ns-%d", n) }
func NewManager(root, object string) *Manager {
	if root == "" {
		root = DefaultRoot()
	}
	if object == "" {
		object = "/usr/local/lib/ebpfw/stateful.o"
	}
	return &Manager{root, object}
}
func (m *Manager) checkRoot() error {
	if !filepath.IsAbs(m.Root) {
		return errors.New("pin root must be an absolute bpffs path")
	}
	var fs unix.Statfs_t
	parent := m.Root
	for {
		if e := unix.Statfs(parent, &fs); e == nil {
			break
		} else if !os.IsNotExist(e) {
			return e
		}
		next := filepath.Dir(parent)
		if next == parent {
			return errors.New("no bpffs mount")
		}
		parent = next
	}
	if uint64(fs.Type) != unix.BPF_FS_MAGIC {
		return fmt.Errorf("%s must be on bpffs; mount bpffs at /sys/fs/bpf first", m.Root)
	}
	if st, e := os.Lstat(m.Root); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("pin root must not be a symlink")
	}
	return nil
}
func (m *Manager) lock() (func(), error) {
	if e := os.MkdirAll("/run/ebpfw", 0700); e != nil {
		return nil, e
	}
	id, e := Namespace()
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(fmt.Sprintf("/run/ebpfw/ns-%d.lock", id), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		f.Close()
		return nil, e
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func (m *Manager) owner(checkObject bool) error {
	p, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "owner"), nil)
	if e != nil {
		return e
	}
	defer p.Close()
	b := make([]byte, 48)
	if e = p.Lookup(uint32(0), &b); e != nil {
		return e
	}
	ns, e := Namespace()
	if e != nil {
		return e
	}
	if binary.NativeEndian.Uint64(b) != ownerMagic || binary.NativeEndian.Uint64(b[8:]) != ns {
		return errors.New("refusing foreign or incompatible pinned state")
	}
	if checkObject {
		data, e := os.ReadFile(m.Object)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(data)
		if string(sum[:]) != string(b[16:]) {
			return errors.New("the pinned program differs from this object; use a reviewed disable/enable upgrade")
		}
	}
	return nil
}
func (m *Manager) createOwner() error {
	b := make([]byte, 48)
	binary.NativeEndian.PutUint64(b, ownerMagic)
	ns, e := Namespace()
	if e != nil {
		return e
	}
	binary.NativeEndian.PutUint64(b[8:], ns)
	data, e := os.ReadFile(m.Object)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(data)
	copy(b[16:], sum[:])
	p, e := ebpf.NewMap(&ebpf.MapSpec{Name: "ebpfw_owner", Type: ebpf.Array, KeySize: 4, ValueSize: 48, MaxEntries: 1})
	if e != nil {
		return e
	}
	defer p.Close()
	if e = p.Update(uint32(0), b, ebpf.UpdateAny); e != nil {
		return e
	}
	p.Freeze()
	return p.Pin(filepath.Join(m.Root, "owner"))
}
func (m *Manager) policyMap() (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(m.Root, "active"), nil)
}
func (m *Manager) install(plan Plan) error {
	outer, e := m.policyMap()
	if e != nil {
		return e
	}
	defer outer.Close()
	inner, e := ebpf.NewMap(&ebpf.MapSpec{Name: "ebpfw_policy", Type: ebpf.Array, KeySize: 4, ValueSize: EntrySize, MaxEntries: config.MaxRules + 1})
	if e != nil {
		return e
	}
	defer inner.Close()
	for i, b := range plan.Entries {
		if e = inner.Update(uint32(i), b, ebpf.UpdateAny); e != nil {
			return e
		}
	}
	if e = inner.Freeze(); e != nil {
		return e
	}
	return outer.Update(uint32(0), inner, ebpf.UpdateAny)
}
func (m *Manager) Apply(c config.Config) error {
	if e := m.checkRoot(); e != nil {
		return e
	}
	release, e := m.lock()
	if e != nil {
		return e
	}
	defer release()
	if !c.Enabled {
		return m.disable()
	}
	plan, e := Compile(c, binary.NativeEndian)
	if e != nil {
		return e
	}
	if e = rlimit.RemoveMemlock(); e != nil {
		return e
	}
	created := false
	if _, e = os.Stat(m.Root); os.IsNotExist(e) {
		if e = os.MkdirAll(m.Root, 0700); e != nil {
			return e
		}
		created = true
	} else if e != nil {
		return e
	}
	success := false
	defer func() {
		if created && !success {
			m.removeOwnedFiles()
		}
	}()
	var prog *ebpf.Program
	if !created {
		if e = m.owner(true); e != nil {
			return e
		}
		prog, e = ebpf.LoadPinnedProgram(filepath.Join(m.Root, "program"), nil)
		if e != nil {
			return e
		}
	} else {
		spec, e := ebpf.LoadCollectionSpec(m.Object)
		if e != nil {
			return e
		}
		col, e := ebpf.NewCollection(spec)
		if e != nil {
			return fmt.Errorf("load eBPF-only datapath: %+v", e)
		}
		defer col.Close()
		for _, name := range mapNames {
			p := col.Maps[name]
			if p == nil {
				return fmt.Errorf("missing map %s", name)
			}
			if e = p.Pin(filepath.Join(m.Root, name)); e != nil {
				return e
			}
		}
		prog = col.Programs["ebpfw_full"]
		if prog == nil {
			return errors.New("missing eBPF program")
		}
		if e = col.Programs["ebpfw_early"].Pin(filepath.Join(m.Root, "early_program")); e != nil {
			return e
		}
		if e = prog.Pin(filepath.Join(m.Root, "program")); e != nil {
			return e
		}
		if e = m.createOwner(); e != nil {
			return e
		}
	}
	defer prog.Close()
	for i, name := range hookNames {
		path := filepath.Join(m.Root, name)
		if _, e = os.Stat(path); e == nil {
			continue
		} else if !os.IsNotExist(e) {
			return e
		}
		family := link.NetfilterProtoIPv4
		if i >= 3 {
			family = link.NetfilterProtoIPv6
		}
		hook := []link.NetfilterInetHook{link.NetfilterInetLocalIn, link.NetfilterInetLocalOut, link.NetfilterInetForward}[i%3]
		// BPF_F_NETFILTER_IP_DEFRAG = 1. The library's named flag is currently 0,
		// so use the kernel ABI value explicitly and test real fragment reassembly.
		l, e := link.AttachNetfilter(link.NetfilterOptions{Program: prog, ProtocolFamily: family, Hook: hook, Priority: 10, NetfilterFlags: 1})
		if e != nil {
			return fmt.Errorf("attach %s (Linux 6.6+, BTF, Netfilter BPF and IP defrag required): %w", name, e)
		}
		if e = l.Pin(path); e != nil {
			l.Close()
			return e
		}
		l.Close()
	}
	if e = m.pauseEarly(); e != nil {
		return e
	}
	if e = m.install(plan); e != nil {
		return e
	}
	if e = m.refreshEarly(plan.Config); e != nil {
		fmt.Fprintln(os.Stderr, "Policy active; early acceleration stays paused:", e)
	}
	success = true
	return nil
}
func (m *Manager) removeOwnedFiles() error {
	entries, e := os.ReadDir(m.Root)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	// Links are unpinned first. The kernel retains maps until the last link ends.
	for _, name := range hookNames {
		if e = os.Remove(filepath.Join(m.Root, name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	for _, d := range entries {
		if strings.HasPrefix(d.Name(), "xdp_") {
			if e = os.Remove(filepath.Join(m.Root, d.Name())); e != nil {
				return e
			}
		}
	}
	for _, d := range entries {
		if d.IsDir() {
			return errors.New("refusing unexpected nested pin state")
		}
		if e = os.Remove(filepath.Join(m.Root, d.Name())); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return os.Remove(m.Root)
}
func (m *Manager) disable() error {
	if _, e := os.Stat(m.Root); os.IsNotExist(e) {
		return nil
	}
	if e := m.owner(false); e != nil {
		return e
	}
	return m.removeOwnedFiles()
}

type Status struct {
	AgentAlive       bool              `json:"agent_alive"`
	AgentPID         int               `json:"agent_pid,omitempty"`
	EarlyActive      bool              `json:"early_active"`
	EarlyInterfaces  []string          `json:"early_interfaces,omitempty"`
	Enabled          bool              `json:"enabled"`
	Hooks            int               `json:"hooks"`
	Generation       uint32            `json:"generation"`
	Rules            uint32            `json:"rules"`
	Counters         map[string]uint64 `json:"counters"`
	RuleCounters     []uint64          `json:"rule_counters"`
	ConntrackEntries int               `json:"conntrack_entries"`
	PinRoot          string            `json:"pin_root"`
}

func (m *Manager) Status() (Status, error) {
	s := Status{PinRoot: m.Root, Counters: map[string]uint64{}}
	s.AgentAlive, s.AgentPID = m.agent()
	if _, e := os.Stat(m.Root); os.IsNotExist(e) {
		return s, nil
	}
	if e := m.owner(false); e != nil {
		return s, e
	}
	for _, name := range hookNames {
		l, e := link.LoadPinnedLink(filepath.Join(m.Root, name), nil)
		if e == nil {
			s.Hooks++
			l.Close()
		} else if !os.IsNotExist(e) {
			return s, e
		}
	}
	entries, _ := os.ReadDir(m.Root)
	for _, d := range entries {
		if strings.HasPrefix(d.Name(), "xdp_") {
			s.EarlyInterfaces = append(s.EarlyInterfaces, strings.TrimPrefix(d.Name(), "xdp_"))
		}
	}
	early, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "early_enabled"), nil)
	if e == nil {
		var on uint32
		early.Lookup(uint32(0), &on)
		early.Close()
		s.EarlyActive = on != 0 && len(s.EarlyInterfaces) > 0
	}
	outer, e := m.policyMap()
	if e != nil {
		return s, e
	}
	defer outer.Close()
	var id ebpf.MapID
	if e = outer.Lookup(uint32(0), &id); e != nil {
		return s, e
	}
	inner, e := ebpf.NewMapFromID(id)
	if e != nil {
		return s, e
	}
	defer inner.Close()
	h := make([]byte, EntrySize)
	if e = inner.Lookup(uint32(0), &h); e != nil {
		return s, e
	}
	s.Rules = binary.NativeEndian.Uint32(h)
	s.Generation = binary.NativeEndian.Uint32(h[24:])
	s.Enabled = s.Hooks == 6 && binary.NativeEndian.Uint32(h[28:]) == 1
	counters, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "stats"), nil)
	if e != nil {
		return s, e
	}
	defer counters.Close()
	read := func(index uint32) (uint64, error) {
		var v []struct {
			Packets    uint64
			Generation uint32
			Pad        uint32
		}
		e := counters.Lookup(index, &v)
		var n uint64
		for _, x := range v {
			if x.Generation == s.Generation {
				n += x.Packets
			}
		}
		return n, e
	}
	for name, index := range map[string]int{"passed": StatPass, "dropped": StatDrop, "rejected": StatReject, "stateful": StatState, "invalid": StatInvalid, "conntrack_full": StatCTFull, "event_lost": StatEventLost, "busy_dropped": config.MaxRules + 12, "fast_open_syns": config.MaxRules + 13, "reply_rate_limited": config.MaxRules + 11, "rate_limited": StatRate} {
		n, e := read(uint32(index))
		if e != nil {
			return s, e
		}
		s.Counters[name] = n
	}
	for i := uint32(0); i < s.Rules; i++ {
		n, e := read(i)
		if e != nil {
			return s, e
		}
		s.RuleCounters = append(s.RuleCounters, n)
	}
	flows, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "flows"), nil)
	if e != nil {
		return s, e
	}
	defer flows.Close()
	it := flows.Iterate()
	var k [40]byte
	var v [48]byte
	for it.Next(&k, &v) {
		s.ConntrackEntries++
	}
	if e = it.Err(); e != nil {
		return s, e
	}
	return s, nil
}
func (m *Manager) Doctor() error {
	if e := m.checkRoot(); e != nil {
		return e
	}
	if _, e := os.Stat("/sys/kernel/btf/vmlinux"); e != nil {
		return errors.New("kernel BTF is required")
	}
	return nil
}
