// SPDX-License-Identifier: Apache-2.0
package runtime

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/duongddinh/ebpfw/internal/policy"
)

// Install creates a complete immutable inner map, then publishes it with one
// map-in-map pointer update. In-flight packets retain their old map reference.
func Install(outer *ebpf.Map, template *ebpf.MapSpec, c policy.Config, order binary.ByteOrder) error {
	value, err := c.Encode(order)
	if err != nil {
		return err
	}
	spec := template.Copy()
	spec.Contents = nil
	inner, err := ebpf.NewMap(spec)
	if err != nil {
		return err
	}
	defer inner.Close()
	key := uint32(0)
	if err = inner.Update(key, value, ebpf.UpdateAny); err != nil {
		return err
	}
	if err = inner.Freeze(); err != nil {
		return err
	}
	return outer.Update(key, inner, ebpf.UpdateAny)
}

type metric struct {
	Passed      uint64 `json:"passed"`
	Denied      uint64 `json:"denied"`
	Invalid     uint64 `json:"malformed_or_unsupported"`
	Rules       int    `json:"rules"`
	Default     string `json:"default"`
	ReloadError string `json:"reload_error,omitempty"`
}
type metrics struct {
	mu            sync.Mutex
	lastError     string
	counters      *ebpf.Map
	activeRules   int
	activeDefault string
}

func (m *metrics) read() (metric, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := metric{ReloadError: m.lastError, Rules: m.activeRules, Default: m.activeDefault}
	dst := []*uint64{&result.Passed, &result.Denied, &result.Invalid}
	for i := range dst {
		var counts []uint64
		if err := m.counters.Lookup(uint32(i), &counts); err != nil {
			return result, err
		}
		for _, count := range counts {
			*dst[i] += count
		}
	}
	return result, nil
}
func socketPath(iface string) string { return filepath.Join("/run/ebpfw", iface+".sock") }

func Stats(iface string, out io.Writer) error {
	c, err := net.DialTimeout("unix", socketPath(iface), time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	_, err = io.Copy(out, io.LimitReader(c, 4096))
	return err
}

func Run(configPath string, args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	iface := flags.String("interface", "", "network interface")
	mode := flags.String("mode", "native", "native or generic XDP")
	object := flags.String("object", "/usr/local/lib/ebpfw/firewall.o", "compiled BPF ELF")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *iface == "" || len(flags.Args()) != 0 {
		return errors.New("usage: run --interface IFACE [--mode native|generic] [--object PATH]")
	}
	xdpMode := link.XDPDriverMode
	switch *mode {
	case "native":
	case "generic":
		xdpMode = link.XDPGenericMode
	default:
		return errors.New("mode must be native or generic")
	}
	nic, err := net.InterfaceByName(*iface)
	if err != nil {
		return err
	}
	if nic.Flags&net.FlagLoopback != 0 {
		return errors.New("loopback interfaces are unsupported")
	}
	c, err := policy.Load(configPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF: %w", err)
	}
	defer col.Close()
	outer := col.Maps["active_policy"]
	template := spec.Maps["active_policy"]
	if outer == nil || template == nil || template.InnerMap == nil || col.Programs["ebpfw"] == nil || col.Maps["counters"] == nil {
		return errors.New("object is missing ebpfw maps or program")
	}
	if err = Install(outer, template.InnerMap, c, spec.ByteOrder); err != nil {
		return err
	}

	// A per-interface lock protects our socket. BPF links also refuse to replace
	// another program, so existing Cilium or other XDP owners are never displaced.
	if err = os.MkdirAll("/run/ebpfw", 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join("/run/ebpfw", *iface+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another ebpfw instance owns this interface")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	path := socketPath(*iface)
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	lnk, err := link.AttachXDP(link.XDPOptions{Program: col.Programs["ebpfw"], Interface: nic.Index, Flags: xdpMode})
	if err != nil {
		return fmt.Errorf("attach XDP (existing programs are never replaced; try generic mode if the driver lacks native XDP): %w", err)
	}
	defer lnk.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	m := &metrics{counters: col.Maps["counters"], activeRules: len(c.Rules), activeDefault: c.Default}
	go func() {
		for {
			connection, e := listener.Accept()
			if e != nil {
				return
			}
			connection.SetDeadline(time.Now().Add(time.Second))
			snapshot, e := m.read()
			if e == nil {
				json.NewEncoder(connection).Encode(snapshot)
			}
			connection.Close()
		}
	}()
	applied, _ := c.Encode(spec.ByteOrder)
	log.Printf("filtering ingress on %s (%s), default %s, %d rules", *iface, *mode, c.Default, len(c.Rules))
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			next, e := policy.Load(configPath)
			var encoded []byte
			if e == nil {
				encoded, e = next.Encode(spec.ByteOrder)
			}
			if e == nil && !bytes.Equal(encoded, applied) {
				e = Install(outer, template.InnerMap, next, spec.ByteOrder)
				if e == nil {
					applied = encoded
					m.mu.Lock()
					m.activeRules, m.activeDefault = len(next.Rules), next.Default
					m.mu.Unlock()
					log.Printf("applied %d rules, default %s", len(next.Rules), next.Default)
				}
			}
			m.mu.Lock()
			previous := m.lastError
			m.lastError = ""
			if e != nil {
				m.lastError = e.Error()
				if previous != m.lastError {
					log.Printf("reload rejected; keeping last valid policy: %v", e)
				}
			}
			m.mu.Unlock()
		}
	}
}
