// SPDX-License-Identifier: Apache-2.0
package policy

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const MaxRules = 64
const WireSize = 8 + MaxRules*28

type Rule struct {
	Action   string `json:"action"`
	Protocol string `json:"protocol"`
	Source   string `json:"source,omitempty"`
	Port     string `json:"port,omitempty"`
}
type Config struct {
	Version int    `json:"version"`
	Default string `json:"default"`
	Rules   []Rule `json:"rules"`
}

func New() Config { return Config{Version: 1, Default: "deny", Rules: []Rule{}} }

func action(s string) (uint32, error) {
	switch s {
	case "allow":
		return 2, nil
	case "deny":
		return 1, nil
	}
	return 0, fmt.Errorf("action must be allow or deny, got %q", s)
}
func ports(s string) (uint16, uint16, error) {
	if s == "" {
		return 0, 0, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) > 2 {
		return 0, 0, errors.New("port must be N or START:END")
	}
	lo, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || lo == 0 {
		return 0, 0, errors.New("ports must be between 1 and 65535")
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(parts[1], 10, 16)
	}
	if err != nil || hi < lo {
		return 0, 0, errors.New("invalid port range")
	}
	return uint16(lo), uint16(hi), nil
}

// Encode is the sole policy validator and defines the C map ABI. The loader
// selects byte order from the BPF ELF, rather than assuming host endianness.
func (c Config) Encode(order binary.ByteOrder) ([]byte, error) {
	if c.Version != 1 {
		return nil, errors.New("unsupported configuration version")
	}
	if len(c.Rules) > MaxRules {
		return nil, fmt.Errorf("at most %d rules are supported", MaxRules)
	}
	def, err := action(c.Default)
	if err != nil {
		return nil, err
	}
	b := make([]byte, WireSize)
	order.PutUint32(b, uint32(len(c.Rules)))
	order.PutUint32(b[4:], def)
	protocols := map[string]byte{"any": 0, "tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}
	for i, r := range c.Rules {
		dst := b[8+i*28 : 8+(i+1)*28]
		a, err := action(r.Action)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		dst[0] = byte(a)
		proto, ok := protocols[r.Protocol]
		if !ok {
			return nil, fmt.Errorf("rule %d: unknown protocol %q", i+1, r.Protocol)
		}
		dst[2] = proto
		lo, hi, err := ports(r.Port)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		if lo != 0 && proto != 6 && proto != 17 {
			return nil, fmt.Errorf("rule %d: ports require tcp or udp", i+1)
		}
		order.PutUint16(dst[4:], lo)
		order.PutUint16(dst[6:], hi)
		if r.Source != "" {
			prefix, err := netip.ParsePrefix(r.Source)
			if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
				return nil, fmt.Errorf("rule %d: source must be an IPv4 or IPv6 CIDR", i+1)
			}
			prefix = prefix.Masked()
			addr := prefix.Addr()
			if addr.Is4() {
				dst[1] = 4
				a := addr.As4()
				copy(dst[12:], a[:])
			} else {
				dst[1] = 6
				a := addr.As16()
				copy(dst[12:], a[:])
			}
			order.PutUint32(dst[8:], uint32(prefix.Bits()))
			if (proto == 1 && dst[1] != 4) || (proto == 58 && dst[1] != 6) {
				return nil, fmt.Errorf("rule %d: ICMP protocol and source family disagree", i+1)
			}
		}
	}
	return b, nil
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	var c Config
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("unexpected trailing configuration data")
	}
	_, err = c.Encode(binary.LittleEndian)
	return c, err
}

// Edit serializes writers, validates before writing, and atomically renames a
// synced temporary file so the running firewall never reads a partial policy.
func Edit(path string, change func(*Config) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	c, err := Load(path)
	if os.IsNotExist(err) {
		c = New()
	} else if err != nil {
		return err
	}
	if err = change(&c); err != nil {
		return err
	}
	if _, err = c.Encode(binary.LittleEndian); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := os.CreateTemp(dir, ".rules-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
