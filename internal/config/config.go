// SPDX-License-Identifier: Apache-2.0
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

const MaxRules = 16384

type Rule struct {
	Action       string `json:"action"`
	Protocol     string `json:"protocol"`
	Source       string `json:"source,omitempty"`
	Port         string `json:"port,omitempty"`
	Destination  string `json:"destination,omitempty"`
	SourcePort   string `json:"source_port,omitempty"`
	Direction    string `json:"direction,omitempty"`
	InInterface  string `json:"in_interface,omitempty"`
	OutInterface string `json:"out_interface,omitempty"`
	Log          bool   `json:"log,omitempty"`
	Comment      string `json:"comment,omitempty"`
	Application  string `json:"application,omitempty"`
	Rate         uint64 `json:"rate_per_minute,omitempty"`
	Burst        uint32 `json:"burst,omitempty"`
}
type Config struct {
	Version      int                `json:"version"`
	Default      string             `json:"default"`
	DefaultOut   string             `json:"default_out,omitempty"`
	DefaultRoute string             `json:"default_route,omitempty"`
	Enabled      bool               `json:"enabled"`
	Logging      bool               `json:"logging,omitempty"`
	Rules        []Rule             `json:"rules"`
	Applications map[string]Profile `json:"applications,omitempty"`
}

func New() Config {
	return Config{Version: 2, Default: "deny", DefaultOut: "allow", DefaultRoute: "deny", Rules: []Rule{}}
}
func (c Config) Normalized() Config {
	c.Rules = append([]Rule(nil), c.Rules...)
	if c.Version == 1 {
		c.Version = 2
	}
	if c.DefaultOut == "" {
		c.DefaultOut = "allow"
	}
	if c.DefaultRoute == "" {
		c.DefaultRoute = "deny"
	}
	for i := range c.Rules {
		if c.Rules[i].Direction == "" {
			if c.Rules[i].Action == "block" {
				c.Rules[i].Direction = "any"
			} else {
				c.Rules[i].Direction = "in"
			}
		}
	}
	return c
}
func ValidInterface(s string) bool {
	if len(s) == 0 || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}
func Prefix(s string) (netip.Prefix, error) {
	if s == "" || s == "any" {
		return netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, e := netip.ParseAddr(s)
		if e != nil {
			return p, fmt.Errorf("invalid IP/CIDR %q", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return p, errors.New("mapped or scoped IPv6 addresses are unsupported; use an interface selector")
	}
	return p.Masked(), nil
}
func Ports(s string) (uint16, uint16, error) { return PortsFor("tcp", s) }
func PortsFor(protocol, s string) (uint16, uint16, error) {
	if s == "" || s == "any" {
		return 0, 0, nil
	}
	if !strings.Contains(s, ":") {
		if _, e := strconv.ParseUint(s, 10, 16); e != nil {
			n, e := net.LookupPort(protocol, s)
			if e != nil {
				return 0, 0, fmt.Errorf("unknown %s service %q", protocol, s)
			}
			s = strconv.Itoa(n)
		}
	}
	p := strings.Split(s, ":")
	if len(p) > 2 {
		return 0, 0, errors.New("port must be NAME, N, or START:END")
	}
	lo, e := strconv.ParseUint(p[0], 10, 16)
	if e != nil || lo == 0 {
		return 0, 0, errors.New("port must be 1..65535")
	}
	hi := lo
	if len(p) == 2 {
		hi, e = strconv.ParseUint(p[1], 10, 16)
	}
	if e != nil || hi < lo {
		return 0, 0, errors.New("invalid port range")
	}
	return uint16(lo), uint16(hi), nil
}
func (c Config) Validate() error {
	if c.Version != 1 && c.Version != 2 {
		return errors.New("unsupported configuration version")
	}
	c = c.Normalized()
	for _, v := range []string{c.Default, c.DefaultOut, c.DefaultRoute} {
		if v != "allow" && v != "deny" && v != "reject" {
			return errors.New("defaults must be allow, deny, or reject")
		}
	}
	if len(c.Rules) > MaxRules {
		return fmt.Errorf("at most %d rules supported", MaxRules)
	}
	if len(c.Applications) > 1024 {
		return errors.New("at most 1024 application profiles supported")
	}
	for name, p := range c.Applications {
		if e := ValidateProfile(name, p); e != nil {
			return e
		}
	}
	for i, r := range c.Rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}
func (r Rule) Validate() error {
	if r.Direction == "" {
		if r.Action == "block" {
			r.Direction = "any"
		} else {
			r.Direction = "in"
		}
	}
	switch r.Action {
	case "allow", "deny", "reject", "limit", "block":
	default:
		return errors.New("unknown action")
	}
	switch r.Direction {
	case "in", "out", "route", "any":
	default:
		return errors.New("direction must be in, out, route, or any")
	}
	switch r.Protocol {
	case "any", "tcp", "udp", "icmp", "icmpv6", "sctp", "esp", "ah", "gre", "igmp":
	default:
		return errors.New("unknown protocol")
	}
	src, e := Prefix(r.Source)
	if e != nil {
		return e
	}
	dst, e := Prefix(r.Destination)
	if e != nil {
		return e
	}
	if src.IsValid() && dst.IsValid() && src.Addr().Is4() != dst.Addr().Is4() {
		return errors.New("source/destination address families disagree")
	}
	for _, p := range []netip.Prefix{src, dst} {
		if p.IsValid() && ((r.Protocol == "icmp" && p.Addr().Is6()) || (r.Protocol == "icmpv6" && p.Addr().Is4())) {
			return errors.New("protocol and address family disagree")
		}
	}
	for _, p := range []string{r.SourcePort, r.Port} {
		lo, _, e := PortsFor(r.Protocol, p)
		if e != nil {
			return e
		}
		if lo != 0 && r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "sctp" {
			return errors.New("ports require tcp, udp, or sctp")
		}
	}
	for _, v := range []string{r.InInterface, r.OutInterface} {
		if v != "" && !ValidInterface(v) {
			return errors.New("invalid interface name")
		}
	}
	if r.Direction == "in" && r.OutInterface != "" || r.Direction == "out" && r.InInterface != "" {
		return errors.New("interface conflicts with direction")
	}
	if len(r.Application) > 64 || strings.ContainsAny(r.Application, "\x00\r\n") {
		return errors.New("invalid application label")
	}
	if !utf8.ValidString(r.Comment) || len(r.Comment) > 128 || strings.ContainsAny(r.Comment, "\x00\r\n") {
		return errors.New("comment must be a single line of at most 128 bytes")
	}
	if r.Action == "limit" {
		if r.Protocol != "tcp" {
			return errors.New("connection rate limits require TCP")
		}
		if r.Rate > 1000000 || r.Burst > 1000000 {
			return errors.New("rate/burst too large")
		}
	} else if r.Rate != 0 || r.Burst != 0 {
		return errors.New("rate/burst require limit")
	}
	if r.Action == "block" {
		if !src.IsValid() || r.Direction != "any" || r.Protocol != "any" || dst.IsValid() || r.Port != "" || r.SourcePort != "" || r.InInterface != "" || r.OutInterface != "" || r.Log {
			return errors.New("block requires only from IP/CIDR (all directions, no logging); use deny for stateful matching")
		}
	}
	return nil
}
func Load(path string) (Config, error) {
	f, e := os.Open(path)
	if e != nil {
		return Config{}, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if e != nil {
		return Config{}, e
	}
	if len(b) > 8<<20 {
		return Config{}, errors.New("configuration exceeds 8 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var c Config
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	if e = c.Validate(); e != nil {
		return c, e
	}
	return c.Normalized(), nil
}
func Store(path string, c Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	c = c.Normalized()
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	f, e := os.CreateTemp(filepath.Dir(path), ".rules-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// Update holds one lock across validation, kernel update and durable persistence.
// apply must be transactional; if persistence fails it is called with the old
// configuration to restore enforcement before returning the error.
func Update(path string, change func(*Config) error, apply func(Config) error) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	old, e := Load(path)
	if os.IsNotExist(e) {
		old = New()
	} else if e != nil {
		return e
	}
	b, _ := json.Marshal(old)
	var next Config
	json.Unmarshal(b, &next)
	if e = change(&next); e != nil {
		return e
	}
	if e = next.Validate(); e != nil {
		return e
	}
	if apply != nil {
		if e = apply(next); e != nil {
			return e
		}
	}
	if e = Store(path, next); e != nil {
		if apply != nil {
			if rollback := apply(old); rollback != nil {
				return fmt.Errorf("save failed: %v; kernel rollback also failed: %w", e, rollback)
			}
		}
		return e
	}
	return nil
}
