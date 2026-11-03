package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestMigration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.json")
	os.WriteFile(p, []byte(`{"version":1,"default":"deny","rules":[{"action":"allow","protocol":"tcp","port":"22"}]}`), 0600)
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if c.Version != 2 || c.DefaultOut != "allow" || c.DefaultRoute != "deny" || c.Rules[0].Direction != "in" {
		t.Fatalf("bad migration: %+v", c)
	}
}
func TestConcurrentUpdates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.json")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := Update(p, func(c *Config) error {
				c.Rules = append(c.Rules, Rule{Action: "allow", Protocol: "tcp", Port: "22"})
				return nil
			}, nil); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	c, e := Load(p)
	if e != nil || len(c.Rules) != 50 {
		t.Fatalf("lost update: %d %v", len(c.Rules), e)
	}
}
func TestRejectedUpdate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.json")
	Update(p, func(c *Config) error { return nil }, nil)
	before, _ := os.ReadFile(p)
	e := Update(p, func(c *Config) error { c.Default = "allow"; return nil }, func(Config) error { return errors.New("kernel rejected transaction") })
	if e == nil {
		t.Fatal("expected failure")
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("failed kernel transaction changed persisted configuration")
	}
}
func TestManyRules(t *testing.T) {
	c := New()
	for i := 0; i < 4096; i++ {
		c.Rules = append(c.Rules, Rule{Action: "deny", Protocol: "tcp", Port: "23"})
	}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
}
func TestParser(t *testing.T) {
	for _, tc := range []struct {
		action, dir string
		args        []string
		count       int
	}{
		{"allow", "", []string{"22/tcp", "from", "192.0.2.1", "comment", "SSH admin"}, 1},
		{"allow", "out", []string{"proto", "udp", "from", "any", "port", "1234", "to", "2001:db8::/32", "port", "53"}, 1},
		{"allow", "route", []string{"in", "on", "eth0", "out", "on", "tun0", "to", "10.0.0.0/8"}, 1},
		{"limit", "", []string{"ssh/tcp", "rate", "12/minute", "burst", "6"}, 1},
		{"reject", "", []string{"443/tcp", "log"}, 1},
		{"allow", "", []string{"WWW Full"}, 2},
		{"block", "", []string{"from", "192.0.2.0/24"}, 1},
	} {
		r, e := Parse(tc.action, tc.dir, tc.args)
		if e != nil || len(r) != tc.count {
			t.Errorf("%v: %+v %v", tc.args, r, e)
		}
	}
}
func TestInvalid(t *testing.T) {
	for _, args := range [][]string{{"22/tcp", "proto", "udp"}, {"from", "bad"}, {"in", "on", "../bad"}, {"from", "192.0.2.1", "to", "::1"}, {"proto", "icmp", "to", "::1"}, {"proto", "udp", "to", "any", "port", "0"}, {"22/tcp", "comment", "a\nb"}, {"proto", "tcp", "from", "any", "port", "22", "port", "33"}} {
		if _, e := Parse("allow", "", args); e == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
func FuzzConfigLoad(f *testing.F) {
	f.Add([]byte(`{"version":2,"default":"deny","rules":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var c Config
		if json.Unmarshal(b, &c) == nil {
			_ = c.Validate()
		}
	})
}
func TestServiceNames(t *testing.T) {
	lo, hi, e := PortsFor("tcp", "ssh")
	if e != nil || lo != 22 || hi != 22 {
		t.Fatal(lo, hi, e)
	}
	lo, hi, e = PortsFor("udp", "domain")
	if e != nil || lo != 53 || hi != 53 {
		t.Fatal(lo, hi, e)
	}
	if _, _, e = PortsFor("tcp", "nonexistent-ebpfw-service"); e == nil {
		t.Fatal("accepted unknown named service")
	}
}
