package main

import (
	"bytes"
	"encoding/json"
	"github.com/duongddinh/ebpfw/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.json")
	commands := [][]string{{"allow", "22/tcp", "from", "192.0.2.0/24"}, {"allow", "out", "53/udp"}, {"route", "allow", "in", "on", "eth0", "out", "on", "tun0"}, {"reject", "443/tcp", "log", "comment", "blocked"}, {"limit", "ssh/tcp"}, {"prepend", "allow", "proto", "icmpv6"}, {"insert", "2", "allow", "WWW Full"}, {"default", "deny", "outgoing"}, {"default", "reject", "routed"}, {"logging", "on"}, {"check"}, {"delete", "2"}}
	for _, args := range commands {
		if e := run(append([]string{"--config", p}, args...), &bytes.Buffer{}); e != nil {
			t.Fatalf("%v: %v", args, e)
		}
	}
	var out bytes.Buffer
	if e := run([]string{"--config", p, "status"}, &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "192.0.2.0/24") || !strings.Contains(out.String(), "outgoing deny") {
		t.Fatal(out.String())
	}
}
func TestDryRunNoSideEffects(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "rules.json")
	var out bytes.Buffer
	if e := run([]string{"--config", p, "--dry-run", "allow", "22/tcp"}, &out); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Dir(p)); !os.IsNotExist(e) {
		t.Fatal("dry-run created files")
	}
	var plan struct {
		Config config.Config `json:"config"`
	}
	if e := json.Unmarshal(out.Bytes(), &plan); e != nil || len(plan.Config.Rules) != 1 {
		t.Fatalf("bad dry-run: %v %s", e, out.String())
	}
}
func TestInvalidSyntax(t *testing.T) {
	for _, args := range [][]string{{"allow", "22/tcp", "proto", "udp"}, {"allow", "from", "bad"}, {"insert", "0", "allow", "22/tcp"}, {"allow", "proto", "icmp", "to", "::1"}, {"default", "wat"}, {"route"}} {
		p := filepath.Join(t.TempDir(), "rules.json")
		if e := run(append([]string{"--config", p}, args...), &bytes.Buffer{}); e == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
func TestProfiles(t *testing.T) {
	var out bytes.Buffer
	if e := run([]string{"app", "list"}, &out); e != nil || !strings.Contains(out.String(), "OpenSSH") {
		t.Fatal(e, out.String())
	}
}
func TestCustomProfileLifecycle(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.json")
	commands := [][]string{{"app", "set", "My Service", "8000/tcp", "8001/udp"}, {"allow", "My Service"}, {"app", "set", "My Service", "9000/tcp"}, {"app", "update", "My Service"}}
	for _, args := range commands {
		if e := run(append([]string{"--config", p}, args...), &bytes.Buffer{}); e != nil {
			t.Fatal(args, e)
		}
	}
	c, e := config.Load(p)
	if e != nil || len(c.Rules) != 1 || c.Rules[0].Port != "9000" || c.Rules[0].Application != "My Service" {
		t.Fatalf("profile expansion/update failed: %+v %v", c, e)
	}
	if e = run([]string{"--config", p, "app", "delete", "My Service"}, &bytes.Buffer{}); e != nil {
		t.Fatal(e)
	}
	c, e = config.Load(p)
	if e != nil || len(c.Applications) != 0 || len(c.Rules) != 1 {
		t.Fatal("deleting the definition unexpectedly changed expanded rules")
	}
}
