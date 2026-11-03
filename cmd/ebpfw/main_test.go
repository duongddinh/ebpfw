package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	commands := [][]string{{"allow", "22/tcp", "from", "192.0.2.0/24"}, {"allow", "proto", "icmpv6"}, {"deny", "53/udp"}, {"default", "deny"}, {"check"}, {"delete", "2"}}
	for _, c := range commands {
		if err := run(append([]string{"--config", path}, c...), &bytes.Buffer{}); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{"--config", path, "status"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "192.0.2.0/24") || strings.Contains(out.String(), "icmpv6") || !strings.Contains(out.String(), "deny") {
		t.Fatal(out.String())
	}
}
func TestRuleSyntax(t *testing.T) {
	for _, args := range [][]string{{"22/tcp", "proto", "udp"}, {"from", "bad"}, {"0/tcp"}, {"22/any"}, {"from"}, {"22", "from", "::/0", "from", "::1/128"}} {
		if _, err := parseRule("allow", args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
