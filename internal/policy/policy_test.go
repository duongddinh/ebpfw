package policy

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestEncoding(t *testing.T) {
	c := New()
	c.Rules = []Rule{{Action: "allow", Protocol: "tcp", Port: "8000:9000", Source: "192.0.2.25/24"}}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b, err := c.Encode(order)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != WireSize || order.Uint32(b) != 1 || order.Uint32(b[4:]) != 1 || b[8] != 2 || b[9] != 4 || b[10] != 6 || order.Uint16(b[12:]) != 8000 || order.Uint16(b[14:]) != 9000 || order.Uint32(b[16:]) != 24 || b[20] != 192 || b[23] != 0 {
			t.Fatalf("incorrect ABI: %x", b[:36])
		}
	}
}
func TestRejectInvalid(t *testing.T) {
	for _, r := range []Rule{
		{"oops", "tcp", "", "22"}, {"allow", "sctp", "", ""}, {"allow", "any", "", "22"},
		{"allow", "tcp", "", "0"}, {"allow", "tcp", "", "65536"}, {"allow", "udp", "", "20:10"},
		{"allow", "tcp", "1.2.3.4", ""}, {"allow", "icmp", "::/0", ""}, {"allow", "icmpv6", "0.0.0.0/0", ""},
		{"allow", "tcp", "::ffff:192.0.2.1/128", ""},
	} {
		c := New()
		c.Rules = []Rule{r}
		if _, err := c.Encode(binary.LittleEndian); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	c := New()
	c.Rules = make([]Rule, MaxRules+1)
	if _, err := c.Encode(binary.LittleEndian); err == nil {
		t.Fatal("accepted excess rules")
	}
}
func TestAtomicEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Edit(path, func(c *Config) error {
				c.Rules = append(c.Rules, Rule{Action: "allow", Protocol: "tcp", Port: "22"})
				return nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	c, err := Load(path)
	if err != nil || len(c.Rules) != 20 {
		t.Fatalf("lost updates: %+v %v", c, err)
	}
	original, _ := os.ReadFile(path)
	if err = Edit(path, func(c *Config) error { c.Default = "invalid"; return nil }); err == nil {
		t.Fatal("accepted invalid edit")
	}
	current, _ := os.ReadFile(path)
	if string(original) != string(current) {
		t.Fatal("invalid edit changed persisted policy")
	}
}
func TestStrictLoad(t *testing.T) {
	for _, s := range []string{`{"version":1,"default":"allow","rules":[],"typo":true}`, `{"version":1,"default":"allow","rules":[]} {}`, `{"version":2,"default":"allow","rules":[]}`} {
		p := filepath.Join(t.TempDir(), "rules.json")
		os.WriteFile(p, []byte(s), 0600)
		if _, err := Load(p); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
