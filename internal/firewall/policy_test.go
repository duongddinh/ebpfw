package firewall

import (
	"encoding/binary"
	"github.com/duongddinh/ebpfw/internal/config"
	"testing"
)

func TestPolicyABI(t *testing.T) {
	c := config.New()
	c.Rules = []config.Rule{{Action: "allow", Protocol: "tcp", Direction: "out", Source: "192.0.2.25/24", Destination: "198.51.100.2", SourcePort: "1000:2000", Port: "443", OutInterface: "tun0", Log: true}, {Action: "block", Protocol: "any", Source: "2001:db8::/32"}}
	for _, o := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		p, e := Compile(c, o)
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Entries) != 3 || o.Uint32(p.Entries[0]) != 2 || o.Uint32(p.Entries[0][4:]) != 1 || o.Uint32(p.Entries[0][32:]) != 2 {
			t.Fatal("header ABI")
		}
		b := p.Entries[2]
		if len(b) != EntrySize || b[0] != 1 || b[1] != 2 || b[2] != 4 || b[3] != 6 || b[4] != 24 || b[5] != 32 || b[6] != 1 || o.Uint16(b[8:]) != 1000 || o.Uint16(b[14:]) != 443 || b[24] != 192 || b[27] != 0 || string(b[72:76]) != "tun0" || o.Uint32(b[88:]) != 0 {
			t.Fatalf("rule ABI: %x", b)
		}
	}
}
func TestStablePlan(t *testing.T) {
	c := config.New()
	a, _ := Compile(c, binary.LittleEndian)
	b, _ := Compile(c, binary.BigEndian)
	if a.SHA256 != b.SHA256 || a.Generation != b.Generation {
		t.Fatal("hash changed with host byte order")
	}
}
