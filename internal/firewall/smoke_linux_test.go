package firewall

import (
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"os"
	"testing"
)

func testObject() string {
	if p := os.Getenv("EBPFW_OBJECT"); p != "" {
		return p
	}
	return "/stateful.o"
}
func TestFoundation(t *testing.T) {
	if os.Getenv("EBPFW_FULL_TEST") != "1" {
		t.Skip("VM test")
	}
	requireVM(t)
	rlimit.RemoveMemlock()
	s, e := ebpf.LoadCollectionSpec(testObject())
	if e != nil {
		t.Fatal(e)
	}
	c, e := ebpf.NewCollection(s)
	if e != nil {
		var v *ebpf.VerifierError
		if errors.As(e, &v) {
			for _, line := range v.Log {
				t.Log(line)
			}
		}
		t.Fatalf("%+v", e)
	}
	defer c.Close()
	l, e := link.AttachNetfilter(link.NetfilterOptions{Program: c.Programs["ebpfw_full"], ProtocolFamily: link.NetfilterProtoIPv4, Hook: link.NetfilterInetLocalIn, Priority: 10, NetfilterFlags: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
}
