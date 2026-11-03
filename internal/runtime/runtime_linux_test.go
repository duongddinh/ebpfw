//go:build linux

package runtime

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/duongddinh/ebpfw/internal/policy"
)

func ipv4(proto byte, port uint16) []byte {
	b := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 40)
	ip[9] = proto
	copy(ip[12:], []byte{192, 0, 2, 10})
	copy(ip[16:], []byte{198, 51, 100, 2})
	l4 := ip[20:]
	binary.BigEndian.PutUint16(l4[2:], port)
	if proto == 6 {
		l4[12] = 0x50
	} else if proto == 17 {
		binary.BigEndian.PutUint16(l4[4:], 20)
	}
	return b
}
func ipv6(proto byte, port uint16) []byte {
	b := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(b[12:], 0x86dd)
	ip := b[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], 20)
	ip[6] = proto
	copy(ip[8:], []byte{0x20, 1, 0xd, 0xb8, 0, 1})
	ip[23] = 1
	l4 := ip[40:]
	binary.BigEndian.PutUint16(l4[2:], port)
	if proto == 6 {
		l4[12] = 0x50
	} else if proto == 17 {
		binary.BigEndian.PutUint16(l4[4:], 20)
	}
	return b
}
func vlan(b []byte, ether uint16) []byte {
	out := make([]byte, len(b)+4)
	copy(out, b[:12])
	binary.BigEndian.PutUint16(out[12:], ether)
	copy(out[16:], b[12:])
	return out
}

func TestKernelFirewall(t *testing.T) {
	if os.Getenv("EBPFW_KERNEL_TEST") != "1" {
		t.Skip("set EBPFW_KERNEL_TEST=1 on a disposable privileged Linux host")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("EBPFW_OBJECT")
	if path == "" {
		t.Fatal("EBPFW_OBJECT is required")
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("kernel verifier rejected program: %+v", err)
	}
	defer collection.Close()
	c := policy.New()
	c.Rules = []policy.Rule{
		{Action: "deny", Protocol: "tcp", Port: "22", Source: "192.0.2.10/32"},
		{Action: "allow", Protocol: "tcp", Port: "22", Source: "192.0.2.0/24"},
		{Action: "allow", Protocol: "udp", Port: "53:54"},
		{Action: "allow", Protocol: "tcp", Port: "443", Source: "2001:db8:1::/48"},
		{Action: "allow", Protocol: "icmpv6"},
	}
	outer := collection.Maps["active_policy"]
	inner := spec.Maps["active_policy"].InnerMap
	if err = Install(outer, inner, c, spec.ByteOrder); err != nil {
		t.Fatal(err)
	}
	ssh := ipv4(6, 22)
	ssh[29] = 11
	wrongNet := ipv4(6, 22)
	wrongNet[28] = 3
	fragment := ipv4(6, 22)
	fragment[20] = 0x20
	padding := ipv4(6, 443)
	binary.BigEndian.PutUint16(padding[16:], 20)
	badTCP := ipv4(6, 443)
	badTCP[46] = 0x40
	badUDP := ipv4(17, 53)
	binary.BigEndian.PutUint16(badUDP[38:], 7)
	cases := []struct {
		name   string
		packet []byte
		want   uint32
	}{
		{"deny precedes allow", ipv4(6, 22), 1}, {"allow CIDR", ssh, 2}, {"wrong CIDR", wrongNet, 1},
		{"default deny", ipv4(6, 443), 1}, {"UDP range low", ipv4(17, 53), 2}, {"UDP range high", ipv4(17, 54), 2}, {"UDP outside range", ipv4(17, 55), 1},
		{"IPv6 CIDR", ipv6(6, 443), 2}, {"IPv6 port denied", ipv6(6, 80), 1}, {"ICMPv6", ipv6(58, 0), 2},
		{"ARP passes", append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 6}, make([]byte, 28)...), 2},
		{"single VLAN", vlan(ssh, 0x8100), 2}, {"QinQ", vlan(vlan(ssh, 0x8100), 0x88a8), 2}, {"third VLAN", vlan(vlan(vlan(ssh, 0x8100), 0x8100), 0x8100), 1},
		{"fragment dropped", fragment, 1}, {"IPv6 extension dropped", ipv6(0, 0), 1}, {"IPv6 fragment dropped", ipv6(44, 0), 1},
		{"Ethernet padding cannot supply TCP header", padding, 1}, {"bad TCP offset", badTCP, 1}, {"bad UDP length", badUDP, 1},
	}
	program := collection.Programs["ebpfw"]
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := program.Test(tc.packet)
			if err != nil || got != tc.want {
				t.Fatalf("got %d, want %d: %v", got, tc.want, err)
			}
		})
	}
	// Every truncation of an otherwise valid TCP packet must be rejected.
	packet := ipv4(6, 22)
	for n := 14; n < len(packet); n++ {
		got, _, err := program.Test(packet[:n])
		if err != nil || got != 1 {
			t.Fatalf("truncated packet length %d: %d %v", n, got, err)
		}
	}
	c = policy.New()
	c.Default = "allow"
	if err = Install(outer, inner, c, spec.ByteOrder); err != nil {
		t.Fatal(err)
	}
	if got, _, err := program.Test(ipv4(6, 443)); err != nil || got != 2 {
		t.Fatalf("policy reload: %d %v", got, err)
	}
	// The last rule must remain reachable at the configured maximum.
	c = policy.New()
	for i := 0; i < policy.MaxRules-1; i++ {
		c.Rules = append(c.Rules, policy.Rule{Action: "deny", Protocol: "tcp", Port: "1"})
	}
	c.Rules = append(c.Rules, policy.Rule{Action: "allow", Protocol: "tcp", Port: "443"})
	if err = Install(outer, inner, c, spec.ByteOrder); err != nil {
		t.Fatal(err)
	}
	if got, _, err := program.Test(ipv4(6, 443)); err != nil || got != 2 {
		t.Fatalf("last rule: %d %v", got, err)
	}
}
