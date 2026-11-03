package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/duongddinh/ebpfw/internal/config"
	"github.com/duongddinh/ebpfw/internal/testnet"
	"golang.org/x/sys/unix"
)

type testNamespace struct{ fd int }

func newNamespace(t *testing.T) *testNamespace {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old, e := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(old)
	if e = unix.Unshare(unix.CLONE_NEWNET); e != nil {
		t.Fatal(e)
	}
	fd, e := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	restore := unix.Setns(old, unix.CLONE_NEWNET)
	if e != nil || restore != nil {
		t.Fatalf("namespace: %v %v", e, restore)
	}
	ns := &testNamespace{fd}
	t.Cleanup(func() { unix.Close(fd) })
	return ns
}
func (ns *testNamespace) do(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	old, e := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	defer unix.Close(old)
	if e = unix.Setns(ns.fd, unix.CLONE_NEWNET); e != nil {
		return e
	}
	defer func() {
		if e := unix.Setns(old, unix.CLONE_NEWNET); e != nil {
			panic(e)
		}
	}()
	return fn()
}
func requireVM(t *testing.T) {
	t.Helper()
	if os.Getenv("EBPFW_FULL_TEST") != "1" {
		t.Skip("privileged disposable VM test")
	}
	nics, e := net.Interfaces()
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range nics {
		if n.Name != "lo" {
			t.Fatal("full tests require a private namespace with only loopback; refusing existing interfaces")
		}
	}
}
func fixture(t *testing.T) (*testNamespace, *testnet.Pair, *Manager) {
	t.Helper()
	requireVM(t)
	if e := testnet.Up("lo"); e != nil {
		t.Fatal(e)
	}
	peer := newNamespace(t)
	pair, e := testnet.New()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pair.Close)
	unix.Close(pair.FD)
	pair.FD = -1
	if e = testnet.Move(pair.Left.Index, peer.fd); e != nil {
		t.Fatal(e)
	}
	for _, a := range []string{"192.0.2.1/24", "2001:db8::1/64"} {
		if e = testnet.Address(pair.Right.Index, a); e != nil {
			t.Fatal(e)
		}
	}
	if e = peer.do(func() error {
		if e := testnet.Up("lo"); e != nil {
			return e
		}
		n, e := net.InterfaceByName(pair.Left.Name)
		if e != nil {
			return e
		}
		for _, a := range []string{"192.0.2.2/24", "2001:db8::2/64"} {
			if e = testnet.Address(n.Index, a); e != nil {
				return e
			}
		}
		return testnet.Up(n.Name)
	}); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join("/sys/fs/bpf", fmt.Sprintf("ebpfw-test-%d", time.Now().UnixNano()))
	m := NewManager(root, testObject())
	t.Cleanup(func() {
		c := config.New()
		if e := m.Apply(c); e != nil {
			t.Error("cleanup:", e)
		}
	})
	return peer, pair, m
}
func echoListener(t *testing.T, network, address string) (net.Listener, int) {
	t.Helper()
	l, e := net.Listen(network, address)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l, l.Addr().(*net.TCPAddr).Port
}
func TestFullTCP(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			peer, _, m := fixture(t)
			address := "192.0.2.1"
			if family == "tcp6" {
				address = "2001:db8::1"
			}
			_, port := echoListener(t, family, net.JoinHostPort(address, "0"))
			c := config.New()
			c.Enabled = true
			c.DefaultOut = "deny"
			c.Rules = []config.Rule{{Action: "allow", Protocol: "tcp", Port: fmt.Sprint(port), Direction: "in"}}
			if e := m.Apply(c); e != nil {
				t.Fatalf("enable: %+v", e)
			}
			var conn net.Conn
			if e := peer.do(func() error {
				var e error
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, e = (&net.Dialer{}).DialContext(ctx, family, net.JoinHostPort(address, fmt.Sprint(port)))
				return e
			}); e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("stateful-ebpf-"), 8192)
			go func() { _, _ = conn.Write(payload) }()
			got := make([]byte, len(payload))
			if _, e := io.ReadFull(conn, got); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("corrupt TCP transfer")
			}
			// Existing accepted flows survive an atomic reload removing their allow rule.
			c.Rules = nil
			if e := m.Apply(c); e != nil {
				t.Fatal(e)
			}
			if _, e := conn.Write([]byte("alive")); e != nil {
				t.Fatal(e)
			}
			reply := make([]byte, 5)
			if _, e := io.ReadFull(conn, reply); e != nil || string(reply) != "alive" {
				t.Fatalf("connection lost across reload: %q %v", reply, e)
			}
			s, e := m.Status()
			if e != nil || !s.Enabled || s.Hooks != 6 || s.Counters["stateful"] == 0 {
				t.Fatalf("status: %+v %v", s, e)
			}
		})
	}
}

func peerDial(ns *testNamespace, network, address string, local net.Addr) (net.Conn, error) {
	var c net.Conn
	e := ns.do(func() error {
		var e error
		c, e = (&net.Dialer{Timeout: 400 * time.Millisecond, LocalAddr: local}).Dial(network, address)
		return e
	})
	return c, e
}
func TestFullOutboundAndUDP(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			peer, _, m := fixture(t)
			host, remote := "192.0.2.1", "192.0.2.2"
			if network == "udp6" {
				host, remote = "2001:db8::1", "2001:db8::2"
			}
			var server *net.UDPConn
			if e := peer.do(func() error {
				var e error
				server, e = net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(remote)})
				return e
			}); e != nil {
				t.Fatal(e)
			}
			defer server.Close()
			go func() {
				b := make([]byte, 2048)
				for {
					n, a, e := server.ReadFromUDP(b)
					if e != nil {
						return
					}
					server.WriteToUDP(b[:n], a)
				}
			}()
			port := server.LocalAddr().(*net.UDPAddr).Port
			c := config.New()
			c.Enabled = true
			c.DefaultOut = "deny"
			c.Rules = []config.Rule{{Action: "allow", Protocol: "udp", Direction: "out", Destination: remote, Port: fmt.Sprint(port)}}
			if e := m.Apply(c); e != nil {
				t.Fatal(e)
			}
			client, e := net.DialUDP(network, &net.UDPAddr{IP: net.ParseIP(host)}, &net.UDPAddr{IP: net.ParseIP(remote), Port: port})
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(time.Second))
			if _, e = client.Write([]byte("dns-like-reply")); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 128)
			n, e := client.Read(b)
			if e != nil || string(b[:n]) != "dns-like-reply" {
				t.Fatalf("stateful UDP reply: %q %v", b[:n], e)
			}
			// An unrelated inbound UDP tuple must not inherit this flow's permission.
			receiver, e := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(host)})
			if e != nil {
				t.Fatal(e)
			}
			defer receiver.Close()
			if e = peer.do(func() error {
				v, e := net.DialUDP(network, nil, receiver.LocalAddr().(*net.UDPAddr))
				if e != nil {
					return e
				}
				defer v.Close()
				_, e = v.Write([]byte("unsolicited"))
				return e
			}); e != nil {
				t.Fatal(e)
			}
			receiver.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
			if n, _, e := receiver.ReadFromUDP(b); e == nil {
				t.Fatalf("unsolicited packet accepted: %d", n)
			}
			s, e := m.Status()
			if e != nil || s.Counters["stateful"] == 0 || s.Counters["dropped"] == 0 {
				t.Fatalf("counters: %+v %v", s, e)
			}
		})
	}
}
func TestFullIncomingSelectors(t *testing.T) {
	peer, pair, m := fixture(t)
	server, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port
	c := config.New()
	c.Enabled = true
	c.Logging = true
	c.Rules = []config.Rule{{Action: "allow", Protocol: "udp", Direction: "in", InInterface: pair.Right.Name, Source: "192.0.2.2/32", Destination: "192.0.2.1/32", SourcePort: "31337", Port: fmt.Sprint(port)}}
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	send := func(source int, text string) {
		t.Helper()
		if e := peer.do(func() error {
			v, e := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: source}, server.LocalAddr().(*net.UDPAddr))
			if e != nil {
				return e
			}
			defer v.Close()
			_, e = v.Write([]byte(text))
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	send(31337, "allowed")
	b := make([]byte, 64)
	server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, e := server.ReadFromUDP(b)
	if e != nil || string(b[:n]) != "allowed" {
		p, _ := ebpf.LoadPinnedMap(filepath.Join(m.Root, "events"), nil)
		if p != nil {
			defer p.Close()
			r, _ := ringbuf.NewReader(p)
			if r != nil {
				defer r.Close()
				r.SetDeadline(time.Now().Add(100 * time.Millisecond))
				rec, er := r.Read()
				if er == nil {
					var ev Event
					binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev)
					t.Logf("event family=%d proto=%d src=%v dst=%v ports=%d/%d action=%d iif=%q oif=%q", ev.Family, ev.Protocol, ev.Source, ev.Destination, ev.SourcePort, ev.DestinationPort, ev.Action, string(ev.InInterface[:]), string(ev.OutInterface[:]))
				}
			}
		}
		t.Fatal(e, string(b[:n]))
	}
	send(31338, "wrong-source-port")
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, e = server.ReadFromUDP(b); e == nil {
		t.Fatal("source-port selector was bypassed")
	}
	c.Rules[0].InInterface = "unrelated0"
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	send(31337, "established-survives")
	server.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, e = server.ReadFromUDP(b); e != nil {
		t.Fatal("existing flow should survive policy edit", e)
	}
	c.Rules[0].SourcePort = "31339"
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	send(31339, "wrong-interface")
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, e = server.ReadFromUDP(b); e == nil {
		t.Fatal("interface selector was bypassed")
	}
}
func TestFullRateLimit(t *testing.T) {
	peer, pair, m := fixture(t)
	_, port := echoListener(t, "tcp4", "192.0.2.1:0")
	c := config.New()
	c.Enabled = true
	c.DefaultOut = "deny"
	c.Rules = []config.Rule{{Action: "limit", Protocol: "tcp", Port: fmt.Sprint(port), Rate: 1, Burst: 2}}
	if e := m.Apply(c); e != nil {
		t.Fatal(e)
	}
	address := net.JoinHostPort("192.0.2.1", fmt.Sprint(port))
	for i := 0; i < 2; i++ {
		v, e := peerDial(peer, "tcp4", address, nil)
		if e != nil {
			t.Fatalf("within burst %d: %v", i, e)
		}
		v.Close()
	}
	if v, e := peerDial(peer, "tcp4", address, nil); e == nil {
		v.Close()
		t.Fatal("connection over the per-source burst was accepted")
	}
	if e := peer.do(func() error {
		n, e := net.InterfaceByName(pair.Left.Name)
		if e != nil {
			return e
		}
		return testnet.Address(n.Index, "192.0.2.3/24")
	}); e != nil {
		t.Fatal(e)
	}
	v, e := peerDial(peer, "tcp4", address, &net.TCPAddr{IP: net.ParseIP("192.0.2.3")})
	if e != nil {
		t.Fatal("independent source shared another source's bucket", e)
	}
	v.Close()
	s, e := m.Status()
	if e != nil || s.Counters["rate_limited"] == 0 {
		t.Fatal("missing rate-limit counter", e)
	}
}
func TestFullRelatedICMP(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			_, _, m := fixture(t)
			host, remote := "192.0.2.1", "192.0.2.2"
			if network == "udp6" {
				host, remote = "2001:db8::1", "2001:db8::2"
			}
			c := config.New()
			c.Enabled = true
			if e := m.Apply(c); e != nil {
				t.Fatal(e)
			}
			v, e := net.DialUDP(network, &net.UDPAddr{IP: net.ParseIP(host)}, &net.UDPAddr{IP: net.ParseIP(remote), Port: 54329})
			if e != nil {
				t.Fatal(e)
			}
			defer v.Close()
			v.SetDeadline(time.Now().Add(time.Second))
			if _, e = v.Write([]byte("closed-peer-port")); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 32)
			_, e = v.Read(b)
			if e == nil || !errors.Is(e, unix.ECONNREFUSED) {
				t.Fatalf("expected related ICMP port-unreachable, got %v", e)
			}
			s, e := m.Status()
			if e != nil || s.Counters["stateful"] == 0 {
				t.Fatal("related ICMP was not recognized", e)
			}
		})
	}
}
func TestFullManyRulesAndRejectionAtomicity(t *testing.T) {
	peer, _, m := fixture(t)
	_, port := echoListener(t, "tcp4", "192.0.2.1:0")
	c := config.New()
	c.Enabled = true
	for i := 0; i < 1024; i++ {
		c.Rules = append(c.Rules, config.Rule{Action: "deny", Protocol: "tcp", Port: "1"})
	}
	c.Rules = append(c.Rules, config.Rule{Action: "allow", Protocol: "tcp", Port: fmt.Sprint(port)})
	if e := m.Apply(c); e != nil {
		t.Fatal(e)
	}
	before, _ := m.Status()
	invalid := c
	invalid.Default = "invalid"
	if e := m.Apply(invalid); e == nil {
		t.Fatal("invalid policy was applied")
	}
	after, _ := m.Status()
	if after.Generation != before.Generation {
		t.Fatal("invalid update changed the active generation")
	}
	v, e := peerDial(peer, "tcp4", net.JoinHostPort("192.0.2.1", fmt.Sprint(port)), nil)
	if e != nil {
		t.Fatal("rule beyond old 64-rule limit was unreachable", e)
	}
	v.Close()
}

func udpWire(family int, source, destination string, sport, dport uint16, body []byte, extension bool) []byte {
	udp := make([]byte, 8+len(body))
	binary.BigEndian.PutUint16(udp, sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], body)
	if family == 4 {
		ip := make([]byte, 20+len(udp))
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
		ip[8] = 64
		ip[9] = 17
		copy(ip[12:], net.ParseIP(source).To4())
		copy(ip[16:], net.ParseIP(destination).To4())
		copy(ip[20:], udp)
		binary.BigEndian.PutUint16(ip[10:], checksum(ip[:20]))
		return ip
	}
	extra := 0
	if extension {
		extra = 8
	}
	ip := make([]byte, 40+extra+len(udp))
	ip[0] = 0x60
	ip[6] = 17
	ip[7] = 64
	binary.BigEndian.PutUint16(ip[4:], uint16(extra+len(udp)))
	copy(ip[8:], net.ParseIP(source).To16())
	copy(ip[24:], net.ParseIP(destination).To16())
	if extension {
		ip[6] = 0
		ip[40] = 17
	}
	pseudo := make([]byte, 40)
	copy(pseudo, ip[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(udp)))
	pseudo[39] = 17
	binary.BigEndian.PutUint16(udp[6:], checksum(pseudo, udp))
	copy(ip[40+extra:], udp)
	return ip
}
func rawSend(ns *testNamespace, family int, destination string, packets ...[]byte) error {
	return ns.do(func() error {
		af := unix.AF_INET
		if family == 6 {
			af = unix.AF_INET6
		}
		fd, e := unix.Socket(af, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		if e != nil {
			return e
		}
		defer unix.Close(fd)
		var target unix.Sockaddr
		if family == 4 {
			var a [4]byte
			copy(a[:], net.ParseIP(destination).To4())
			target = &unix.SockaddrInet4{Addr: a}
			unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		} else {
			var a [16]byte
			copy(a[:], net.ParseIP(destination).To16())
			target = &unix.SockaddrInet6{Addr: a}
			unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
		}
		for _, p := range packets {
			if e = unix.Sendto(fd, p, 0, target); e != nil {
				return e
			}
		}
		return nil
	})
}
func TestFullFragmentsAndIPv6Extensions(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			peer, _, m := fixture(t)
			network, host, remote := "udp4", "192.0.2.1", "192.0.2.2"
			if family == 6 {
				network, host, remote = "udp6", "2001:db8::1", "2001:db8::2"
			}
			receiver, e := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(host)})
			if e != nil {
				t.Fatal(e)
			}
			defer receiver.Close()
			port := uint16(receiver.LocalAddr().(*net.UDPAddr).Port)
			c := config.New()
			c.Enabled = true
			c.Rules = []config.Rule{{Action: "allow", Protocol: "udp", Port: fmt.Sprint(port)}}
			if e = m.Apply(c); e != nil {
				t.Fatal(e)
			}
			body := bytes.Repeat([]byte("fragment"), 8)
			whole := udpWire(family, remote, host, 50101, port, body, false)
			var first, second []byte
			if family == 4 {
				first = append([]byte{}, whole[:20]...)
				first = append(first, whole[20:44]...)
				binary.BigEndian.PutUint16(first[2:], uint16(len(first)))
				binary.BigEndian.PutUint16(first[4:], 0x1234)
				binary.BigEndian.PutUint16(first[6:], 0x2000)
				first[10], first[11] = 0, 0
				binary.BigEndian.PutUint16(first[10:], checksum(first[:20]))
				second = append([]byte{}, whole[:20]...)
				second = append(second, whole[44:]...)
				binary.BigEndian.PutUint16(second[2:], uint16(len(second)))
				binary.BigEndian.PutUint16(second[4:], 0x1234)
				binary.BigEndian.PutUint16(second[6:], 3)
				second[10], second[11] = 0, 0
				binary.BigEndian.PutUint16(second[10:], checksum(second[:20]))
			} else {
				fragment := func(data []byte, offset uint16) []byte {
					p := append([]byte{}, whole[:40]...)
					p[6] = 44
					binary.BigEndian.PutUint16(p[4:], uint16(8+len(data)))
					h := make([]byte, 8)
					h[0] = 17
					binary.BigEndian.PutUint16(h[2:], offset)
					binary.BigEndian.PutUint32(h[4:], 0x12345678)
					p = append(p, h...)
					return append(p, data...)
				}
				first = fragment(whole[40:64], 1)
				second = fragment(whole[64:], 24)
			}
			// Reverse-order fragments exercise reassembly rather than first-fragment luck.
			if e = rawSend(peer, family, host, second, first); e != nil {
				t.Fatal(e)
			}
			receiver.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 256)
			n, _, e := receiver.ReadFromUDP(b)
			if e != nil || !bytes.Equal(b[:n], body) {
				t.Fatalf("fragment reassembly: %q %v", b[:n], e)
			}
			if family == 6 {
				message := []byte("IPv6-hop-by-hop")
				p := udpWire(6, remote, host, 50102, port, message, true)
				if e = rawSend(peer, 6, host, p); e != nil {
					t.Fatal(e)
				}
				receiver.SetReadDeadline(time.Now().Add(time.Second))
				n, _, e = receiver.ReadFromUDP(b)
				if e != nil || !bytes.Equal(b[:n], message) {
					t.Fatalf("extension header: %q %v", b[:n], e)
				}
			}
		})
	}
}
func TestFullEarlyBlocks(t *testing.T) {
	peer, pair, m := fixture(t)
	receiver, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	port := receiver.LocalAddr().(*net.UDPAddr).Port
	c := config.New()
	c.Enabled = true
	c.Default = "allow"
	c.Rules = []config.Rule{{Action: "block", Protocol: "any", Source: "192.0.2.2/32"}}
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	if e = m.Accelerate(pair.Right.Name, "generic"); e != nil {
		t.Fatal(e)
	}
	if e = m.Accelerate(pair.Right.Name, "generic"); e == nil {
		t.Fatal("duplicate accelerator replaced its owner")
	}
	send := func() {
		t.Helper()
		if e := rawSend(peer, 4, "192.0.2.1", udpWire(4, "192.0.2.2", "192.0.2.1", 50103, uint16(port), []byte("early"), false)); e != nil {
			t.Fatal(e)
		}
	}
	send()
	receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	b := make([]byte, 32)
	if _, _, e = receiver.ReadFromUDP(b); e == nil {
		t.Fatal("early block did not enforce")
	}
	s, e := m.Status()
	if e != nil || len(s.RuleCounters) != 1 || s.RuleCounters[0] == 0 {
		t.Fatalf("early counter: %+v %v", s, e)
	}
	// Logging delegates to the full eBPF hook so early drops cannot hide events.
	c.Logging = true
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	control, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "early_enabled"), nil)
	if e != nil {
		t.Fatal(e)
	}
	var on uint32
	e = control.Lookup(uint32(0), &on)
	control.Close()
	if e != nil || on != 0 {
		t.Fatal("acceleration did not pause for logging", e)
	}
	c.Logging = false
	c.Rules = nil
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	send()
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, e = receiver.ReadFromUDP(b); e != nil {
		t.Fatal("stale early block survived the policy update", e)
	}
	if e = m.Deaccelerate(pair.Right.Name); e != nil {
		t.Fatal(e)
	}
}

func TestFullRejectReplies(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(family, func(t *testing.T) {
			peer, _, m := fixture(t)
			host := "192.0.2.1"
			if strings.HasSuffix(family, "6") {
				host = "2001:db8::1"
			}
			port := 54001
			if strings.HasPrefix(family, "tcp") {
				_, port = echoListener(t, family, net.JoinHostPort(host, "0"))
			}
			c := config.New()
			c.Enabled = true
			c.DefaultOut = "deny"
			c.Rules = []config.Rule{{Action: "reject", Protocol: family[:3], Port: fmt.Sprint(port), Log: true}}
			path := filepath.Join(t.TempDir(), "rules.json")
			if e := config.Store(path, c); e != nil {
				t.Fatal(e)
			}
			if e := m.Apply(c); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Getenv("EBPFW_BINARY"), "--config", path, "--pin-root", m.Root, "--object", testObject(), "run")
			var logs bytes.Buffer
			cmd.Stdout = &logs
			cmd.Stderr = &logs
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				cmd.Process.Signal(unix.SIGTERM)
				cmd.Wait()
				if t.Failed() {
					t.Log(logs.String())
				}
			}()
			time.Sleep(80 * time.Millisecond)
			v, e := peerDial(peer, family, net.JoinHostPort(host, fmt.Sprint(port)), nil)
			if strings.HasPrefix(family, "udp") && e == nil {
				defer v.Close()
				v.SetDeadline(time.Now().Add(time.Second))
				if _, e = v.Write([]byte("reject")); e != nil {
					t.Fatal(e)
				}
				_, e = v.Read(make([]byte, 64))
				if !errors.Is(e, unix.EHOSTUNREACH) && !errors.Is(e, unix.EACCES) {
					t.Fatalf("expected administrative ICMP rejection: %v", e)
				}
				return
			}
			if e == nil {
				v.Close()
				t.Fatal("reject rule accepted connection")
			}
			if !errors.Is(e, unix.ECONNREFUSED) {
				t.Fatalf("expected reset rather than timeout: %v", e)
			}
		})
	}
}

func TestFullRoutedPolicy(t *testing.T) {
	first, a, m := fixture(t)
	second := newNamespace(t)
	b, e := testnet.New()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(b.Close)
	unix.Close(b.FD)
	b.FD = -1
	if e = testnet.Move(b.Left.Index, second.fd); e != nil {
		t.Fatal(e)
	}
	if e = testnet.Address(b.Right.Index, "198.51.100.1/24"); e != nil {
		t.Fatal(e)
	}
	if e = second.do(func() error {
		if e := testnet.Up("lo"); e != nil {
			return e
		}
		n, e := net.InterfaceByName(b.Left.Name)
		if e != nil {
			return e
		}
		if e = testnet.Address(n.Index, "198.51.100.2/24"); e != nil {
			return e
		}
		if e = testnet.Up(n.Name); e != nil {
			return e
		}
		return testnet.Route("192.0.2.0/24", "198.51.100.1", n.Index)
	}); e != nil {
		t.Fatal(e)
	}
	if e = first.do(func() error {
		n, e := net.InterfaceByName(a.Left.Name)
		if e != nil {
			return e
		}
		return testnet.Route("198.51.100.0/24", "192.0.2.1", n.Index)
	}); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
	var server net.Listener
	if e = second.do(func() error { var e error; server, e = net.Listen("tcp4", "198.51.100.2:0"); return e }); e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	go func() {
		for {
			v, e := server.Accept()
			if e != nil {
				return
			}
			go func() { defer v.Close(); io.Copy(v, v) }()
		}
	}()
	port := server.Addr().(*net.TCPAddr).Port
	c := config.New()
	c.Enabled = true
	c.DefaultOut = "deny"
	c.Rules = []config.Rule{{Action: "allow", Direction: "route", Protocol: "tcp", Port: fmt.Sprint(port), InInterface: a.Right.Name, OutInterface: b.Right.Name}}
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	v, e := peerDial(first, "tcp4", server.Addr().String(), nil)
	if e != nil {
		t.Fatal("forwarded connection blocked", e)
	}
	defer v.Close()
	v.SetDeadline(time.Now().Add(time.Second))
	v.Write([]byte("routed"))
	got := make([]byte, 6)
	if _, e = io.ReadFull(v, got); e != nil || string(got) != "routed" {
		t.Fatal("forwarded reply did not use state", e)
	}
	// Root's own output policy remains separate from the route allow rule.
	if local, e := net.DialTimeout("tcp4", server.Addr().String(), 250*time.Millisecond); e == nil {
		local.Close()
		t.Fatal("route rule incorrectly authorized host output")
	}
}
func TestFullNewTunnelAndLoopback(t *testing.T) {
	_, _, m := fixture(t)
	c := config.New()
	c.Enabled = true
	c.DefaultOut = "deny"
	c.Rules = []config.Rule{{Action: "allow", Protocol: "udp", InInterface: "ewtun0"}}
	if e := m.Apply(c); e != nil {
		t.Fatal(e)
	}
	// Create the virtual interface after enable: namespace-wide eBPF hooks cover it.
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	ifr, e := unix.NewIfreq("ewtun0")
	if e != nil {
		t.Fatal(e)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if e = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); e != nil {
		t.Fatal(e)
	}
	nic, e := net.InterfaceByName("ewtun0")
	if e != nil {
		t.Fatal(e)
	}
	if e = testnet.Address(nic.Index, "203.0.113.1/24"); e != nil {
		t.Fatal(e)
	}
	if e = testnet.Up(nic.Name); e != nil {
		t.Fatal(e)
	}
	receiver, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("203.0.113.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	port := uint16(receiver.LocalAddr().(*net.UDPAddr).Port)
	p := udpWire(4, "203.0.113.2", "203.0.113.1", 50104, port, []byte("tunnel"), false)
	if _, e = unix.Write(fd, p); e != nil {
		t.Fatal(e)
	}
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	n, _, e := receiver.ReadFromUDP(b)
	if e != nil || string(b[:n]) != "tunnel" {
		t.Fatal("new tunnel was not covered", e)
	}
	_, tcpPort := echoListener(t, "tcp4", "127.0.0.1:0")
	v, e := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(tcpPort)), time.Second)
	if e != nil {
		t.Fatal("loopback default broke local applications", e)
	}
	v.Close()
}

func waitUntil(t *testing.T, condition func() bool, message string) {
	t.Helper()
	end := time.Now().Add(4 * time.Second)
	for time.Now().Before(end) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(message)
}
func TestFullAgentCrashAndReload(t *testing.T) {
	peer, _, m := fixture(t)
	_, port := echoListener(t, "tcp4", "192.0.2.1:0")
	c := config.New()
	c.Enabled = true
	c.Rules = []config.Rule{{Action: "allow", Protocol: "tcp", Port: fmt.Sprint(port), Log: true}}
	path := filepath.Join(t.TempDir(), "rules.json")
	if e := config.Store(path, c); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Getenv("EBPFW_BINARY"), "--config", path, "--pin-root", m.Root, "--object", testObject(), "run")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	waitUntil(t, func() bool { s, e := m.Status(); return e == nil && s.Enabled && s.AgentAlive }, "agent did not become ready")
	address := net.JoinHostPort("192.0.2.1", fmt.Sprint(port))
	v, e := peerDial(peer, "tcp4", address, nil)
	if e != nil {
		t.Fatal(e)
	}
	v.Close()
	original, _ := m.Status()
	if e = os.WriteFile(path, []byte(`{"version":999}`), 0600); e != nil {
		t.Fatal(e)
	}
	time.Sleep(1100 * time.Millisecond)
	still, e := m.Status()
	if e != nil || still.Generation != original.Generation {
		t.Fatal("invalid file changed live enforcement", e)
	}
	c.Rules = []config.Rule{{Action: "deny", Protocol: "tcp", Port: fmt.Sprint(port)}}
	if e = config.Store(path, c); e != nil {
		t.Fatal(e)
	}
	plan, _ := Compile(c, binary.NativeEndian)
	waitUntil(t, func() bool { s, e := m.Status(); return e == nil && s.Generation == plan.Generation }, "valid policy edit did not reload")
	if v, e = peerDial(peer, "tcp4", address, nil); e == nil {
		v.Close()
		t.Fatal("reloaded deny did not enforce")
	}
	cmd.Process.Kill()
	cmd.Wait()
	waited = true
	s, e := m.Status()
	if e != nil || !s.Enabled || s.Hooks != 6 || s.AgentAlive {
		t.Fatalf("crash lost enforcement or left a false heartbeat: %+v %v", s, e)
	}
	if v, e = peerDial(peer, "tcp4", address, nil); e == nil {
		v.Close()
		t.Fatal("daemon crash caused fail-open")
	}
	// A fresh management process can resume the same pinned kernel program.
	if e = m.Apply(c); e != nil {
		t.Fatal("restart could not resume pinned enforcement", e)
	}
	var eventLog bytes.Buffer
	if e = m.Logs(&eventLog); e != nil || eventLog.Len() == 0 {
		t.Fatal("packet event logging did not produce a record", e)
	}
}

func TestFullConcurrentConnections(t *testing.T) {
	peer, _, m := fixture(t)
	_, port := echoListener(t, "tcp4", "192.0.2.1:0")
	c := config.New()
	c.Enabled = true
	c.DefaultOut = "deny"
	c.Rules = []config.Rule{{Action: "allow", Protocol: "tcp", Port: fmt.Sprint(port)}}
	if e := m.Apply(c); e != nil {
		t.Fatal(e)
	}
	errorsFound := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := peerDial(peer, "tcp4", net.JoinHostPort("192.0.2.1", fmt.Sprint(port)), nil)
			if e != nil {
				errorsFound <- e
				return
			}
			defer v.Close()
			v.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte("parallel"), 1024)
			if _, e = v.Write(payload); e != nil {
				errorsFound <- e
				return
			}
			b := make([]byte, len(payload))
			if _, e = io.ReadFull(v, b); e != nil {
				errorsFound <- e
				return
			}
			if !bytes.Equal(b, payload) {
				errorsFound <- fmt.Errorf("corrupt concurrent stream")
			}
		}()
	}
	wg.Wait()
	close(errorsFound)
	for e := range errorsFound {
		t.Error(e)
	}
}
func TestFullBoundedStateExpiry(t *testing.T) {
	_, _, m := fixture(t)
	c := config.New()
	c.Enabled = true
	c.Rules = []config.Rule{{Action: "limit", Protocol: "tcp", Port: "22", Rate: 60, Burst: 2}}
	if e := m.Apply(c); e != nil {
		t.Fatal(e)
	}
	now := uint64(2 * time.Hour)
	flows, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "flows"), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer flows.Close()
	info, e := flows.Info()
	if e != nil || info.MaxEntries != 65536 {
		t.Fatal("unbounded or unexpected flow capacity", e)
	}
	var expired, fresh [40]byte
	expired[36], expired[37] = 4, 6
	fresh = expired
	fresh[0] = 1
	var a, b [48]byte
	binary.NativeEndian.PutUint32(a[4:], 4)
	binary.NativeEndian.PutUint64(a[8:], 1)
	binary.NativeEndian.PutUint32(b[4:], 3)
	binary.NativeEndian.PutUint64(b[8:], now-1)
	if e = flows.Update(expired, a, ebpf.UpdateAny); e != nil {
		t.Fatal(e)
	}
	if e = flows.Update(fresh, b, ebpf.UpdateAny); e != nil {
		t.Fatal(e)
	}
	rates, e := ebpf.LoadPinnedMap(filepath.Join(m.Root, "rates"), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer rates.Close()
	plan, _ := Compile(c, binary.NativeEndian)
	var rk [28]byte
	rk[20] = 4
	binary.NativeEndian.PutUint32(rk[24:], plan.Generation)
	var rv [24]byte
	binary.NativeEndian.PutUint64(rv[8:], now-uint64(3*time.Second))
	if e = rates.Update(rk, rv, ebpf.UpdateAny); e != nil {
		t.Fatal(e)
	}
	if e = m.expireAt(c, now); e != nil {
		t.Fatal(e)
	}
	if e = flows.Lookup(expired, &a); !errors.Is(e, ebpf.ErrKeyNotExist) {
		t.Fatal("expired closed flow retained", e)
	}
	if e = flows.Lookup(fresh, &b); e != nil {
		t.Fatal("fresh established flow was removed", e)
	}
	if e = rates.Lookup(rk, &rv); !errors.Is(e, ebpf.ErrKeyNotExist) {
		t.Fatal("fully refilled idle rate bucket retained", e)
	}
}
func TestFullForeignOwnerProtection(t *testing.T) {
	requireVM(t)
	root := filepath.Join("/sys/fs/bpf", fmt.Sprintf("foreign-test-%d", time.Now().UnixNano()))
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(root)
	p, e := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	path := filepath.Join(root, "foreign")
	if e = p.Pin(path); e != nil {
		t.Fatal(e)
	}
	defer p.Unpin()
	m := NewManager(root, testObject())
	c := config.New()
	c.Enabled = true
	if e = m.Apply(c); e == nil {
		t.Fatal("accepted a foreign pin root")
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal("foreign state was removed", e)
	}
	c.Enabled = false
	if e = m.Apply(c); e == nil {
		t.Fatal("disable removed a foreign root")
	}
}

func TestFullTCPFastOpen(t *testing.T) {
	peer, _, m := fixture(t)
	if e := os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("515"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := peer.do(func() error { return os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("7"), 0600) }); e != nil {
		t.Fatal(e)
	}
	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var failure error
		e := raw.Control(func(fd uintptr) { failure = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 5) })
		if e != nil {
			return e
		}
		return failure
	}}
	server, e := lc.Listen(context.Background(), "tcp4", "192.0.2.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	go func() {
		for {
			v, e := server.Accept()
			if e != nil {
				return
			}
			go func() { defer v.Close(); io.Copy(v, v) }()
		}
	}()
	port := server.Addr().(*net.TCPAddr).Port
	c := config.New()
	c.Enabled = true
	c.DefaultOut = "deny"
	c.Rules = []config.Rule{{Action: "allow", Protocol: "tcp", Port: fmt.Sprint(port)}}
	if e = m.Apply(c); e != nil {
		t.Fatal(e)
	}
	if e = peer.do(func() error {
		fd, e := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if e != nil {
			return e
		}
		defer unix.Close(fd)
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 2})
		message := []byte("data-in-SYN")
		if e = unix.Sendto(fd, message, unix.MSG_FASTOPEN, &unix.SockaddrInet4{Addr: [4]byte{192, 0, 2, 1}, Port: port}); e != nil {
			return e
		}
		b := make([]byte, 64)
		n, e := unix.Read(fd, b)
		if e != nil {
			return e
		}
		if !bytes.Equal(b[:n], message) {
			return fmt.Errorf("fast-open response mismatch")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	s, e := m.Status()
	if e != nil || s.Counters["fast_open_syns"] == 0 {
		t.Fatal("test did not exercise data in SYN", e)
	}
}
