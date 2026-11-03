package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/duongddinh/ebpfw/internal/config"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type benchmarkSample struct {
	Backend                 string  `json:"backend"`
	Workload                string  `json:"workload"`
	Rules                   int     `json:"rules"`
	Repetition              int     `json:"repetition"`
	Operations              int     `json:"operations"`
	NSPerOperation          float64 `json:"ns_per_operation"`
	VerifiedPackets         uint64  `json:"verified_packets,omitempty"`
	VerifiedPayloadMessages uint64  `json:"verified_payload_messages,omitempty"`
	CompletedConnections    uint64  `json:"completed_connections,omitempty"`
	Kernel                  string  `json:"kernel"`
	Architecture            string  `json:"architecture"`
}

func ufwCommand(t *testing.T, args ...string) {
	t.Helper()
	out, e := exec.Command("ufw", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("ufw %v: %v\n%s", args, e, out)
	}
}
func setupUFW(t *testing.T, workload string, rules, port int) {
	t.Helper()
	// Each worker owns private mount + network namespaces; UFW's mutable
	// configuration must be fresh too, otherwise reset backup names collide.
	if e := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); e != nil {
		t.Fatal(e)
	}
	defaults, e := os.ReadFile("/etc/default/ufw")
	if e != nil {
		t.Fatal(e)
	}
	private := filepath.Join(t.TempDir(), "ufw-defaults")
	if e = os.WriteFile(private, defaults, 0644); e != nil {
		t.Fatal(e)
	}
	if e = unix.Mount(private, "/etc/default/ufw", "", unix.MS_BIND, ""); e != nil {
		t.Fatal(e)
	}
	type seedFile struct {
		name      string
		mode      os.FileMode
		data      []byte
		directory bool
	}
	var seed []seedFile
	if e = filepath.WalkDir("/etc/ufw", func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, e := filepath.Rel("/etc/ufw", path)
		if e != nil {
			return e
		}
		if relative == "." {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return e
		}
		v := seedFile{name: relative, mode: info.Mode().Perm(), directory: d.IsDir()}
		if !v.directory {
			v.data, e = os.ReadFile(path)
			if e != nil {
				return e
			}
		}
		seed = append(seed, v)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = unix.Mount("tmpfs", "/etc/ufw", "tmpfs", 0, "mode=0755"); e != nil {
		t.Fatal(e)
	}
	for _, v := range seed {
		target := filepath.Join("/etc/ufw", v.name)
		if v.directory {
			if e = os.MkdirAll(target, v.mode); e != nil {
				t.Fatal(e)
			}
		} else {
			if e = os.WriteFile(target, v.data, v.mode); e != nil {
				t.Fatal(e)
			}
		}
	}
	if e = os.MkdirAll("/etc/ufw/applications.d", 0755); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"ufw.conf", "before.init", "after.init"} {
		data, e := os.ReadFile(filepath.Join("/usr/share/ufw", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join("/etc/ufw", name), data, 0640); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"before.rules", "before6.rules", "after.rules", "after6.rules", "user.rules", "user6.rules"} {
		data, e := os.ReadFile(filepath.Join("/usr/share/ufw/iptables", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join("/etc/ufw", name), data, 0640); e != nil {
			t.Fatal(e)
		}
	}
	ufwCommand(t, "logging", "off")
	ufwCommand(t, "default", "deny", "incoming")
	ufwCommand(t, "default", "allow", "outgoing")
	ufwCommand(t, "default", "deny", "routed")
	if workload == "early-source-drop" {
		path := "/etc/ufw/before.rules"
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		text := string(data)
		at := strings.Index(text, "\n-A ")
		if at < 0 {
			t.Fatal("unexpected UFW template")
		}
		at++
		var extra strings.Builder
		for _, chain := range []string{"ufw-before-input", "ufw-before-output", "ufw-before-forward"} {
			for i := 0; i < rules; i++ {
				source := fmt.Sprintf("198.18.%d.0/24", i)
				if i == rules-1 {
					source = "192.0.2.2/32"
				}
				fmt.Fprintf(&extra, "-A %s -s %s -j DROP\n", chain, source)
			}
		}
		text = text[:at] + extra.String() + text[at:]
		if e = os.WriteFile(path, []byte(text), 0640); e != nil {
			t.Fatal(e)
		}
	} else {
		proto := "udp"
		if strings.HasPrefix(workload, "tcp-") {
			proto = "tcp"
		}
		for i := 0; i < rules; i++ {
			p := 1000 + i
			action := "deny"
			if i == rules-1 {
				p = port
				if workload != "udp-drop" {
					action = "allow"
				}
			}
			ufwCommand(t, action, "in", "proto", proto, "to", "any", "port", strconv.Itoa(p))
		}
	}
	ufwCommand(t, "--force", "enable")
	t.Cleanup(func() { ufwCommand(t, "disable") })
}
func nftCount(chainName string, index int) (uint64, error) {
	c := &nftables.Conn{}
	table := &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4}
	rules, e := c.GetRules(table, &nftables.Chain{Name: chainName, Table: table})
	if e != nil {
		return 0, e
	}
	if index >= len(rules) {
		return 0, fmt.Errorf("UFW chain %s has %d rules; expected index %d", chainName, len(rules), index)
	}
	var count uint64
	found := false
	for _, v := range rules[index].Exprs {
		if n, ok := v.(*expr.Counter); ok {
			count += n.Packets
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("missing UFW packet counter")
	}
	return count, nil
}
func TestBenchmarkWorker(t *testing.T) {
	if os.Getenv("EBPFW_BENCH_WORKER") != "1" {
		t.Skip("benchmark subprocess")
	}
	peer, pair, m := fixture(t)
	backend := os.Getenv("EBPFW_BENCH_BACKEND")
	workload := os.Getenv("EBPFW_BENCH_WORKLOAD")
	rules, _ := strconv.Atoi(os.Getenv("EBPFW_BENCH_RULES"))
	rep, _ := strconv.Atoi(os.Getenv("EBPFW_BENCH_REP"))
	if rules < 1 || rules > 64 {
		t.Fatal("invalid benchmark size")
	}
	runtime.GOMAXPROCS(2)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var cpu unix.CPUSet
	cpu.Set(0)
	if e := unix.SchedSetaffinity(0, &cpu); e != nil {
		t.Fatal(e)
	}
	port := 54321
	var udp *net.UDPConn
	var listener net.Listener
	protocol := "udp"
	if strings.HasPrefix(workload, "tcp-") {
		protocol = "tcp"
		listener, port = echoListener(t, "tcp4", "192.0.2.1:0")
		_ = listener
	}
	if workload == "udp-established" {
		var e error
		udp, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: port})
		if e != nil {
			t.Fatal(e)
		}
		defer udp.Close()
		go func() {
			b := make([]byte, 256)
			for {
				n, a, e := udp.ReadFromUDP(b)
				if e != nil {
					return
				}
				udp.WriteToUDP(b[:n], a)
			}
		}()
	}
	if backend == "ufw" {
		setupUFW(t, workload, rules, port)
	} else if backend == "ebpf" {
		tables, e := (&nftables.Conn{}).ListTables()
		if e != nil {
			t.Fatal(e)
		}
		if len(tables) != 0 {
			t.Fatal("eBPF worker must have no nftables tables")
		}
		c := config.New()
		c.Enabled = true
		for i := 0; i < rules; i++ {
			r := config.Rule{Action: "deny", Protocol: protocol, Port: strconv.Itoa(1000 + i)}
			if i == rules-1 {
				r.Port = strconv.Itoa(port)
				if workload != "udp-drop" {
					r.Action = "allow"
				}
			}
			if workload == "early-source-drop" {
				r = config.Rule{Action: "block", Protocol: "any", Source: fmt.Sprintf("198.18.%d.0/24", i)}
				if i == rules-1 {
					r.Source = "192.0.2.2/32"
				}
			}
			c.Rules = append(c.Rules, r)
		}
		if e = m.Apply(c); e != nil {
			t.Fatal(e)
		}
		if workload == "early-source-drop" {
			if e = m.Accelerate(pair.Right.Name, "generic"); e != nil {
				t.Fatal(e)
			}
		}
	} else {
		t.Fatal("unknown benchmark backend")
	}
	count := func() (uint64, error) {
		if backend == "ufw" {
			chain := "ufw-user-input"
			if workload == "early-source-drop" {
				chain = "ufw-before-input"
			}
			return nftCount(chain, rules-1)
		}
		s, e := m.Status()
		if e != nil {
			return 0, e
		}
		if rules > len(s.RuleCounters) {
			return 0, fmt.Errorf("missing eBPF rule counters")
		}
		return s.RuleCounters[rules-1], nil
	}
	operations := 5000
	verified := uint64(0)
	messages, connections := uint64(0), uint64(0)
	var elapsed time.Duration
	switch workload {
	case "udp-drop", "early-source-drop":
		var fd, index int
		if e := peer.do(func() error {
			n, e := net.InterfaceByName(pair.Left.Name)
			if e != nil {
				return e
			}
			index = n.Index
			fd, e = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(binary.NativeEndian.Uint16([]byte{0, 3})))
			if e != nil {
				return e
			}
			return unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: index, Protocol: binary.NativeEndian.Uint16([]byte{0, 3})})
		}); e != nil {
			t.Fatal(e)
		}
		defer unix.Close(fd)
		ip := udpWire(4, "192.0.2.2", "192.0.2.1", 54320, uint16(port), bytes.Repeat([]byte{0x61}, 22), false)
		frame := make([]byte, 14)
		copy(frame, pair.Right.HardwareAddr)
		copy(frame[6:], pair.Left.HardwareAddr)
		binary.BigEndian.PutUint16(frame[12:], 0x0800)
		frame = append(frame, ip...)
		target := &unix.SockaddrLinklayer{Ifindex: index}
		send := func(n int) {
			t.Helper()
			for i := 0; i < n; i++ {
				if e := unix.Sendto(fd, frame, 0, target); e != nil {
					t.Fatal(e)
				}
			}
		}
		send(200)
		time.Sleep(10 * time.Millisecond)
		before, e := count()
		if e != nil {
			t.Fatal(e)
		}
		start := time.Now()
		send(operations)
		elapsed = time.Since(start)
		after, e := count()
		if e != nil {
			t.Fatal(e)
		}
		verified = after - before
		if verified != uint64(operations) {
			t.Fatalf("%s %s expected %d verified drops, got %d", backend, workload, operations, verified)
		}
	case "udp-established", "tcp-established":
		network := "udp4"
		operations = 1000
		if workload == "tcp-established" {
			network = "tcp4"
		}
		v, e := peerDial(peer, network, net.JoinHostPort("192.0.2.1", strconv.Itoa(port)), nil)
		if e != nil {
			t.Fatal(e)
		}
		defer v.Close()
		v.SetDeadline(time.Now().Add(20 * time.Second))
		payload := bytes.Repeat([]byte{0x61}, 64)
		reply := make([]byte, 64)
		exchange := func(n int) {
			t.Helper()
			for i := 0; i < n; i++ {
				if _, e := v.Write(payload); e != nil {
					t.Fatal(e)
				}
				if _, e := io.ReadFull(v, reply); e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(reply, payload) {
					t.Fatal("corrupt benchmark response")
				}
			}
		}
		exchange(100)
		start := time.Now()
		exchange(operations)
		elapsed = time.Since(start)
		messages = uint64(operations * 2)
	case "tcp-new":
		operations = 50
		address := net.JoinHostPort("192.0.2.1", strconv.Itoa(port))
		exchange := func(n int) {
			t.Helper()
			for i := 0; i < n; i++ {
				v, e := peerDial(peer, "tcp4", address, nil)
				if e != nil {
					t.Fatal(e)
				}
				v.SetDeadline(time.Now().Add(time.Second))
				if _, e = v.Write([]byte("new")); e != nil {
					v.Close()
					t.Fatal(e)
				}
				b := make([]byte, 3)
				if _, e = io.ReadFull(v, b); e != nil || string(b) != "new" {
					v.Close()
					t.Fatal(e)
				}
				v.Close()
			}
		}
		exchange(5)
		messages = uint64(operations * 2)
		connections = uint64(operations)
		start := time.Now()
		exchange(operations)
		elapsed = time.Since(start)
	default:
		t.Fatal("unknown benchmark workload")
	}
	var uname unix.Utsname
	unix.Uname(&uname)
	sample := benchmarkSample{Backend: backend, Workload: workload, Rules: rules, Repetition: rep, Operations: operations, NSPerOperation: float64(elapsed.Nanoseconds()) / float64(operations), VerifiedPackets: verified, VerifiedPayloadMessages: messages, CompletedConnections: connections, Kernel: unix.ByteSliceToString(uname.Release[:]), Architecture: runtime.GOARCH}
	b, _ := json.Marshal(sample)
	fmt.Println("EBPFW_UFW_SAMPLE " + string(b))
}
func TestDirectUFWBenchmark(t *testing.T) {
	if os.Getenv("EBPFW_UFW_BENCH") != "1" {
		t.Skip("set EBPFW_UFW_BENCH=1 for explicit performance runs")
	}
	requireVM(t)
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	reps := 5
	if value := os.Getenv("EBPFW_BENCH_REPS"); value != "" {
		reps, e = strconv.Atoi(value)
		if e != nil || reps < 1 || reps > 20 {
			t.Fatal("invalid repetition count")
		}
	}
	for _, workload := range []string{"udp-drop", "udp-established", "tcp-established", "tcp-new", "early-source-drop"} {
		for _, rules := range []int{1, 16, 64} {
			for rep := 1; rep <= reps; rep++ {
				modes := []string{"ufw", "ebpf"}
				if rep%2 == 0 {
					modes[0], modes[1] = modes[1], modes[0]
				}
				for _, backend := range modes {
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					cmd := exec.CommandContext(ctx, exe, "-test.run=^TestBenchmarkWorker$", "-test.v", "-test.timeout=85s")
					cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS}
					cmd.Env = append(os.Environ(), "EBPFW_BENCH_WORKER=1", "EBPFW_BENCH_BACKEND="+backend, "EBPFW_BENCH_WORKLOAD="+workload, "EBPFW_BENCH_RULES="+strconv.Itoa(rules), "EBPFW_BENCH_REP="+strconv.Itoa(rep))
					out, e := cmd.CombinedOutput()
					cancel()
					if e != nil {
						t.Fatalf("%s %s %d: %v\n%s", backend, workload, rules, e, out)
					}
					found := false
					for _, line := range strings.Split(string(out), "\n") {
						if strings.HasPrefix(line, "EBPFW_UFW_SAMPLE ") {
							fmt.Println(line)
							found = true
						}
					}
					if !found {
						t.Fatal("benchmark worker did not return a verified sample")
					}
				}
			}
		}
	}
}
