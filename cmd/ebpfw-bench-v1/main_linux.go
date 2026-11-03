// SPDX-License-Identifier: Apache-2.0
// ebpfw-bench compares equivalent stateless rules on a private veth pair.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/duongddinh/ebpfw/internal/policy"
	engine "github.com/duongddinh/ebpfw/internal/runtime"
	"github.com/duongddinh/ebpfw/internal/testnet"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type sample struct {
	Rules              int     `json:"rules"`
	Mode               string  `json:"mode"`
	Repetition         int     `json:"repetition"`
	Packets            int     `json:"packets"`
	WallNSPerPacket    float64 `json:"wall_ns_per_packet"`
	CPUTimeNSPerPacket float64 `json:"sender_cpu_ns_per_packet"`
	VerifiedDrops      uint64  `json:"verified_drops"`
	ThrottledPeriods   uint64  `json:"throttled_periods"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func cpuTime() (int64, error) {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_PROCESS_CPUTIME_ID, &ts)
	return ts.Nano(), err
}

// A CPU safety quota must not masquerade as a datapath speed difference.
func throttled() (uint64, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		var mounts []string
		if parts[0] == "0" {
			mounts = []string{"/sys/fs/cgroup"}
		} else if strings.Contains(","+parts[1]+",", ",cpu,") {
			mounts = []string{"/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu"}
		}
		for _, mount := range mounts {
			data, e := os.ReadFile(filepath.Join(mount, parts[2], "cpu.stat"))
			if e != nil {
				continue
			}
			fields := strings.Fields(string(data))
			for i := 0; i+1 < len(fields); i += 2 {
				if fields[i] == "nr_throttled" {
					return strconv.ParseUint(fields[i+1], 10, 64)
				}
			}
		}
	}
	return 0, nil // No mounted quota controller, e.g. the minimal test VM.
}
func run() error {
	object := flag.String("object", "build/firewall.o", "BPF object path")
	packets := flag.Int("packets", 5000, "packets per sample (1..100000)")
	repetitions := flag.Int("repetitions", 5, "repetitions (1..20)")
	selectedModes := flag.String("modes", "nftables,generic,native", "comma-separated comparison modes")
	flag.Parse()
	// Guard before creating interfaces, maps, or firewall rules. Never benchmark
	// in a namespace containing an existing host or application interface.
	own, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if own == init {
		return errors.New("refusing the host network namespace: run under unshare --net")
	}
	ifaces, err := netInterfaces()
	if err != nil {
		return err
	}
	if ifaces != 1 {
		return errors.New("isolated namespace must contain only loopback")
	}
	if *packets < 1 || *packets > 100000 || *repetitions < 1 || *repetitions > 20 {
		return errors.New("invalid sample bounds")
	}
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	pair, err := testnet.New()
	if err != nil {
		return err
	}
	defer pair.Close()
	packet := pair.Packet(54321)
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF: %+v", err)
	}
	defer collection.Close()
	enc := json.NewEncoder(os.Stdout)
	modes := strings.Split(*selectedModes, ",")
	seen := map[string]bool{}
	for _, mode := range modes {
		if (mode != "nftables" && mode != "generic" && mode != "native") || seen[mode] {
			return errors.New("modes must be unique nftables, generic, or native entries")
		}
		seen[mode] = true
	}
	for _, count := range []int{1, 16, 64} {
		c := policy.New()
		c.Default = "allow"
		for i := 0; i < count; i++ {
			port := "1"
			if i == count-1 {
				port = "54321"
			}
			c.Rules = append(c.Rules, policy.Rule{Action: "deny", Protocol: "udp", Port: port})
		}
		if err = engine.Install(collection.Maps["active_policy"], spec.Maps["active_policy"].InnerMap, c, spec.ByteOrder); err != nil {
			return err
		}
		for rep := 0; rep < *repetitions; rep++ {
			// Rotate order across repetitions, avoiding a fixed warm/cold advantage.
			for k := 0; k < len(modes); k++ {
				mode := modes[(k+rep)%len(modes)]
				cleanup, drops, err := setup(mode, count, pair.Right.Index, pair.Right.Name, collection)
				if err != nil {
					return fmt.Errorf("%s: %w", mode, err)
				}
				result, err := measure(pair, packet, *packets, count, mode, rep, drops)
				cleanup()
				if err != nil {
					return err
				}
				if err = enc.Encode(result); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	return nil
}
func measure(pair *testnet.Pair, packet []byte, n, count int, mode string, rep int, drops func() (uint64, error)) (sample, error) {
	result := sample{Rules: count, Mode: mode, Repetition: rep + 1, Packets: n}
	// Refill a resource-limited service's CPU budget before each short burst.
	time.Sleep(250 * time.Millisecond)
	// Warm code/cache/queues, then establish the counter baseline.
	for i := 0; i < 200; i++ {
		if err := pair.Send(packet); err != nil {
			return result, err
		}
	}
	time.Sleep(time.Millisecond)
	before, err := drops()
	if err != nil {
		return result, err
	}
	beforeThrottle, err := throttled()
	if err != nil {
		return result, err
	}
	cpu, err := cpuTime()
	if err != nil {
		return result, err
	}
	start := time.Now()
	for i := 0; i < n; i++ {
		if err = pair.Send(packet); err != nil {
			return result, err
		}
	}
	elapsed := time.Since(start)
	afterCPU, err := cpuTime()
	if err != nil {
		return result, err
	}
	afterThrottle, err := throttled()
	if err != nil {
		return result, err
	}
	result.ThrottledPeriods = afterThrottle - beforeThrottle
	if result.ThrottledPeriods > 0 {
		return result, fmt.Errorf("%s: CPU quota throttled the timed sample; reduce --packets", mode)
	}
	// A run is valid only if all generated packets reached the intended drop.
	deadline := time.Now().Add(time.Second)
	var after uint64
	for {
		after, err = drops()
		if err != nil {
			return result, err
		}
		if after-before >= uint64(n) || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	result.VerifiedDrops = after - before
	if result.VerifiedDrops != uint64(n) {
		return result, fmt.Errorf("%s: expected %d drops, got %d", mode, n, result.VerifiedDrops)
	}
	result.WallNSPerPacket = float64(elapsed.Nanoseconds()) / float64(n)
	result.CPUTimeNSPerPacket = float64(afterCPU-cpu) / float64(n)
	return result, nil
}
func setup(mode string, count, index int, name string, col *ebpf.Collection) (func(), func() (uint64, error), error) {
	if mode != "nftables" {
		flags := link.XDPGenericMode
		if mode == "native" {
			flags = link.XDPDriverMode
		}
		l, err := link.AttachXDP(link.XDPOptions{Program: col.Programs["ebpfw"], Interface: index, Flags: flags})
		if err != nil {
			return nil, nil, err
		}
		read := func() (uint64, error) {
			var values []uint64
			if err := col.Maps["counters"].Lookup(uint32(1), &values); err != nil {
				return 0, err
			}
			var total uint64
			for _, v := range values {
				total += v
			}
			return total, nil
		}
		return func() { l.Close() }, read, nil
	}
	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyNetdev, Name: "ebpfw_bench"})
	chain := conn.AddChain(&nftables.Chain{Table: table, Name: "ingress", Hooknum: nftables.ChainHookIngress, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter, Device: name})
	for i := 0; i < count; i++ {
		port := uint16(1)
		if i == count-1 {
			port = 54321
		}
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, port)
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{8, 0}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBytes},
			&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop},
		}})
	}
	if err := conn.Flush(); err != nil {
		return nil, nil, err
	}
	cleanup := func() { conn.DelTable(table); conn.Flush() }
	read := func() (uint64, error) {
		rules, err := conn.GetRules(table, chain)
		if err != nil {
			return 0, err
		}
		var n uint64
		for _, r := range rules {
			for _, e := range r.Exprs {
				if c, ok := e.(*expr.Counter); ok {
					n += c.Packets
				}
			}
		}
		return n, nil
	}
	return cleanup, read, nil
}

// Keep syscall namespace detection independent of interface-name assumptions.
func netInterfaces() (int, error) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range b {
		if c == ':' {
			n++
		}
	}
	return n, nil
}
