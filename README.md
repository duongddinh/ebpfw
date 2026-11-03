# ebpfw

A small Linux ingress firewall with UFW-style commands and an eBPF/XDP packet
filter. Rules run in the kernel; no packet traffic passes through the Go daemon.

**Early-stage software.** This version is a stateless ingress filter, with no
connection tracking, outbound rules, NAT, or application profiles. It does not
yet replace UFW. A default-deny policy also drops replies to outbound connections
unless rules explicitly permit them. Test on a disposable host before deployment.

## What works

- Ordered `allow` and `deny` rules; the first matching rule wins.
- IPv4/IPv6 source CIDRs, TCP/UDP destination ports and ranges, ICMP/ICMPv6.
- Up to 64 rules, one shared policy across explicitly selected interfaces.
- Native XDP and explicitly selected generic XDP mode.
- Atomic policy swaps using a map of maps: packets see a complete old or new policy.
- Policy persistence, automatic reloads, systemd startup, and per-CPU counters.
- Refusal to replace an existing XDP program, including another ebpfw instance.

## Build

Use Linux 5.10+ with BPF/XDP enabled, Go 1.25+, LLVM/Clang 11+ with the BPF backend,
and systemd for `enable`/`disable`. The filter has run on Linux 5.10 and 6.12;
the complete kernel and live lifecycle tests passed on 6.12.
The CLI's policy commands also work on macOS, but enforcement requires Linux.

The development shell pins tools through Nix:

```sh
nix develop
make all test
```

Or use existing Go, Clang, and Make installations:

```sh
make all test
sudo make install
sudo systemctl daemon-reload
```

`make install` installs the binary, BPF object, and systemd template. It does not
start a firewall or change existing rules. The defaults use little-endian BPF
(`bpfel`), covering x86-64 and common ARM64 Linux systems. For a big-endian target,
build with `make BPF_ENDIAN=bpfeb`; the daemon reads the object's byte order.

## Try it

First identify the interface with `ip link`. These commands demonstrate an
allow-by-default prefilter on `eth0`, blocking Telnet and an example source CIDR:

```sh
sudo ebpfw default allow
sudo ebpfw deny 23/tcp
sudo ebpfw deny from 192.0.2.0/24
sudo ebpfw check
sudo ebpfw status
sudo ebpfw enable eth0
sudo ebpfw stats eth0
sudo ebpfw disable eth0
```

When creating a new configuration, the initial default is **deny**. Set your
intended default explicitly before enabling. `status` shows the saved policy;
`systemctl status ebpfw@eth0` shows whether enforcement is running.

More rule examples:

```sh
sudo ebpfw allow 22/tcp from 10.0.0.0/8
sudo ebpfw allow 443/tcp
sudo ebpfw allow 8000:8100/tcp
sudo ebpfw allow 53/udp from 2001:db8::/32
sudo ebpfw allow proto icmp
sudo ebpfw allow proto icmpv6
sudo ebpfw delete 3
```

Bare ports mean TCP. Use CIDR syntax for sources, including `/32` or `/128`
for one host. Rules append at the end; an earlier matching rule takes precedence.
Ports match the destination port. `deny` drops silently; there is no reject action.
Malformed policies are rejected. File updates use a writer lock, `fsync`, and
atomic rename. Running instances check for edits once per second and retain the
last valid policy on reload failure. `stats` reports reload errors as well as
passed, denied, and malformed/unsupported packet counts since daemon startup.

For generic mode, set `/etc/ebpfw/ebpfw.env` before enabling the unit:

```sh
echo EBPFW_MODE=generic | sudo tee /etc/ebpfw/ebpfw.env
```

Or run in the foreground without systemd:

```sh
sudo ebpfw --config ./rules.json run --interface eth0 \
  --mode generic --object ./build/firewall.o
```

## Packet semantics and boundaries

The XDP hook runs on incoming Ethernet frames, before the regular network stack.
It affects both traffic addressed to the host and traffic it forwards. Only
interfaces explicitly passed to `run` or `enable` are covered. Loopback is
unsupported. Other interfaces, tunnels created later in the stack, and outbound
traffic require their own security controls. Existing nftables/UFW rules can
still filter packets passed by ebpfw.

The parser handles up to two VLAN tags. ARP and other non-IP EtherTypes pass.
Malformed packets, IPv4 fragments, IPv6 extension headers (including fragments
and IPsec), and more than two VLAN tags drop **regardless of the default policy**.
IPv6 jumbograms are unsupported. This conservative behavior avoids port-rule
evasion but limits compatibility with fragmentation, some IPv6 paths, and VPNs.
NIC VLAN stripping can remove tags before XDP; ebpfw has no VLAN-specific rules.
Checksums are left to the network stack.

There are no automatic exceptions for SSH, DHCP, DNS replies, or IPv6 neighbor
discovery. With default deny, explicitly allow needed ICMPv6 to preserve IPv6
neighbor discovery and path MTU handling, and account for return traffic. Allowing
an ephemeral port range is not equivalent to connection tracking. Keep console
access while testing policies that could block remote administration.

The daemon owns an unpinned BPF link. Stopping it or a process crash detaches the
filter: this is **fail-open**. Systemd restarts failed instances, but enforcement
has gaps at startup and during restarts. This is not a boot-time security boundary.
The root-owned Unix socket exposes counters only. No production infrastructure
configuration or Kubernetes integration is included.

## Performance

Native XDP can drop packets early in the driver receive path, avoiding later
network-stack work. Generic XDP runs later and has different costs. This version
scans at most 64 rules, so cost grows with the number and position of rules.
See [measured results and limitations](benchmarks/README.md) for a comparison
with equivalent stateless nftables rules. This does not establish performance
against UFW's complete stateful ruleset or on a physical NIC. Measure your own
workload before choosing a firewall for performance.

## Tests

```sh
make test build/kernel.test      # CLI, strict validation, persistence, races, vet
sudo env PATH="$PATH" make test-kernel  # verifier, packets, live veth, reload, detach
```

Privileged tests belong on a disposable Linux machine. The integration test
creates and deletes its own veth pair; it does not attach to an existing NIC.
GitHub Actions runs the build, unit tests, kernel tests, and live integration.

## License

Go code: Apache-2.0. BPF C code: GPL-2.0-only. See `LICENSE` and `bpf/LICENSE`.
