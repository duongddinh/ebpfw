# ebpfw

A UFW-style Linux firewall with stateful **eBPF enforcement** for incoming,
outgoing, and routed IPv4/IPv6 traffic. Optional XDP acceleration drops explicit
source blocks before the normal network stack. Accepted local traffic still
uses Linux TCP/IP.

This is experimental firewall software, not an audited drop-in UFW replacement.
Test policies in a VM with console access before deploying them. The current
implementation requires **Linux 6.6 or later**, kernel BTF, bpffs, Netfilter BPF
links, IP defragmentation support, and skb dynptr helpers. Actual feature support
is checked by the kernel verifier at enable time. Linux 5.10 cannot run this mode.
[BTF compatibility notes](docs/kernel-btf.md) explain why an external BTF download
alone cannot enable a kernel built without it.

## Enforcement

Six pinned BPF links cover IPv4/IPv6 input, output, and forwarding, including
loopback and interfaces/tunnels created after enable. The Netfilter hooks are
kernel attachment points; ebpfw installs **no nftables rules and uses no Netfilter
conntrack state**. Its own BPF maps track flows. Linux provides IP reassembly,
routing, and the socket stack. Existing host firewalls can impose additional
restrictions on packets ebpfw accepts.

Policy includes:

- Ordered allow, deny, reject, and TCP connection-limit rules; up to 16,384 rules.
- Independent incoming, outgoing, and routed defaults.
- Source/destination IPv4/IPv6 CIDRs, source/destination ports and ranges, service
  names, protocol and interface selectors, comments, numbered insertion/deletion.
- Stateful TCP, UDP, ICMP echo, related ICMP errors, and generic IP replies.
- IPv4/IPv6 fragment reassembly and bounded IPv6 extension parsing.
- Built-in/custom application profiles, dry runs, validation, JSON status,
  per-rule counters, bounded packet metadata logs, and persistent configuration.
- Atomic rule-table swaps; invalid updates retain the last valid policy.
- Kernel enforcement survives management-agent exit or crash through bpffs pins.

Established flows continue after ordinary allow rules are removed. Use
`block from CIDR` for an absolute source block that preempts existing state.
Optional XDP acceleration applies only to these blocks; it pauses when packet
logging is enabled so the authoritative hooks can record events.

## Build and install

```sh
nix develop
make all test
sudo make install
sudo systemctl daemon-reload
```

The Nix flake pins development tools. Alternatively use Go 1.25+, Clang with the
BPF backend (Clang 18+), Python 3, and Make. The stateful build explicitly
targets eBPF ISA v3 (`-mcpu=v3`), required for its 32-bit atomics. Little-endian
x86-64/ARM64 are tested targets.
macOS supports policy editing and VM tests; enforcement requires Linux.
`make install` copies files and does not enable filtering.

Mount bpffs at `/sys/fs/bpf` using your distribution's persistent mount
configuration, then check `sudo ebpfw doctor`. The policy is stored at
`/etc/ebpfw/rules.json`. A new configuration starts **disabled**, with incoming
and routed deny, outgoing allow. Review access rules before enabling:

```sh
sudo ebpfw allow OpenSSH
sudo ebpfw allow 443/tcp
sudo ebpfw allow proto icmp
sudo ebpfw allow proto icmpv6
sudo ebpfw default deny incoming
sudo ebpfw default allow outgoing
sudo ebpfw check
sudo ebpfw --dry-run enable
sudo ebpfw enable
sudo ebpfw status verbose
sudo ebpfw stats
```

Before applying defaults, ebpfw permits loopback, local IPv6 neighbor/router
discovery (types 133–136, code zero, hop limit 255), and incoming DHCP server
replies. Explicit rules, including absolute blocks, take precedence over these
base allowances. There is no automatic SSH exception. A port without a protocol
means TCP. IPs may be single addresses or CIDRs.

```sh
sudo ebpfw allow in on eth0 proto tcp from 192.0.2.0/24 to any port 8443
sudo ebpfw allow out proto udp to 198.51.100.53 port 53
sudo ebpfw route allow in on lan0 out on wan0 proto tcp to any port 443
sudo ebpfw limit 22/tcp rate 12/minute burst 6
sudo ebpfw reject 23/tcp
sudo ebpfw block from 203.0.113.0/24
sudo ebpfw accelerate eth0 native  # explicit, optional; generic also supported
sudo ebpfw insert 1 allow 2222/tcp
sudo ebpfw delete 3
sudo ebpfw app set Cameras 554/tcp 8554/tcp
sudo ebpfw allow Cameras
sudo ebpfw app update Cameras
sudo ebpfw logging on
sudo ebpfw reload
sudo ebpfw disable
```

`ebpfw help` lists the grammar. `--config`, `--object`, and `--pin-root` select
alternate files/namespace-specific pins. Flags precede the command. Foreground
`ebpfw run` restores enabled policy, watches for valid file changes, expires
state, and handles logs/replies. Installed `enable` starts `ebpfw.service` for the
default configuration. `disable` explicitly removes owned links/maps; stopping
the service alone leaves enforcement active. After reboot, the service restores
policy before normal networking; pins do not survive reboot.

The former v0.1 JSON policy migrates into the new schema with enforcement
**disabled** for review. Legacy XDP links must be stopped before switching. A
changed BPF object is refused against existing pins: review the new policy and
schedule an explicit disable/enable upgrade, which has an enforcement gap.
Do not remove pins manually while the firewall is active.

## Boundaries

This implements the common UFW policy model, not every UFW command or Linux
firewall facility. There is no NAT, connection-helper/ALG support, bridge-layer
firewall, user/group matching, MAC/VLAN policy, IPsec policy matching, or UFW
configuration-file compatibility. Limit uses a per-source token bucket rather
than UFW's exact recent-connection window. SCTP and other protocols use generic
flow state rather than protocol-specific association validation.

TCP state checks handshake, sequence/ack windows, retransmissions, FIN/RST and
Fast Open, but is a new implementation with less validation than Linux
conntrack. It has not undergone an independent security audit. IPv6 jumbograms
and extension chains beyond 32 headers are unsupported. Checksums are ultimately
validated by Linux; malformed traffic can consume bounded state resources.

The flow table holds 65,536 entries; the limiter holds 16,384 source/rule entries.
When state cannot be allocated, new stateful traffic fails closed. The agent
reclaims expired entries every ten seconds; kernel timeout checks also reject
expired state. Established TCP idle timeout is five days. A stopped agent leaves
filtering active but stops garbage collection, logs, and reject replies; check
`status` for its heartbeat.

Reject verdicts always drop in eBPF. The event agent sends best-effort TCP RST or
ICMP administrative-prohibited replies, limited to 50/s per CPU with burst 100;
ring pressure or a stopped agent can suppress replies. Logs contain metadata,
not packet bodies, and are bounded to two 4 MiB files per namespace in `/run/ebpfw`.
Logging is limited to five events/s per rule per CPU. Status exposes lost-event,
state-full, rate-limit, reply-limit and other counters.

## Tests and performance

```sh
make test
python3 tests/vm_runner.py                 # isolated QEMU VM, no external NIC
python3 tests/vm_runner.py --arch amd64    # cross-architecture testing via TCG
python3 tests/vm_runner.py --benchmark     # real UFW, 150 verified trials
```

Run these inside `nix develop`. VM assets and Debian packages are digest pinned;
files are extracted only into a guest cache, never installed on the host. Native
macOS uses HVF, native Linux uses KVM when accessible, otherwise QEMU uses TCG.
Alpine's netboot URLs are mutable: a changed upstream asset fails its pinned hash
and requires a reviewed fixture update. Kernel files are GPL-distributed guest
assets downloaded on demand, not included in this repository.

On a **disposable Linux host**, `sudo tests/run-isolated.sh env
EBPFW_FULL_TEST=1 EBPFW_OBJECT="$PWD/build/stateful.o"
EBPFW_BINARY="$PWD/build/ebpfw" "$PWD/build/full.test" -test.v` runs the live
suite in private network/mount namespaces with private bpffs and `/run`.
GitHub Actions runs build/race/vet/archive safety tests and the live suite on an
isolated Ubuntu runner. A manually requested benchmark additionally runs real
UFW in private namespaces. Workflows do not deploy this firewall to your hosts.

See [the direct UFW results](benchmarks/stateful-ufw.md) and
[validation coverage](tests/RESULTS.md). Early drops can save stack work; accepted
local traffic cannot skip its socket stack. The measurements do not establish a
universal performance advantage or physical-NIC line rate. The older
[nftables comparison](benchmarks/README.md) measures the historical stateless
v0.1 program, not this implementation.

## License

Go/Python code: Apache-2.0. BPF C: GPL-2.0-only. See `LICENSE` and `bpf/LICENSE`.
