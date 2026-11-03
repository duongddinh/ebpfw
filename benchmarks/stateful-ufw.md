# Stateful ebpfw against real UFW — 2026-11-03

These measurements were collected from commit `fef330d` with Clang 21.1.8,
before the subsequent Clang 18 portability repair. The raw samples and object
hash below identify that measured build.

This compares the stateful eBPF program against **UFW 0.36.2**, executed
through the real UFW CLI. UFW used `iptables 1.8.9 (nf_tables)`, so nftables and
Linux conntrack implement UFW's rules. The ebpfw worker verified that no nftables
tables were installed; ebpfw uses its own BPF flow maps. The nftables Go library
in the benchmark reads/verifies UFW counters; it is not the ebpfw policy backend.

The VM measured faster drops for ebpfw. Established traffic showed overlapping
ranges and mixed results, including slower ebpfw TCP medians at 1 and 16 rules.
There is no consistent accepted-traffic speedup demonstrated by these trials.

## Environment and method

- Apple M5 host, 10 CPU cores, 16 GiB RAM, macOS 26.6.2.
- QEMU 10.2.4, native ARM64 via HVF, two vCPUs, 1,536 MiB guest RAM, no external NIC.
- Alpine Linux `6.12.114-0-virt` kernel, digest pinned in `tests/vm_runner.py`.
- Debian bookworm guest userspace and package digests in
  [the ARM64 fixture](../tests/fixtures/debian-arm64.json).
- Go 1.26.6, Clang 21.1.8 from the pinned Nix environment.
- BPF object SHA256: `fa10db11f7d2d4612ba67af1aeea0d0d7dea71700b4b613b94ba8650ea496f85`.
- Each backend/trial is a fresh subprocess in private network and mount
  namespaces, with its own veth pair, policy, and UFW configuration files.
- Five repetitions, alternating backend order, at 1, 16, and 64 configured rules:
  **150 measured trials**, plus warmups. The sender thread is pinned to vCPU 0.
- Logging is off for both backends. Incoming/routed defaults deny, outgoing
  allows. Normal cases have nonmatching leading port rules and the tested rule
  last. Established paths use state tracking in both backends.
- Drop cases inject 5,000 valid 64-byte Ethernet frames per trial after a
  200-frame warmup; the intended drop counter must increase by exactly 5,000.
- Established UDP/TCP cases exchange and verify 1,000 64-byte application
  payload round trips after 100 warmups. Packet counts are **not** inferred from
  TCP application messages. Timings include both directions and application I/O.
- New TCP cases measure 50 connect/echo/close operations after five warmups;
  connection success and echoed data are checked. Both backends include their
  state allocation and TCP stack work.
- Early-source-drop uses optional **generic XDP on veth**, against equivalent UFW
  `before.rules` source drops in input/output/forward before UFW's established
  acceptance rules. These are absolute source blocks; normal UFW user deny
  rules do not override established flows. UFW still traverses kernel hooks
  earlier than its filter rules, including conntrack when loaded.

Lower time is better. Ratios above 1 favor ebpfw. Each range shows the minimum
and maximum of five samples, not a confidence interval. Drop timings include
packet-send syscalls and veth processing; they are not isolated program cycles.
| Workload | Rules | UFW median [min, max] µs | ebpfw median [min, max] µs | UFW / ebpfw |
|---|---:|---:|---:|---:|
| early-source-drop | 1 | 0.605 [0.600, 0.621] | 0.514 [0.509, 0.519] | 1.18× |
| early-source-drop | 16 | 0.680 [0.671, 0.708] | 0.520 [0.517, 0.551] | 1.31× |
| early-source-drop | 64 | 0.927 [0.917, 0.964] | 0.520 [0.512, 0.520] | 1.78× |
| tcp-established | 1 | 38.238 [37.555, 45.370] | 41.326 [38.559, 45.168] | 0.93× |
| tcp-established | 16 | 38.541 [37.826, 41.980] | 41.227 [37.794, 41.756] | 0.93× |
| tcp-established | 64 | 38.254 [37.811, 38.373] | 37.951 [37.305, 38.796] | 1.01× |
| tcp-new | 1 | 71.782 [69.115, 75.516] | 72.278 [71.164, 82.856] | 0.99× |
| tcp-new | 16 | 73.453 [72.045, 75.467] | 70.537 [68.582, 71.395] | 1.04× |
| tcp-new | 64 | 73.782 [71.743, 79.862] | 74.104 [69.509, 75.015] | 1.00× |
| udp-drop | 1 | 0.701 [0.686, 0.705] | 0.573 [0.570, 0.586] | 1.22× |
| udp-drop | 16 | 0.778 [0.768, 0.784] | 0.614 [0.607, 0.622] | 1.27× |
| udp-drop | 64 | 1.001 [0.984, 1.024] | 0.739 [0.733, 0.753] | 1.35× |
| udp-established | 1 | 36.612 [32.502, 37.612] | 36.928 [36.502, 41.228] | 0.99× |
| udp-established | 16 | 36.197 [36.110, 37.096] | 36.913 [36.130, 37.745] | 0.98× |
| udp-established | 64 | 36.702 [36.043, 36.949] | 36.548 [36.323, 37.650] | 1.00× |

The time unit is µs/frame for drop workloads, µs/application round trip for
established workloads, and µs/connect+echo+close for new TCP. Do not compare
numbers between these different units as firewall instruction costs.

All **300,000 measured drop frames** matched their counters. Established cases
verified 60,000 round trips; new-TCP cases verified 1,500 completed connections.
Warmups are additional and excluded from those totals. Raw samples are in
[stateful-ufw-arm64-2026-11-03.jsonl](stateful-ufw-arm64-2026-11-03.jsonl), with
[the complete guest log](../tests/evidence/ufw-benchmark-arm64.log).

These are local VM/veth results with a small sample count. Host scheduling,
power state, virtualization, caches, and syscall/application overhead affect
measurements. There is no physical-NIC line-rate, saturation, CPU-efficiency, or
camera-host performance claim. The eBPF TCP implementation and Linux conntrack
are also not identical security implementations. These results do not prove
full UFW compatibility or recommend replacing an established production firewall.

Reproduce in the pinned Nix shell:

```sh
python3 tests/vm_runner.py --benchmark --arch arm64
python3 tests/summarize_benchmark.py .cache/vm/arm64-benchmark.jsonl
```

Native ARM64 acceleration matters: do not compare TCG-emulated x86 timings with
these HVF measurements. Re-run on the intended hardware/workload to make a
production performance decision. The previous stateless v0.1 nftables-only
results remain [historical evidence](README.md).
