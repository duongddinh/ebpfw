# Measured performance — 2026-11-03

Generic XDP was faster at the median with larger sequential rulesets in this
test. It did not improve the one-rule case. These are exploratory measurements,
with substantial variation; they do not establish a universal speedup over UFW.

## Real Linux hardware

Debian, Linux `5.10.0-0.deb10.16-amd64`, Intel Core i5-4210U (two cores/four
threads), 4 GB RAM, BPF JIT enabled. The host continued its existing workloads.
The test process was pinned to CPU 0, at nice 19, with a quota of 25% of one CPU,
192 MB memory limit, and a 90-second deadline. No timed sample had a CPU quota
throttling event. The full transient service took 34.767 seconds.

Each cell is the median of 15 samples, with 256 injected frames per sample.
Lower is better. Times include packet generation syscalls and the virtual
network path, rather than measuring the filter instructions alone.

| Rules | nftables µs/frame | ebpfw generic XDP µs/frame | Ratio nftables / ebpfw |
| ---: | ---: | ---: | ---: |
| 1 | 5.076 | 5.364 | 0.95× |
| 16 | 7.102 | 5.549 | 1.28× |
| 64 | 12.619 | 5.443 | 2.32× |

The ranges overlap substantially. For example, the 64-rule samples ranged from
3.714–17.435 µs/frame for nftables and 1.818–6.241 µs/frame for ebpfw. Host activity,
CPU power management, caches, and scheduling contribute to this variation. These
median ratios are observations, not statistically established improvement claims.

All **23,040 measured frames** were verified against the intended drop counters.
The raw samples are in [hardware-2026-11-03.jsonl](hardware-2026-11-03.jsonl).

Native XDP on this host's veth pair failed the zero-loss check during a longer
burst: only 744 of 2,000 frames reached the program's drop counter. That sample
was rejected. It cannot be used as evidence for native XDP performance. Physical
NIC native-XDP performance was not tested.

An earlier long-burst exploration is retained in
[hardware-long-bursts-2026-11-03.jsonl](hardware-long-bursts-2026-11-03.jsonl).
It used 2,000 frames/sample, included counter-read overhead in wall time, and
could hit the CPU quota. It is **excluded** from the table above. The final
harness uses shorter bursts, excludes counter-query time, and rejects samples
with quota-throttling events.

## Isolated Linux VM

QEMU 11.1.2, software-emulated x86-64 on an Apple ARM64 Mac, `-cpu max`, one vCPU,
512 MB RAM, Alpine Linux 6.12.114-0-virt. There was no physical network device.
Each cell is the median of seven samples with 5,000 frames/sample.

| Rules | nftables µs/frame | Generic XDP µs/frame | Native XDP on veth µs/frame |
| ---: | ---: | ---: | ---: |
| 1 | 10.943 | 13.729 | 12.113 |
| 16 | 13.957 | 14.233 | 12.779 |
| 64 | 23.590 | 14.920 | 13.525 |

All 315,000 measured frames passed the counter check. See
[vm-2026-11-03.jsonl](vm-2026-11-03.jsonl). Emulator timings are useful for
checking the harness and exploring rule-count scaling, not predicting NIC
throughput. Results from different environments should not be directly compared.

The same VM also passed kernel verifier, packet semantics, live attachment,
policy reload/rejection, duplicate ownership, and detach/restart tests.

## Method

- Each invocation requires a private network namespace containing only loopback.
  It creates its own veth pair and refuses the host network namespace.
- Frames are 64-byte Ethernet/IPv4/UDP packets (excluding FCS), destination port
  54321. The last rule drops them; preceding rules target nonmatching port 1.
- nftables uses a `netdev` ingress chain, IP/UDP/destination-port checks, a drop
  counter, and a drop verdict. ebpfw uses the same ordered drop rules with a
  default allow policy. The policies are equivalent for these valid test frames;
  the programs have different semantics for other packet types.
- Rule counts are 1, 16, and 64. Mode order rotates between repetitions.
- Each sample has a 250 ms cooldown and 200 warmup frames before timing.
- The timed interval covers the send loop. Drop counters are read afterward to
  reject loss or a filter that was not actually exercised. Counter queries and
  setup are outside the final timing interval.
- `sender_cpu_ns_per_packet` measures the generating process, not total system
  CPU usage. It does not account for processing charged to other kernel threads.
- This is a single-stream, last-rule-drop microbenchmark. It does not measure
  physical-NIC line rate, latency distributions, allowed traffic, mixed flows,
  IPv6 workloads, DDoS capacity, or stateful connection tracking.
- UFW itself was not installed or changed. These results compare an equivalent
  stateless nftables chain, not UFW's complete generated ruleset.
- No host interface or host firewall was modified. The real host's interface and
  route fingerprints matched before and after. No failed systemd services were
  observed before or after, and all uploaded test files were removed.

## Reproduce on a disposable Linux host

Build with the repository's pinned Nix shell or existing Go/LLVM tools:

```sh
make all build/ebpfw-bench
sudo unshare --net ./build/ebpfw-bench \
  --object ./build/firewall.o --packets 256 --repetitions 15 \
  --modes nftables,generic > results.jsonl
python3 benchmarks/summarize.py results.jsonl
```

Use `--modes nftables,generic,native` only where native veth XDP is supported and
passes the drop-count check. Reduce `--packets` if the generator overruns the
virtual receive path. The tool rejects loss rather than treating missing packets
as successful filtering.

For the hardware safety envelope, run the command through a transient systemd
unit with `CPUQuota=25%`, `CPUAffinity=0`, `MemoryMax=192M`, `Nice=19`,
`RuntimeMaxSec=90s`, `TasksMax=32`, and `LimitMEMLOCK=infinity`. The tool detects
quota stalls through common cgroup v1/v2 `cpu.stat` paths. On systems without a
mounted quota controller, that check is unavailable. Existing workload contention
can still affect results even when the quota check passes.
