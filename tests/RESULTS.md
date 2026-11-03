# Validation record — 2026-11-03

The expanded firewall passed the repository unit/race/vet checks and live
kernel tests in disposable ARM64 and x86-64 VMs. This is functional validation,
not an independent security audit or proof of complete UFW compatibility.

## Completed checks

- `make test`: Go race tests, vet, Python guest-archive traversal/symlink tests.
- Linux AMD64 cross-vet with CGO disabled.
- Config validation fuzzing: 10 seconds, 3,471,606 executions, no failure.
- Both architectures: real BPF verifier/load, six pinned Netfilter hooks,
  IPv4/IPv6 TCP and UDP request/reply, established flows surviving policy changes,
  outbound policy, address/port/interface selectors, per-source rate buckets,
  related ICMP errors, 1,024-rule live policy, invalid-update rejection, and
  out-of-order IPv4/IPv6 fragment reassembly with IPv6 extension parsing.
- Both architectures: generic XDP absolute blocks, duplicate ownership refusal,
  logging suspension of early acceleration, atomic block removal, TCP/UDP reject
  replies under outgoing deny, routed policy, interfaces created after enable,
  loopback, agent reload and SIGKILL with enforcement retained, sixteen
  concurrent streams, bounded-table expiry, foreign-pin protection, and actual
  TCP Fast Open data in SYN verified by a datapath counter.
- ARM64 additionally: reject-packet TCP/ICMP checksums and suppression of reset
  replies/multicast, plus malformed-packet fuzz seeds.
- Direct real-UFW benchmark: 150 trials, exact drop counters and application
  reply checks, followed by the live suite. See
  [the benchmark report](../benchmarks/stateful-ufw.md).
- Reconstructed the ARM64 Debian/UFW guest root from the checked-in digest lock.

The local pinned tools were Go 1.26.6, Clang 21.1.8, and QEMU 10.2.4.
Staged installation into a temporary directory also passed; it enabled no service.

## Evidence and environment

- [ARM64 functional log](evidence/vm-arm64.log): Linux 6.12.114-0-virt, QEMU/HVF,
  two vCPUs, 1,536 MiB RAM, no external NIC; final marker `EBPFW_FULL_VM_PASS`.
- [AMD64 functional log](evidence/vm-amd64.log): same kernel version, QEMU/TCG,
  two vCPUs, 1,536 MiB RAM, no external NIC; final marker `EBPFW_FULL_VM_PASS`.
- [UFW trial and functional log](evidence/ufw-benchmark-arm64.log).

The VM runner builds static guest binaries, downloads verified official kernel
assets, and extracts verified Debian packages only into its guest cache. It
mounts fresh bpffs in the guest. Netfilter conntrack is not loaded for the eBPF
functional suite; UFW can autoload it for its own benchmark workers. No host
interface or host firewall participates in these measurements.

## Physical hosts

The older Debian camera machine runs Linux 5.10 and cannot run the new
Netfilter-BPF datapath. Its prior v0.1 XDP test is historical evidence only.

The second camera is a Raspberry Pi 3 Model B Plus with Debian 13 and
Linux 6.18.34+rpt-rpi-v8. Its configuration has `CONFIG_DEBUG_INFO_NONE=y` and
no `/sys/kernel/btf/vmlinux`. The static CLI executed successfully; policy dry
run passed and `doctor` correctly refused missing BTF. Link/route fingerprints
were unchanged, no policy was written, temporary files were removed, and no
services were failed before/after. No package, module, boot, camera, or host
firewall change was made. **The stateful datapath was not tested on this Pi.**
See [BTF compatibility and the kernel preparation notes](../docs/kernel-btf.md).

## Remaining validation limits

No physical-NIC stateful benchmark, native driver XDP throughput test,
independent TCP adversarial/security audit, NAT/helper compatibility, Pi custom
kernel/camera-driver validation, or full upstream UFW conformance suite was
performed. No production deployment was made. See the README for supported
semantics and bounded resource behavior.

GitHub Actions is configured to repeat build/unit and private-namespace live
checks; a manual input additionally runs the direct UFW benchmark. Its remote
result must be assessed separately from the local evidence above.
