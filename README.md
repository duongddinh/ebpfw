# ebpfw

A UFW-style Linux firewall with stateful eBPF rules for incoming, outgoing, and
routed IPv4/IPv6 traffic. It tracks connections in BPF maps and installs no
nftables rules. Optional XDP acceleration drops explicit source blocks early;
accepted local traffic still uses Linux TCP/IP.

> [!WARNING]
> **EXPERIMENTAL FIREWALL — NOT INDEPENDENTLY SECURITY AUDITED.**
> Bugs or incorrect rules can allow unwanted traffic, disconnect SSH, or disrupt
> cameras, applications, and routing. This includes a new connection-tracking
> implementation. Test in a disposable VM and keep console/recovery access before
> enabling it. Do not rely on ebpfw as your only protection for a production host.
>
> **Installing a package is not a security certification.** Filtering stays disabled
> until you explicitly enable it. VM benchmark results do not establish faster
> accepted traffic, physical-NIC throughput, or a general speed advantage over UFW.
> The software is provided without warranty under the bundled licenses.

Requires Linux 6.6+, kernel BTF, bpffs, Netfilter BPF
links, and IP defragmentation support. Check with `sudo ebpfw doctor`. A kernel
without `/sys/kernel/btf/vmlinux` needs a BTF-enabled kernel; installing headers
or downloading an external BTF file is insufficient for this implementation.
Test in a VM before using it on a production host.

## Debian / Ubuntu packages

Signed packages are available for **amd64 and arm64** at
**https://packages.cytizennetworks.com**. The `stable` channel name describes the
APT repository, not production readiness. The Linux/kernel requirements above
still apply; installation does not upgrade your kernel.

Download and review the setup script, then run it:

```sh
curl --proto '=https' --tlsv1.2 -fsSLO https://packages.cytizennetworks.com/install.sh
less install.sh
sudo sh install.sh
```

The script checks basic kernel/BTF prerequisites, installs a repository-specific
key and APT source, and runs `apt-get install ebpfw`. It does not change your kernel
or enable the firewall. Package clients do not need Go or Clang.
Use `sudo ebpfw doctor`, allow administration traffic, and review the policy
before enabling. A successful package install does not prove kernel compatibility.

The public `0.2.0~rc1` ARM64 package was installed using the setup script and manual APT instructions on
Ubuntu 24.04.5, Linux 6.8.0-147-generic, in a disposable QEMU VM. Kernel tests,
systemd activation, active-package guards, reinstall, removal, and purge passed.
This does not establish compatibility with other kernels or architectures.

### Manual APT setup

Install the download/key tools and inspect the repository's public key:

```sh
sudo apt update
sudo apt install ca-certificates curl gnupg
key_file="$(mktemp)"
curl --proto '=https' --tlsv1.2 -fsSL \
  https://packages.cytizennetworks.com/repository.asc -o "$key_file"
gpg --show-keys --fingerprint "$key_file"
```

Verify that the primary key fingerprint is exactly:

```text
4779 D597 2453 95AE 746D 7E3A 7B89 769C ECF2 9882
```

Then add the repository with a key scoped to this APT source:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 "$key_file" /etc/apt/keyrings/cytizen-ebpfw.asc
rm -f "$key_file"
sudo tee /etc/apt/sources.list.d/cytizen-ebpfw.sources >/dev/null <<EOF
Types: deb
URIs: https://packages.cytizennetworks.com/debian
Suites: stable
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/cytizen-ebpfw.asc
EOF
sudo apt update
sudo apt install ebpfw
sudo ebpfw doctor
sudo ebpfw check
```

Review rules and administration access before following the explicit enable
example below. Installation leaves the policy disabled and the service inactive.

### Upgrade and remove

Packages preserve `/etc/ebpfw/rules.json` across upgrades. Disable ebpfw in every
using network namespace before upgrading or removing: maintainer scripts refuse
to replace the eBPF object or remove files while pinned state or an enabled policy
remains. Review and explicitly re-enable after an upgrade. No automatic service
start or restart occurs during package installation.

```sh
sudo ebpfw disable
sudo apt update
sudo apt install --only-upgrade ebpfw
sudo ebpfw check
sudo ebpfw enable
```

To remove the package, disable it in every using network namespace first, then
run `sudo apt remove ebpfw`. Configuration remains for a later reinstall;
`sudo apt purge ebpfw` also removes the saved configuration.

Build packages locally with `make deb VERSION=0.2.0 ARCH=amd64` or `ARCH=arm64`
inside `nix develop`; Python 3 is also required outside Nix. Output is under
`build/packages/`. The package includes the compiled BPF object, so clients do
not need Go or Clang. Packaging is not distribution approval or a security audit.

## Build from source

```sh
git clone https://github.com/duongddinh/ebpfw.git
cd ebpfw
nix develop
make all test
sudo make install
sudo systemctl daemon-reload
```

Or use Go 1.25+, Clang 18+ with its BPF backend, and Make. Builds
explicitly target eBPF v3 for 32-bit atomics. Installation copies files and does
not start filtering. Mount bpffs at `/sys/fs/bpf` if needed and configure it to
mount at boot before enabling the firewall.
Use one installation method per machine; avoid mixing `/usr/local` source
installs with APT-managed `/usr` packages.

## Use

New policies are disabled, with incoming/routed deny and outgoing allow.
Allow your administration traffic before enabling; keep console access available.

```sh
sudo ebpfw allow OpenSSH
sudo ebpfw allow 443/tcp
sudo ebpfw default deny incoming
sudo ebpfw default allow outgoing
sudo ebpfw check
sudo ebpfw --dry-run enable
sudo ebpfw enable
sudo ebpfw status numbered
```

More examples:

```sh
sudo ebpfw allow in on eth0 proto tcp from 192.0.2.0/24 to any port 8443
sudo ebpfw allow out proto udp to 198.51.100.53 port 53
sudo ebpfw route allow in on lan0 out on wan0 proto tcp to any port 443
sudo ebpfw limit 22/tcp rate 12/minute burst 6
sudo ebpfw reject 23/tcp
sudo ebpfw app set Cameras 554/tcp 8554/tcp
sudo ebpfw allow Cameras
sudo ebpfw insert 1 allow 2222/tcp
sudo ebpfw delete 3
sudo ebpfw logging on
sudo ebpfw stats
sudo ebpfw disable
```

Use `ebpfw help` for all commands. Rules are ordered; existing connections survive
ordinary rule changes. `block from CIDR` also blocks existing state. Optional
`accelerate INTERFACE native` (or `generic`) accelerates those source blocks with
XDP; packet logging pauses acceleration. Loopback, local IPv6 discovery, and
incoming DHCP replies have base allowances that explicit rules can override.

Configuration lives in `/etc/ebpfw/rules.json`. Installed `enable` starts
`ebpfw.service`; foreground `ebpfw run` is also supported. Pinned kernel links
keep filtering if the service stops or crashes. Use `disable` to detach. Logs,
best-effort reject replies, and expired-state cleanup need the running agent.
A changed BPF object requires a reviewed disable/enable upgrade, with a brief
enforcement gap. The flow table holds 65,536 entries and fails closed when full.

This is not a drop-in UFW replacement: no NAT, connection helpers, bridge-layer
filtering, or UFW configuration-file compatibility. Connection limiting uses a
token bucket. TCP tracking is a new implementation without an independent
security audit. IPv6 jumbograms and extension chains beyond 32 headers are
unsupported. Legacy v0.1 policies migrate disabled for review.

## Benchmark

![ebpfw vs UFW: time per operation at 64 rules](benchmarks/comparison.svg)

**Blocking was faster; accepted traffic was approximately equal.** At 64 rules,
source IP blocking with ebpfw’s XDP acceleration took about **44% less time**
and UDP port blocking through its standard eBPF hooks about
**26% less time**. Small accepted-traffic differences overlap observed variation;
these results do not establish faster streaming or greater network throughput.

Method: real UFW 0.36.2 using `iptables-nft`, compared with ebpfw in separate
network/mount namespaces over veth. Five repetitions at 1, 16, and 64 rules,
alternating backend order: 150 trials. Each drop trial verifies 5,000 frames;
established TCP/UDP trials verify 1,000 64-byte echo round trips; new TCP trials
verify 50 connect/echo/close operations. Logging is off.

Every row compares UFW with ebpfw. Only ebpfw uses generic XDP in the source IP
blocking test; the other rows use its standard Netfilter eBPF hooks. UFW uses
`iptables-nft` throughout, with equivalent absolute source blocks before its
established-flow acceptance rules. UFW does not use XDP.

Recorded on 2026-11-03 from `fef330d` with Clang 21.1.8, before the compiler
portability repair: Linux 6.12.114, ARM64 QEMU 10.2.4/HVF, two vCPUs, 1.5 GiB RAM,
Apple M5 host. This is a VM measurement, not physical-NIC or Pi performance.
[Raw samples](benchmarks/results.jsonl) and [graph generator](benchmarks/plot.py)
are included; older reports and logs remain in Git history.

## Test and reproduce

```sh
make test                                  # unit tests, race detector, vet
sudo env PATH="$PATH" make test-kernel       # live kernel tests
sudo env PATH="$PATH" make benchmark         # real UFW comparison
python3 benchmarks/plot.py                  # redraw the recorded graph
```

Kernel tests and benchmarks require a disposable Linux machine with BTF and
BPF privileges. The benchmark also requires UFW. Both Make targets create
private network/mount namespaces and private bpffs; they never attach to a real
NIC. The live suite covers IPv4/IPv6, state, routing, fragments, selectors,
limits, rejects, XDP, reloads, and agent crashes. CI runs these tests and offers
the benchmark as a manual input. Chart generation uses Matplotlib, included in
the Nix shell.

## License

Go/Python: Apache-2.0. BPF C: GPL-2.0-only. See `LICENSE` and `bpf/LICENSE`.
