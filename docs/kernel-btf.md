# Kernel BTF and Raspberry Pi compatibility

BTF (BPF Type Format) describes kernel types and function signatures. This build
uses kernel BTF for CO-RE field relocation and for verifier-approved kfunc calls,
including `bpf_dynptr_from_skb`. BTF is required on every host enforcing this
version of ebpfw. It is metadata, not an attached debugger or debug logging mode.
See the [BTF specification](https://docs.kernel.org/bpf/btf.html) and
[kfunc documentation](https://www.kernel.org/doc/html/latest/bpf/kfuncs.html).

An external BTF file can assist CO-RE relocation for other applications. It does
not install the kernel's missing kfunc registrations. Copying a file to `/sys`,
installing headers, or installing `bpftool` does not make this datapath work on a
kernel built without BTF. The Linux 6.18
[kfunc registration implementation](https://raw.githubusercontent.com/torvalds/linux/v6.18/kernel/bpf/btf.c)
resolves registrations against the kernel's own BTF.

## Observed Pi prerequisite failure

On 2026-11-03, a Raspberry Pi 3 Model B Plus camera host reported:

```text
Debian GNU/Linux 13 (trixie), arm64
Linux 6.18.34+rpt-rpi-v8
linux-image-6.18.34+rpt-rpi-v8 1:6.18.34-1+rpt1
CONFIG_DEBUG_INFO_NONE=y
CONFIG_NETFILTER_BPF_LINK=y
/sys/kernel/btf/vmlinux: absent
```

Its CLI dry run succeeded; `doctor` correctly refused missing kernel BTF. No
live BPF attachment, host firewall change, package installation, boot change,
module load, or reboot was performed. Temporary CLI files were removed and
link/route fingerprints were unchanged. This is a **preflight result**, not a
successful hardware datapath test or performance measurement.

## Building a compatible kernel: preparation only

A compatible distribution kernel or a custom Pi kernel must be booted before
this firewall can run. Replacing a camera's running kernel requires a maintenance
window and local/serial recovery access; a new kernel may affect camera drivers.
No custom Pi kernel was built, installed, or validated as part of this test.

For a separate Linux build machine:

1. Obtain the exact Raspberry Pi distribution source package corresponding to
   the installed kernel, retain its provenance, and use the existing
   `/boot/config-<release>` as the starting configuration. Avoid substituting a
   generic ARM kernel or discarding the Pi's driver configuration.
2. Apply [the example configuration fragment](kernel-btf.fragment) with the
   kernel's `scripts/kconfig/merge_config.sh`, then run `olddefconfig`. Review the
   resulting full configuration: options can be removed when dependencies are
   unavailable. Use a compatible compiler and `pahole`; the kernel build
   generates BTF from DWARF debug information.
3. Give the build a unique `LOCALVERSION`, for example `-rpi-v8-ebpfw-btf`, so it
   cannot overwrite stock kernel modules. Build the kernel, matching modules,
   device trees, and an appropriate matching initramfs. Preserve the stock boot
   files, overlays, and camera configuration.
4. Validate the resulting BTF and ebpfw in an isolated environment. VM success
   does not establish that the physical Pi camera drivers will work.
5. During an explicitly scheduled maintenance window, install the custom kernel
   alongside the stock image, select it by a distinct boot filename, and reboot.
   Have a tested SD-card/console rollback path to select the stock kernel if
   networking or the camera fails. Do not change the stock default remotely
   without recovery access.
6. Check `/sys/kernel/btf/vmlinux`, camera health, SSH, and routing after boot.
   Run ebpfw's private-namespace tests before considering host-wide enforcement.
   Booting a BTF-enabled kernel alone does not enable ebpfw.

Raspberry Pi documents separate image names, `LOCALVERSION`, module isolation,
and rollback in its [kernel build guide](https://www.raspberrypi.com/documentation/computers/linux_kernel.html).
The fragment is preparation guidance, not a validated build recipe or an
installation script. Its use must preserve distribution patches and hardware
support for the specific Pi.
