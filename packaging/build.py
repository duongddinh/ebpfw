#!/usr/bin/env python3
"""Build self-contained Debian packages without requiring root or dpkg."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
DISCLAIMER = """Experimental software; no independent security audit.
An incorrect firewall policy can interrupt SSH, cameras, applications, or routing.
Test in a disposable VM and keep console access before enabling. Linux 6.6+ with
kernel BTF and the required BPF hooks/kfuncs is necessary; packages cannot add
missing kernel features. Reported speed results are VM measurements, mainly for
blocking, not a guarantee of faster accepted traffic or production throughput.
Installation leaves filtering disabled. No warranty; see the bundled licenses.
"""
GUARD = '''# Never replace the object or remove the agent underneath pinned enforcement.
for state in /sys/fs/bpf/ebpfw/ns-*/owner; do
    if [ -e "$state" ]; then
        echo 'ebpfw: disable ebpfw in every using network namespace before upgrading/removing.' >&2
        exit 1
    fi
done
if [ -f /etc/ebpfw/rules.json ] && grep -Eq '"enabled"[[:space:]]*:[[:space:]]*true' /etc/ebpfw/rules.json; then
    echo 'ebpfw: run sudo ebpfw disable before upgrading/removing; review and re-enable afterward.' >&2
    exit 1
fi
'''


def tar(entries, epoch):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.GNU_FORMAT) as archive:
        directories = set()
        for name, (data, mode) in sorted(entries.items()):
            for parent in reversed(Path(name).parents):
                directory = parent.as_posix()
                if directory != '.' and directory not in directories:
                    info = tarfile.TarInfo('./' + directory + '/')
                    info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, epoch
                    info.uname = info.gname = 'root'
                    archive.addfile(info)
                    directories.add(directory)
            info = tarfile.TarInfo('./' + name)
            info.size, info.mode, info.mtime = len(data), mode, epoch
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(output.getvalue(), mtime=0)


def deb(control, data, epoch):
    output = bytearray(b'!<arch>\n')
    for name, value in [('debian-binary', b'2.0\n'), ('control.tar.gz', tar(control, epoch)), ('data.tar.gz', tar(data, epoch))]:
        output.extend(f'{name + "/":<16}{epoch:<12}{0:<6}{0:<6}{"100644":<8}{len(value):<10}`\n'.encode())
        output.extend(value)
        if len(value) % 2:
            output.extend(b'\n')
    return output


def build(version, arch, output, epoch):
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[~+][a-zA-Z0-9.]+)?', version):
        raise ValueError('version must be X.Y.Z, optionally followed by ~prerelease or +suffix')
    if arch not in ('amd64', 'arm64'):
        raise ValueError('only amd64 and arm64 are supported')
    stage = ROOT / 'build' / ('deb-' + arch)
    stage.mkdir(parents=True, exist_ok=True)
    subprocess.run([os.environ.get('GO', 'go'), 'build', '-trimpath', '-ldflags',
                    '-X main.defaultObject=/usr/lib/ebpfw/stateful.o', '-o', str(stage / 'ebpfw'), '.'],
                   cwd=ROOT, env={**os.environ, 'GOOS': 'linux', 'GOARCH': arch, 'CGO_ENABLED': '0'}, check=True)
    subprocess.run([os.environ.get('CLANG', 'clang'), '-O2', '-g', '-target', 'bpfel', '-mcpu=v3',
                    '-Wall', '-Werror', '-c', str(ROOT / 'bpf/stateful.c'), '-o', str(stage / 'stateful.o')], check=True)
    data = {
        'usr/sbin/ebpfw': ((stage / 'ebpfw').read_bytes(), 0o755),
        'usr/lib/ebpfw/stateful.o': ((stage / 'stateful.o').read_bytes(), 0o644),
        'usr/lib/systemd/system/ebpfw.service': ((ROOT / 'ebpfw.service').read_bytes().replace(b'/usr/local', b'/usr'), 0o644),
        'etc/ebpfw/rules.json': ((json.dumps({'version': 2, 'enabled': False, 'default': 'deny',
            'default_out': 'allow', 'default_route': 'deny', 'rules': []}, indent=2) + '\n').encode(), 0o600),
        'usr/share/doc/ebpfw/README.md': ((ROOT / 'README.md').read_bytes(), 0o644),
        'usr/share/doc/ebpfw/DISCLAIMER': (DISCLAIMER.encode(), 0o644),
        'usr/share/doc/ebpfw/copyright': ((ROOT / 'LICENSE').read_bytes() + b'\nBPF C license:\n' + (ROOT / 'bpf/LICENSE').read_bytes(), 0o644),
    }
    metadata = f'''Package: ebpfw
Version: {version}
Architecture: {arch}
Section: net
Priority: optional
Maintainer: Cytizen Networks LLC <support@fragella.com>
Homepage: https://github.com/duongddinh/ebpfw
Depends: systemd
Installed-Size: {(sum(len(v[0]) for v in data.values()) + 1023) // 1024}
Description: experimental UFW-style stateful eBPF firewall
 Requires Linux 6.6+, kernel BTF, and supported BPF hooks and kfuncs.
 Installation does not enable filtering. Not independently security audited.
'''
    postinst = '''#!/bin/sh
set -e
if [ "$1" = configure ]; then
    if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
    echo 'ebpfw installed; filtering has NOT been enabled.'
    echo 'EXPERIMENTAL: no independent audit. Test in a VM and preserve console/SSH access.'
    echo 'Run sudo ebpfw doctor; allow administration traffic before sudo ebpfw enable.'
    echo 'See /usr/share/doc/ebpfw/DISCLAIMER and https://packages.cytizennetworks.com/'
fi
'''
    postrm = '''#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
    if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
fi
'''
    control = {
        'control': (metadata.encode(), 0o644),
        'conffiles': (b'/etc/ebpfw/rules.json\n', 0o644),
        'preinst': (('#!/bin/sh\nset -e\ncase "$1" in install|upgrade)\n' + GUARD + ';;\nesac\n').encode(), 0o755),
        'prerm': (('#!/bin/sh\nset -e\ncase "$1" in remove|upgrade|deconfigure)\n' + GUARD + ';;\nesac\n').encode(), 0o755),
        'postinst': (postinst.encode(), 0o755),
        'postrm': (postrm.encode(), 0o755),
        'md5sums': (''.join(f'{hashlib.md5(value[0]).hexdigest()}  {name}\n' for name, value in sorted(data.items())
                           if not name.startswith('etc/')).encode(), 0o644),
    }
    output.mkdir(parents=True, exist_ok=True)
    target = output / f'ebpfw_{version}_{arch}.deb'
    target.write_bytes(deb(control, data, epoch))
    print(target)
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/packages')
    parser.add_argument('--epoch', type=int, default=int(os.environ.get('SOURCE_DATE_EPOCH', '0')))
    args = parser.parse_args()
    build(args.version, args.arch, args.output, args.epoch)
