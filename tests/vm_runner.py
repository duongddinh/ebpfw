#!/usr/bin/env python3
"""Build and test in a disposable QEMU VM with no external NIC or host mounts."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import urllib.request

REPO = Path(__file__).resolve().parents[1]
ASSETS = {
    'arm64': ('aarch64', '01c33bc9a2a61cdde9eea7b6f3e43da6ba115b3fdcb76991a94415627b4c6768',
              'b38ae7e9794114459002d1076865e72523fe5b717b752f977fcbd2b5d8caf5d9'),
    'amd64': ('x86_64', '26f146f664ad057be3b39b211422b03b1f94cb2c3d66522fd4841811a224bfd5',
              'a996c7584302c2c4dee8dd7ba26ed8e4e2e5c3c670a124ada0ad6cfb852d2967'),
}
VERSION = '6.12.114-0-virt'


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def artifact(cache, arch, name, digest):
    path = cache / (arch + '-' + name)
    if not path.exists():
        url = f'https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/{ASSETS[arch][0]}/netboot/{name}'
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('upstream asset changed; review and update its pinned digest: ' + url)
        path.write_bytes(data)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RuntimeError('cached artifact digest mismatch: ' + str(path))
    return path


class CPIO:
    def __init__(self):
        self.data = bytearray()
        self.ino = 0

    def add(self, name, mode, data=b'', major=0, minor=0):
        self.ino += 1
        name = name.encode() + b'\0'
        fields = [self.ino, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name), 0]
        self.data.extend(('070701' + ''.join(f'{v:08x}' for v in fields)).encode())
        self.data.extend(name)
        self.data.extend(b'\0' * (-len(self.data) % 4))
        self.data.extend(data)
        self.data.extend(b'\0' * (-len(self.data) % 4))


def pack(root, cache, arch, modloop, benchmark):
    archive = CPIO()
    for path in sorted(root.rglob('*')):
        name, mode = path.relative_to(root).as_posix(), path.lstat().st_mode
        if stat.S_ISLNK(mode):
            archive.add(name, stat.S_IFLNK | 0o777, os.readlink(path).encode())
        elif stat.S_ISDIR(mode):
            archive.add(name, stat.S_IFDIR | (mode & 0o777))
        elif stat.S_ISREG(mode):
            archive.add(name, stat.S_IFREG | (mode & 0o777), path.read_bytes())
    for name in ('dev', 'proc', 'sys', 'tmp', 'run'):
        archive.add(name, stat.S_IFDIR | (0o1777 if name == 'tmp' else 0o755))
    archive.add('dev/console', stat.S_IFCHR | 0o600, major=5, minor=1)
    for name, source in [('init', 'vm-init-' + arch), ('full.test', 'full-' + arch + '.test'),
                         ('ebpfw', 'ebpfw-' + arch), ('stateful.o', 'stateful.o')]:
        archive.add(name, stat.S_IFREG | 0o755, (REPO / 'build' / source).read_bytes())

    def module_file(name):
        return run(['unsquashfs', '-cat', modloop, 'modules/' + VERSION + '/' + name], stdout=subprocess.PIPE).stdout

    metadata = module_file('modules.dep')
    deps = dict((name, tail.split()) for name, tail in (line.split(':') for line in metadata.decode().splitlines()))
    initial = []

    def select(name, selected):
        if name in selected:
            return
        for dep in deps[name]:
            select(dep, selected)
        selected.append(name)

    for name in ('kernel/net/packet/af_packet.ko', 'kernel/drivers/net/veth.ko', 'kernel/drivers/net/tun.ko',
                 'kernel/net/ipv4/netfilter/nf_defrag_ipv4.ko', 'kernel/net/ipv6/netfilter/nf_defrag_ipv6.ko',
                 'kernel/crypto/crc32c_generic.ko'):
        select(name, initial)
    # Read exact-case entries from squashfs; macOS filesystems may conflate xt_FOO and xt_foo.
    contents = {}
    for i, name in enumerate(initial):
        contents[name] = module_file(name)
        archive.add(f'module-{i}.ko', stat.S_IFREG | 0o600, contents[name])
    archive.add('modules.list', stat.S_IFREG | 0o600, '\n'.join(f'module-{i}.ko' for i in range(len(initial))).encode())
    selected = initial.copy()
    for name in deps:
        if name.startswith(('kernel/net/netfilter/', 'kernel/net/ipv4/netfilter/', 'kernel/net/ipv6/netfilter/')):
            select(name, selected)
    module_base = 'usr/lib/modules/' + VERSION + '/'
    made = set()

    def directories(path):
        for parent in reversed([path, *path.parents]):
            if str(parent) != '.' and str(parent) not in made:
                archive.add(parent.as_posix(), stat.S_IFDIR | 0o755)
                made.add(str(parent))

    directories(Path(module_base))
    # depmod/modprobe use these unmodified guest-kernel metadata files.
    listing = run(['unsquashfs', '-ll', modloop, 'modules/' + VERSION], stdout=subprocess.PIPE).stdout.decode()
    for line in listing.splitlines():
        name = line.split()[-1].split('/')[-1] if line.split() else ''
        if name.startswith('modules.') and ' -> ' not in line:
            archive.add(module_base + name, stat.S_IFREG | 0o644, module_file(name))
    for name in sorted(selected):
        directories(Path(module_base + name).parent)
        data = contents[name] if name in contents else module_file(name)
        archive.add(module_base + name, stat.S_IFREG | 0o644, data)
    archive.add('ufw-test-enabled', stat.S_IFREG | 0o600, b'1')
    if benchmark:
        archive.add('ufw-benchmark-enabled', stat.S_IFREG | 0o600, b'1')
    archive.add('TRAILER!!!', 0)
    target = cache / (arch + '-initramfs.gz')
    target.write_bytes(gzip.compress(archive.data, mtime=0))
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang', default=os.environ.get('CLANG', 'clang'), help='BPF compiler executable')
    parser.add_argument('--arch', choices=ASSETS, default='arm64' if platform.machine() in ('arm64', 'aarch64') else 'amd64')
    parser.add_argument('--cache', type=Path, default=REPO / '.cache' / 'vm')
    parser.add_argument('--benchmark', action='store_true', help='also compare against real UFW (150 trials)')
    parser.add_argument('--accel', choices=('auto', 'hvf', 'kvm', 'tcg'), default='auto')
    parser.add_argument('--log', type=Path)
    args = parser.parse_args()
    cache, arch = args.cache.resolve(), args.arch
    cache.mkdir(parents=True, exist_ok=True)
    for tool in ('go', args.clang, 'unsquashfs', 'qemu-system-' + ASSETS[arch][0]):
        if not shutil.which(tool):
            raise SystemExit('missing ' + tool + '; run inside nix develop')
    kernel = artifact(cache, arch, 'vmlinuz-virt', ASSETS[arch][1])
    modloop = artifact(cache, arch, 'modloop-virt', ASSETS[arch][2])
    root = cache / ('debian-' + arch)
    if not (root / '.ebpfw-guest-ready').exists():
        run([sys.executable, REPO / 'tests/fetch_ufw_root.py', cache, arch])
        (root / '.ebpfw-guest-ready').write_text('verified guest assets\n')
    (REPO / 'build').mkdir(exist_ok=True)
    env = dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0')
    run([args.clang, '-O2', '-g', '-target', 'bpfel', '-mcpu=v3', '-Wall', '-Werror', '-c', REPO / 'bpf/stateful.c', '-o', REPO / 'build/stateful.o'])
    for target, package, test in [('ebpfw-' + arch, './cmd/ebpfw', False), ('full-' + arch + '.test', './internal/firewall', True), ('vm-init-' + arch, './tests/vm', False)]:
        command = ['go', 'test', '-c'] if test else ['go', 'build', '-trimpath']
        run(command + ['-o', REPO / 'build' / target, package], env=env, cwd=REPO)
    initrd = pack(root, cache, arch, modloop, args.benchmark)
    native = (arch == 'arm64') == (platform.machine() in ('arm64', 'aarch64'))
    accel = args.accel
    if accel == 'auto':
        accel = 'hvf' if native and sys.platform == 'darwin' else 'kvm' if native and os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg'
    machine = ('virt' if arch == 'arm64' else 'q35') + ',accel=' + accel
    cpu = ('host' if accel != 'tcg' else 'max')
    console = 'ttyAMA0' if arch == 'arm64' else 'ttyS0'
    command = ['qemu-system-' + ASSETS[arch][0], '-machine', machine, '-cpu', cpu, '-m', '1536', '-smp', '2',
               '-nic', 'none', '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-kernel', kernel, '-initrd', initrd, '-append', f'console={console} quiet panic=-1']
    log = args.log or cache / (arch + ('-benchmark' if args.benchmark else '-functional') + '.log')
    print('Running isolated VM:', arch, accel, '; log:', log, flush=True)
    with log.open('wb') as output:
        run(command, stdout=output, stderr=subprocess.STDOUT, timeout=1500)
    content = log.read_text(errors='replace')
    if 'EBPFW_FULL_VM_PASS' not in content or 'EBPFW_FULL_VM_FAIL' in content:
        print(content[-16000:])
        raise SystemExit('VM tests failed; see ' + str(log))
    print('VM tests passed:', log)
    if args.benchmark:
        samples = [json.loads(line.split('EBPFW_UFW_SAMPLE ', 1)[1]) for line in content.splitlines() if line.startswith('EBPFW_UFW_SAMPLE ')]
        if len(samples) != 150:
            raise SystemExit(f'expected 150 benchmark samples, got {len(samples)}')
        output = log.with_suffix('.jsonl')
        output.write_text(''.join(json.dumps(s, sort_keys=True) + '\n' for s in samples))
        print('Verified benchmark samples:', output)


if __name__ == '__main__':
    main()
