#!/usr/bin/env python3
"""Fetch official Debian files into an isolated guest root; never install on host."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import urllib.request

def get(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()

def cached(url, digest):
    path = cache / 'downloads' / digest
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        data = get(url)
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('artifact digest mismatch: ' + url)
        path.write_bytes(data)
    return path

def guest_path(name, follow_leaf=True):
    parts = list(PurePosixPath(name.lstrip('/')).parts)
    done = []
    hops = 0
    while parts:
        part = parts.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if done:
                done.pop()
            continue
        candidate = root.joinpath(*done, part)
        if candidate.is_symlink() and (parts or follow_leaf):
            hops += 1
            if hops > 64:
                raise RuntimeError('symlink cycle in guest archive')
            target = os.readlink(candidate)
            if target.startswith('/'):
                done = []
            parts = list(PurePosixPath(target.lstrip('/')).parts) + parts
        else:
            done.append(part)
    return root.joinpath(*done)

def extract(data):
    pending = []
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        for entry in archive:
            if PurePosixPath(entry.name).is_absolute() or ".." in PurePosixPath(entry.name).parts:
                raise RuntimeError("unsafe archive path")
            if entry.name.startswith('.wh.'):
                raise RuntimeError('unexpected OCI whiteout in base image')
            target = guest_path(entry.name, follow_leaf=False)
            target.parent.mkdir(parents=True, exist_ok=True)
            if entry.isdir():
                guest_path(entry.name).mkdir(parents=True, exist_ok=True)
                continue
            if target.is_symlink() or target.is_file():
                target.unlink()
            if entry.issym():
                target.symlink_to(entry.linkname)
            elif entry.islnk():
                pending.append((target, entry.linkname))
            elif entry.isfile():
                with archive.extractfile(entry) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(entry.mode & 0o777)
            # Device nodes are supplied safely by the VM's initramfs builder.
    for target, source in pending:
        os.link(guest_path(source), target)

def deb_data(data):
    if not data.startswith(b'!<arch>\n'):
        raise RuntimeError('invalid Debian archive')
    offset = 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        name = header[:16].decode().strip().rstrip('/')
        size = int(header[48:58])
        body = data[offset + 60:offset + 60 + size]
        if name.startswith('data.tar'):
            if name.endswith('.zst'):
                return subprocess.run(['zstd', '-d', '-q', '-c'], input=body, check=True, stdout=subprocess.PIPE).stdout
            return body
        offset += 60 + size + size % 2
    raise RuntimeError('no data archive in Debian package')

def configure_guest_ufw():
    """Copy the unmodified templates exactly as Debian's postinst does."""
    target = guest_path('/etc/ufw')
    target.mkdir(parents=True, exist_ok=True)
    for name in ('before.rules', 'before6.rules', 'after.rules', 'after6.rules', 'user.rules', 'user6.rules'):
        destination = target / name
        if not destination.exists():
            shutil.copyfile(guest_path('/usr/share/ufw/iptables/' + name), destination)
            destination.chmod(0o640)
    for name in ('before.init', 'after.init', 'ufw.conf'):
        destination = target / name
        if not destination.exists():
            shutil.copyfile(guest_path('/usr/share/ufw/' + name), destination)
            destination.chmod(0o640 if name.endswith('.init') else 0o644)


def main():
    global cache, root
    cache = Path(sys.argv[1]).resolve()

    arch = sys.argv[2] if len(sys.argv) > 2 else 'amd64'

    if arch not in ('amd64', 'arm64'):
        raise SystemExit('architecture must be amd64 or arm64')

    root = cache / ('debian-' + arch)

    root.mkdir(parents=True, exist_ok=True)

    (cache / 'downloads').mkdir(exist_ok=True)

    lock = json.loads((Path(__file__).parent / 'fixtures' / ('debian-' + arch + '.json')).read_text())
    manifest = dict(lock)

    print('Fetching official Debian OCI image metadata for', arch, flush=True)

    auth = json.loads(get('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull'))

    headers = {'Authorization': 'Bearer ' + auth['token'],
               'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json'}

    base = 'https://registry-1.docker.io/v2/library/debian/'

    image_data = get(base + 'manifests/' + lock['oci_manifest'], headers)
    if hashlib.sha256(image_data).hexdigest() != lock['oci_manifest'].split(':')[1]:
        raise RuntimeError('OCI manifest digest mismatch')
    image = json.loads(image_data)

    for layer in image['layers']:
        digest = layer['digest'].split(':')[1]
        path = cache / 'downloads' / digest
        if not path.exists():
            data = get(base + 'blobs/' + layer['digest'], headers)
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError('OCI layer digest mismatch')
            path.write_bytes(data)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError('cached OCI layer digest mismatch')
        extract(path.read_bytes())

    for package in lock['packages']:
        print('Guest package:', package['Package'], package['Version'], flush=True)
        path = cached('https://deb.debian.org/debian/' + package['Filename'], package['SHA256'])
        extract(deb_data(path.read_bytes()))

    for family in ('iptables', 'ip6tables'):
        for suffix in ('', '-save', '-restore'):
            target = root / 'usr/sbin' / (family + suffix)
            if target.is_symlink() or target.exists():
                target.unlink()
            target.symlink_to('xtables-nft-multi')

    configure_guest_ufw()
    manifest_path = cache / ('ufw-guest-manifest-' + arch + '.json')

    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')

    print('Guest root ready:', root, flush=True)

    print('Artifact manifest:', manifest_path, flush=True)

if __name__ == "__main__":
    main()
