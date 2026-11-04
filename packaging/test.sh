#!/bin/sh
# Run only in a disposable Linux guest or CI runner; never on a production host.
set -eu
if [ "${EBPFW_PACKAGE_TEST:-}" != 1 ] || [ "$(id -u)" != 0 ]; then
    echo 'Requires root and EBPFW_PACKAGE_TEST=1 on a disposable Linux guest.' >&2; exit 1
fi
[ "$#" = 2 ] || { echo 'Usage: test.sh first.deb second.deb' >&2; exit 1; }
first=$1
second=$2
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
dpkg --install "$first"
ebpfw check
ebpfw --help 2>&1 | grep -q /usr/lib/ebpfw/stateful.o
[ "$(stat -c %a /etc/ebpfw/rules.json)" = 600 ]
if grep -Eq '"enabled"[[:space:]]*:[[:space:]]*true' /etc/ebpfw/rules.json; then
    echo 'Installation enabled filtering unexpectedly'; exit 1
fi
# Minimal Debian images may deliberately exclude /usr/share/doc at unpack time.
dpkg-deb --extract "$first" "$temporary/unpacked"
test -r "$temporary/unpacked/usr/share/doc/ebpfw/DISCLAIMER"
test -r /usr/lib/ebpfw/stateful.o
ebpfw allow 443/tcp
cp /etc/ebpfw/rules.json "$temporary/saved.json"
dpkg-deb --control "$first" "$temporary/control"

# Run real enforcement only in private network/mount namespaces. A custom config
# avoids invoking the host systemd manager. The host's pinned state is hidden.
modprobe nf_defrag_ipv4
modprobe nf_defrag_ipv6
# shellcheck disable=SC2016 # Arguments expand in the isolated child shell.
unshare --net --mount sh -ec '
    mount --make-rprivate /
    mount -t bpf bpf /sys/fs/bpf
    mount -t tmpfs -o mode=0755 tmpfs /run
    ebpfw --config "$1/private.json" allow OpenSSH
    ebpfw --config "$1/private.json" enable
    if sh "$1/control/preinst" upgrade; then echo "Active upgrade was not refused"; exit 1; fi
    if sh "$1/control/prerm" remove; then echo "Active removal was not refused"; exit 1; fi
    ebpfw --config "$1/private.json" disable
' sh "$temporary"

# Check the saved-enabled policy guard independently of pinned maps.
cp /etc/ebpfw/rules.json "$temporary/disabled.json"
sed 's/"enabled":false/"enabled":true/; s/"enabled": false/"enabled": true/' "$temporary/disabled.json" > /etc/ebpfw/rules.json
if sh "$temporary/control/preinst" upgrade; then echo 'Enabled policy upgrade was not refused'; exit 1; fi
cp "$temporary/disabled.json" /etc/ebpfw/rules.json
dpkg --install "$second"
cmp /etc/ebpfw/rules.json "$temporary/saved.json"
ebpfw check
dpkg --remove ebpfw
cmp /etc/ebpfw/rules.json "$temporary/saved.json"
dpkg --purge ebpfw
test ! -e /etc/ebpfw/rules.json
echo 'PASS: install, correct object path, disabled defaults, private kernel enforcement, upgrade/removal guards, preserved configuration, and purge'
