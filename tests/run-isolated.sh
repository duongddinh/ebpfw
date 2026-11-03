#!/bin/sh
# Run only on a disposable Linux test host. No programs attach to its real NICs.
set -eu
if [ "${EBPFW_PRIVATE_CHILD:-}" != 1 ]; then
    if [ "$(id -u)" != 0 ]; then
        echo 'Run as root on a disposable Linux test host.' >&2
        exit 1
    fi
    exec unshare --net --mount env EBPFW_PRIVATE_CHILD=1 "$0" "$@"
fi
mount --make-rprivate /
mount -t bpf bpf /sys/fs/bpf
mount -t tmpfs -o mode=0755 tmpfs /run
exec "$@"
