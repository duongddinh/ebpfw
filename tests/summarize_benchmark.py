#!/usr/bin/env python3
"""Validate and summarize the direct UFW JSONL evidence (microseconds/operation)."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('samples', type=Path)
    args = parser.parse_args()
    groups = defaultdict(list)
    seen = set()
    for line in args.samples.read_text().splitlines():
        sample = json.loads(line)
        key = (sample['workload'], sample['rules'], sample['backend'])
        identity = (*key, sample['repetition'])
        if identity in seen:
            raise SystemExit('duplicate trial: ' + str(identity))
        seen.add(identity)
        operations = sample['operations']
        if sample['workload'] in ('udp-drop', 'early-source-drop'):
            assert sample['verified_packets'] == operations
        else:
            assert sample['verified_payload_messages'] == 2 * operations
            if sample['workload'] == 'tcp-new':
                assert sample['completed_connections'] == operations
        groups[key].append(sample['ns_per_operation'] / 1000)
    expected = {(w, r, b) for w in ('udp-drop', 'udp-established', 'tcp-established', 'tcp-new', 'early-source-drop')
                for r in (1, 16, 64) for b in ('ufw', 'ebpf')}
    assert set(groups) == expected and all(len(v) == 5 for v in groups.values()), 'expected 150 trials'
    print('| Workload | Rules | UFW median [min, max] µs | ebpfw median [min, max] µs | UFW / ebpfw |')
    print('|---|---:|---:|---:|---:|')
    for w, r in sorted({(k[0], k[1]) for k in groups}):
        u, e = groups[w, r, 'ufw'], groups[w, r, 'ebpf']
        def cell(v):
            return f'{statistics.median(v):.3f} [{min(v):.3f}, {max(v):.3f}]'
        print(f'| {w} | {r} | {cell(u)} | {cell(e)} | {statistics.median(u) / statistics.median(e):.2f}× |')


if __name__ == '__main__':
    main()
