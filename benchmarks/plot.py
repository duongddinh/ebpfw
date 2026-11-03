#!/usr/bin/env python3
"""Validate UFW benchmark samples and plot normalized time at 64 rules."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics

WORKLOADS = [
    ('early-source-drop', 'XDP source blocking'),
    ('udp-drop', 'Normal UDP blocking'),
    ('tcp-established', 'Established TCP'),
    ('udp-established', 'Established UDP'),
    ('tcp-new', 'TCP connect + echo + close'),
]


def read_samples(path):
    groups, seen = defaultdict(list), set()
    for line in path.read_text().splitlines():
        sample = json.loads(line)
        key = (sample['workload'], sample['rules'], sample['backend'])
        identity = (*key, sample['repetition'])
        if identity in seen:
            raise ValueError('duplicate trial: ' + str(identity))
        seen.add(identity)
        operations = sample['operations']
        if sample['workload'] in ('udp-drop', 'early-source-drop'):
            verified = sample['verified_packets'] == operations
        else:
            verified = sample['verified_payload_messages'] == 2 * operations
            if sample['workload'] == 'tcp-new':
                verified &= sample['completed_connections'] == operations
        if not verified or operations <= 0 or sample['ns_per_operation'] <= 0:
            raise ValueError('unverified or invalid sample: ' + str(identity))
        groups[key].append(sample['ns_per_operation'] / 1000)
    expected = {(w, r, b) for w, _ in WORKLOADS for r in (1, 16, 64) for b in ('ufw', 'ebpf')}
    if set(groups) != expected or any(len(v) != 5 for v in groups.values()):
        raise ValueError('expected five repetitions for all 150 trials')
    return groups


def draw(groups, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9,
                         'svg.fonttype': 'none', 'svg.hashsalt': 'ebpfw'})
    fig, ax = plt.subplots(figsize=(8.8, 4.3))
    colors = {'ufw': '#eeeeee', 'ebpf': '#444444'}
    for i, (workload, _) in enumerate(WORKLOADS):
        baseline = statistics.median(groups[workload, 64, 'ufw'])
        for backend, offset in [('ufw', -0.17), ('ebpf', 0.17)]:
            trials = [v / baseline * 100 for v in groups[workload, 64, backend]]
            value = statistics.median(trials)
            ax.barh(i + offset, value, height=0.27, color=colors[backend],
                    edgecolor='#555555', linewidth=0.5,
                    label=('UFW' if backend == 'ufw' else 'eBPF') if i == 0 else None,
                    xerr=[[value - min(trials)], [max(trials) - value]],
                    error_kw={'ecolor': '#333333', 'elinewidth': 0.7, 'capsize': 2})
        saving = 100 * (1 - statistics.median(groups[workload, 64, 'ebpf']) / baseline)
        ax.text(1.025, i, f'{saving:.1f}%'.replace('-', '−'),
                transform=ax.get_yaxis_transform(), ha='right', va='center', fontsize=9)
    ax.set_yticks(range(len(WORKLOADS)), [label for _, label in WORKLOADS])
    ax.invert_yaxis()
    ax.set_xlim(0, 134)
    ax.set_xticks([0, 25, 50, 75, 100, 125], ['0', '25', '50', '75', '100', '125'])
    ax.set_xlabel('Time per operation (% of UFW median; lower is better)', labelpad=10)
    ax.axvline(100, color='#999999', linestyle=':', linewidth=0.7, zorder=0)
    ax.tick_params(axis='y', length=0)
    ax.tick_params(axis='x', length=3, width=0.6, color='#777777')
    for name, spine in ax.spines.items():
        spine.set_visible(name == 'bottom')
        spine.set_color('#777777')
        spine.set_linewidth(0.6)
    ax.legend(loc='upper left', bbox_to_anchor=(0, 1.17), ncol=2, frameon=False,
              handlelength=1.6, columnspacing=1.8)
    ax.text(1.025, 1.10, 'Time saved', transform=ax.transAxes,
            ha='right', va='bottom', fontsize=9)
    fig.text(0.04, 0.94, 'UFW and eBPF: time per operation', fontsize=12, fontweight='medium')
    fig.text(0.04, 0.895, '64 rules · ARM64 virtual machine', fontsize=9, color='#555555')
    fig.text(0.04, 0.035, 'Bars show medians; whiskers show the range of five trials. Positive time savings favor eBPF.',
             fontsize=8, color='#555555')
    fig.subplots_adjust(left=0.30, right=0.94, top=0.73, bottom=0.22)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, metadata={'Date': None}, facecolor='white')
    plt.close(fig)
    if output.suffix.lower() == '.svg':
        output.write_text('\n'.join(line.rstrip() for line in output.read_text().splitlines()) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('samples', nargs='?', type=Path, default=Path(__file__).with_name('results.jsonl'))
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('comparison.svg'))
    args = parser.parse_args()
    groups = read_samples(args.samples)
    print('| Workload | UFW µs/op | eBPF µs/op | Time saved |')
    print('|---|---:|---:|---:|')
    for workload, label in WORKLOADS:
        ufw = statistics.median(groups[workload, 64, 'ufw'])
        ebpf = statistics.median(groups[workload, 64, 'ebpf'])
        print(f'| {label} | {ufw:.3f} | {ebpf:.3f} | {100 * (1 - ebpf / ufw):.1f}% |')
    draw(groups, args.output)
    print('Graph:', args.output)


if __name__ == '__main__':
    main()
