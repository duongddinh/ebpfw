#!/usr/bin/env python3
"""Print median completion times from raw ebpfw-bench JSONL (no dependencies)."""
import json
import statistics
import sys

rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert rows and all(r["verified_drops"] == r["packets"] for r in rows)
print("| Rules | Mode | Median µs/frame | Min–max µs/frame | Samples |")
print("| ---: | --- | ---: | ---: | ---: |")
for rules in sorted({r["rules"] for r in rows}):
    for mode in sorted({r["mode"] for r in rows}):
        values = [r["wall_ns_per_packet"] / 1000 for r in rows
                  if r["rules"] == rules and r["mode"] == mode]
        if values:
            print(f"| {rules} | {mode} | {statistics.median(values):.3f} | "
                  f"{min(values):.3f}–{max(values):.3f} | {len(values)} |")
