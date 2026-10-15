#!/usr/bin/env python3
"""Summarize the final interleaved campaign; preserve first and warm trials."""
import json
import pathlib
import re
import statistics

records = [json.loads(line) for line in
           pathlib.Path(__file__).with_name("raw-comparison.jsonl").read_text().splitlines()]
assert len(records) == 63
assert all(not r["returncode"] and r["output_valid"] and len(r["rows"]) == 3 for r in records)
summary = []
for case in sorted({(r["resident_mib"], r["peers"], r["sample"]) for r in records}):
    for variant in ("baseline", "uffd", "softdirty"):
        group = [r for r in records if (r["resident_mib"], r["peers"], r["sample"]) == case
                 and r["variant"] == variant]
        cold = [r["rows"][0] for r in group]
        warm = [s for r in group for s in r["rows"][1:]]
        counters = [dict((k, int(v)) for k, v in re.findall(r"(\w+)=(\d+)", line))
                    for r in group for line in r["stderr"].splitlines() if line.startswith("UFFD_POC ")]
        cpu = [float(user) + float(system) for r in group for trial, user, system in
               re.findall(r"aggregate-child-cpu trial=(\d+) user=([\d.]+) system=([\d.]+)", r["stderr"])
               if trial != "0"]
        summary.append(dict(
            variant=variant, resident_mib=case[0], peers=case[1], sample=case[2],
            cold_launch_ms=statistics.median(s["launch_s"] for s in cold) * 1000,
            warm_launch_ms=statistics.median(s["launch_s"] for s in warm) * 1000,
            warm_total_ms=statistics.median(s["total_s"] for s in warm) * 1000,
            warm_total_min_ms=min(s["total_s"] for s in warm) * 1000,
            warm_total_max_ms=max(s["total_s"] for s in warm) * 1000,
            warm_aggregate_child_cpu_ms=statistics.median(cpu) * 1000,
            peak_parent_rss_kib=max(s["self_maxrss_kib"] for s in cold + warm),
            peak_child_rss_kib=max(s["child_maxrss_kib"] for s in cold + warm),
            warm_child_minflt_range=[min(s["child_minflt"] for s in warm), max(s["child_minflt"] for s in warm)],
            warm_child_majflt_range=[min(s["child_majflt"] for s in warm), max(s["child_majflt"] for s in warm)],
            uffd_counter_ranges={key: [min(c[key] for c in counters), max(c[key] for c in counters)]
                                 for key in counters[0]} if counters else {},
        ))
print(json.dumps({"process_runs": len(records), "verified_launches": len(records) * 3,
                  "results": summary}, indent=2))
