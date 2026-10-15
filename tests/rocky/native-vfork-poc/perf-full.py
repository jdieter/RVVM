#!/usr/bin/env python3
"""Matched spawn benchmark where each variant is also the post-exec interpreter.

Every run uses the same launch (guest.sh: private user/mount/binfmt/PID
namespaces, proc in the retained root, UID993/GID135, empty bounding set)
with the variant registered as the private binfmt interpreter, so xz/true
after exec run under the same binary as the spawning parent. Variants run
interleaved per case, forward then reverse. The observed interpreter hashes
are recorded per run, and output hashes must agree across variants.

Run as root on the dev host:
  perf-full.py <launcher-dir> <out.jsonl> name=/path/in/root ...
"""
import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import sys
import time

ROOT = "/var/lib/mock/rocky-10-riscv64-rvvm/root"
BENCH = "/tmp/claude/bench-vfork-modes"
FIXTURES = "/tmp/rvvm-vfork-poc"
OUTPUT = "/tmp/claude-perf"
LAUNCHES = 6
CASES = [  # resident MiB, peers, mode, sample
    (1024, 8, "spawn", "module.xz"), (3072, 96, "spawn", "module.xz"),
    (1024, 8, "spawn", "true"), (3072, 96, "spawn", "true"),
    (1024, 8, "spawn", "large-module.xz"),
    (1024, 8, "plain", "true"), (1024, 8, "mixed", "true"),
    (3072, 96, "plain", "true"), (3072, 96, "mixed", "true"),
    (1024, 8, "plain", "module.xz"), (1024, 8, "mixed", "module.xz"),
]


def tree(pid):
    """PIDs of pid and its descendants."""
    found, queue = [], [pid]
    while queue:
        current = queue.pop()
        found.append(current)
        try:
            for task in pathlib.Path(f"/proc/{current}/task").iterdir():
                queue.extend(map(int, (task / "children").read_text().split()))
        except (OSError, ValueError):
            pass
    return found


def run(launcher, name, path, case):
    mib, peers, mode, sample = case
    program = "/usr/bin/true" if sample == "true" else "/usr/bin/xz"
    fixture = f"{FIXTURES}/{'module.xz' if sample == 'true' else sample}"
    prefix = f"{OUTPUT}/{name}-{mib}-{peers}-{mode}-{sample}"
    command = [f"{launcher}/guest.sh", "120", path, BENCH, str(mib), str(peers),
               str(LAUNCHES), mode, program, fixture, prefix]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    interpreters, digests = set(), {}
    while process.poll() is None:
        for pid in tree(process.pid):
            try:
                link = pathlib.Path(f"/proc/{pid}/exe")
                target = os.readlink(link)
                if not target.startswith(ROOT + "/tmp/"):
                    continue
                stat = link.stat()
                key = (stat.st_dev, stat.st_ino)
                if key not in digests:
                    digests[key] = hashlib.sha256(link.read_bytes()).hexdigest()
                interpreters.add((target, digests[key]))
            except OSError:
                pass
        time.sleep(0.02)
    stdout, stderr = process.communicate()
    rows = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    hashes = []
    if process.returncode == 0:
        hashes = [hashlib.sha256(pathlib.Path(f"{ROOT}{prefix}-{i}").read_bytes()).hexdigest()
                  for i in range(LAUNCHES)]
    return dict(variant=name, path=path, resident_mib=mib, peers=peers, mode=mode, sample=sample,
                returncode=process.returncode, rows=rows, hashes=hashes,
                interpreters=sorted({"path": p, "sha256": d} for p, d in interpreters),
                stderr=stderr[-2000:])


def main():
    launcher, out = sys.argv[1], sys.argv[2]
    variants = [argument.split("=", 1) for argument in sys.argv[3:]]
    os.makedirs(ROOT + OUTPUT, exist_ok=True)
    os.chmod(ROOT + OUTPUT, 0o1777)
    results = []
    with open(out, "w") as log:
        for order in (variants, variants[::-1]):
            for case in CASES:
                for name, path in order:
                    result = run(launcher, name, path, case)
                    results.append(result)
                    log.write(json.dumps(result) + "\n")
                    log.flush()
    failures = [r for r in results if r["returncode"]]
    for r in failures:
        print(f"FAIL {r['variant']} {r['resident_mib']}/{r['peers']} {r['mode']} {r['sample']}: "
              f"rc={r['returncode']} {r['stderr'][-300:]}")
    print(f"{'case':34} {'variant':12} {'first ms':>10} {'warm median ms':>15} {'launch median ms':>17}")
    for case in CASES:
        outputs = {tuple(r["hashes"]) for r in results
                   if (r["resident_mib"], r["peers"], r["mode"], r["sample"]) == case and r["hashes"]}
        label = f"{case[0]}MiB/{case[1]}p {case[2]} {case[3]}"
        for name, _ in variants:
            runs = [r for r in results if r["variant"] == name and not r["returncode"]
                    and (r["resident_mib"], r["peers"], r["mode"], r["sample"]) == case]
            if not runs:
                print(f"{label:34} {name:12} {'-':>10}")
                continue
            first = [r["rows"][0]["total_s"] * 1e3 for r in runs]
            warm = [statistics.median(x["total_s"] * 1e3 for x in r["rows"][1:]) for r in runs]
            launch = [statistics.median(x["launch_s"] * 1e3 for x in r["rows"][1:]) for r in runs]
            print(f"{label:34} {name:12} {' / '.join(f'{v:.2f}' for v in first):>10} "
                  f"{' / '.join(f'{v:.2f}' for v in warm):>15} {' / '.join(f'{v:.2f}' for v in launch):>17}")
        if len(outputs) > 1:
            print(f"{label:34} OUTPUT MISMATCH across variants")
    print("interpreters observed:")
    for name, _ in variants:
        seen = {(i["path"], i["sha256"][:12]) for r in results if r["variant"] == name for i in r["interpreters"]}
        print(f"  {name}: {sorted(seen)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
