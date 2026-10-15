#!/usr/bin/env python3
"""Matched unprivileged launches, individually hash-checked, interleaved."""
import hashlib
import json
import pathlib
import subprocess
import argparse
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = "/var/lib/mock/rocky-10-riscv64-rvvm/root"
GUEST = "/tmp/rvvm-vfork-poc"
SSH = ["ssh", "-F", "/home/jdieter/.ssh/config", "fedora@3.144.135.42"]
EXPECTED = {
    "module.xz": "251aa1f6b8df216e423df6fef0c7db76876ff9cd36d183445b7bcdd19b979bb1",
    "large-module.xz": "43a55f4bec22ad9912a75dcc3e57fa999e66b9304ee513ff2b23db1388a8d5a7",
    "true": hashlib.sha256(b"").hexdigest(),
}
parser = argparse.ArgumentParser()
parser.add_argument("--native", default="native-vfork")
parser.add_argument("--output", default="comparison-guarded.jsonl")
options = parser.parse_args()
variants = ["baseline", "fastcopy", options.native]
cases = [(1024, 8, "module.xz"), (3072, 96, "module.xz"),
         (1024, 8, "large-module.xz"), (1024, 8, "true")]
failures = 0
with (HERE / options.output).open("a") as stream:
    for mib, peers, sample in cases:
        for pair in range(3):
            for variant in (variants if pair % 2 == 0 else variants[::-1]):
                program = "/usr/bin/true" if sample == "true" else "/usr/bin/xz"
                fixture = "module.xz" if sample == "true" else sample
                output = f"/tmp/native-vfork-benchmark-{variant}-{mib}-{pair}"
                command = (
                    f"sudo -n unshare -m --propagation private sh -c 'ulimit -c 0; "
                    f"mount -t proc proc {ROOT}/proc && "
                    f"timeout 120 chroot --userspec=993:135 {ROOT} {GUEST}/{variant} "
                    f"{GUEST}/bench-spawn {mib} {peers} 3 {program} {GUEST}/{fixture} {output} && "
                    f"sha256sum {ROOT}{output}-0 {ROOT}{output}-1 {ROOT}{output}-2'"
                )
                start = time.monotonic()
                run = subprocess.run(SSH + [command], text=True, capture_output=True, timeout=150)
                rows = [json.loads(line) for line in run.stdout.splitlines() if line.startswith("{")]
                hashes = [line.split()[0] for line in run.stdout.splitlines()
                          if len(line.split()) == 2 and len(line.split()[0]) == 64]
                valid = (run.returncode == 0 and len(rows) == 3
                         and [row.get("trial") for row in rows] == [0, 1, 2]
                         and len(hashes) == 3 and all(h == EXPECTED[sample] for h in hashes))
                record = dict(variant=variant, resident_mib=mib, peers=peers, sample=sample,
                              pair=pair, command=command, returncode=run.returncode,
                              wall_s=time.monotonic() - start, rows=rows,
                              hashes=hashes, valid=valid, stdout=run.stdout, stderr=run.stderr)
                stream.write(json.dumps(record) + "\n")
                stream.flush()
                print(json.dumps({k: record[k] for k in ("variant", "resident_mib", "sample", "pair", "returncode", "valid")}), flush=True)
                failures += bool(run.returncode or not valid)
if failures:
    raise SystemExit(f"{failures} failed runs; raw output retained")
