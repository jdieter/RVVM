#!/usr/bin/env python3
"""Interleave isolated guest xz runs and retain exact output and hashes."""
import hashlib
import json
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = "/var/lib/mock/rocky-10-riscv64-rvvm/root"
GUEST = "/tmp/rvvm-vfork-poc"
HOST = "fedora@3.144.135.42"
SSH = ["ssh", "-F", "/home/jdieter/.ssh/config", HOST]
EXPECTED = {
    "module.xz": "251aa1f6b8df216e423df6fef0c7db76876ff9cd36d183445b7bcdd19b979bb1",
    "large-module.xz": "43a55f4bec22ad9912a75dcc3e57fa999e66b9304ee513ff2b23db1388a8d5a7",
    "true": hashlib.sha256(b"").hexdigest(),
    "ro-module.xz": "251aa1f6b8df216e423df6fef0c7db76876ff9cd36d183445b7bcdd19b979bb1",
}
output = HERE / "fastcopy-comparison.jsonl"
variants = sys.argv[1:] or ["baseline", "fastcopy"]
failures = 0
cases = [(0, 0, "module.xz"), (256, 8, "module.xz"),
         (1024, 8, "module.xz"), (3072, 96, "module.xz"),
         (1024, 8, "true"), (1024, 8, "large-module.xz"),
         (1024, 8, "ro-module.xz")]
with output.open("a") as stream:
    for mib, peers, sample in cases:
        for pair in range(3):
            order = variants if pair % 2 == 0 else variants[::-1]
            for variant in order:
                program = "/usr/bin/true" if sample == "true" else "/usr/bin/xz"
                fixture = "module.xz" if sample in ("true", "ro-module.xz") else sample
                readonly = f" {GUEST}/large-module.xz" if sample == "ro-module.xz" else ""
                command = (
                    f"sudo -n unshare -m --propagation private sh -c '"
                    f"mount -t proc proc {ROOT}/proc && "
                    f"timeout 120 chroot {ROOT} {GUEST}/{variant} "
                    f"{GUEST}/bench-spawn {mib} {peers} 3 {program} "
                    f"{GUEST}/{fixture} {GUEST}/output{readonly} && "
                    f"sha256sum {ROOT}{GUEST}/output-0 {ROOT}{GUEST}/output-1 {ROOT}{GUEST}/output-2'"
                )
                start = time.monotonic()
                run = subprocess.run(SSH + [command], capture_output=True, text=True, timeout=150)
                stdout, stderr = run.stdout, run.stderr
                rows = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
                digests = [line.split()[0] for line in stdout.splitlines()
                           if len(line.split()) == 2 and len(line.split()[0]) == 64]
                digest = digests[-1] if rows and run.returncode == 0 and digests else None
                record = dict(variant=variant, resident_mib=mib, peers=peers, sample=sample,
                              pair=pair, remote_command=command, returncode=run.returncode,
                              wall_s=time.monotonic() - start, rows=rows, stderr=stderr,
                              stdout=stdout, output_sha256=digest,
                              output_sha256s=digests,
                              output_valid=len(digests) == 3 and all(v == EXPECTED[sample] for v in digests))
                stream.write(json.dumps(record) + "\n")
                stream.flush()
                print(json.dumps({key: record[key] for key in
                                  ("variant", "resident_mib", "peers", "sample", "pair",
                                   "returncode", "output_valid", "wall_s")}), flush=True)
                if run.returncode or not record["output_valid"]:
                    failures += 1
if failures:
    raise SystemExit(f"{failures} benchmark runs failed; raw output retained")
