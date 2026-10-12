#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run independent Linux behavior probes and retain native/guest evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile


def execute(command, env, timeout, directory):
    with subprocess.Popen(command, env=env, cwd=directory, start_new_session=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            code = 124
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        return {"code": code, "stdout": stdout, "stderr": stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--emulator", type=Path)
    parser.add_argument("--reference", type=Path, action="append", default=[])
    parser.add_argument("--source", type=Path, help="fixture source for supplemental native references")
    parser.add_argument("--allow-cross-architecture-reference", action="store_true",
                        help="permit supplemental native references built from identical source")
    parser.add_argument("--expectations", type=Path,
                        default=Path(__file__).with_name("linux-compat-xfail.json"))
    parser.add_argument("--allow-known-failures", action="store_true",
                        help="inventory known gaps; default guest acceptance requires all PASS")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--case", action="append", help="run selected cases only")
    args = parser.parse_args()
    if args.emulator and not args.reference:
        parser.error("guest runs require native --reference results")
    if args.output.exists():
        parser.error("--output must be a new evidence file")
    binary = str(args.binary.resolve())
    emulator = str(args.emulator.resolve()) if args.emulator else None
    env = dict(os.environ, GLIBC_TUNABLES="glibc.pthread.rseq=0", RVVM_USER_PREFIX="")
    # The fixture's --list contains no feature probes.
    listing = subprocess.check_output(([emulator] if emulator else []) + [binary, "--list"],
                                      env=env, text=True, timeout=args.timeout)
    names = listing.splitlines()
    if args.case:
        if set(args.case) - set(names):
            parser.error("unknown --case name")
        names = [name for name in names if name in args.case]
    expected = json.loads(args.expectations.read_text()) if emulator else {}
    references = [(str(path), json.loads(path.read_text())) for path in args.reference]
    source_hash = hashlib.sha256(args.source.read_bytes()).hexdigest() if args.source else None
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    for path, reference in references:
        if reference["binary_sha256"] != binary_hash:
            if not (args.allow_cross_architecture_reference and source_hash
                    and reference.get("source_sha256") == source_hash):
                parser.error(f"{path}: reference must use the identical binary or explicitly matched source")
    results = {"binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
               "uname": list(os.uname()), "uid": os.geteuid(), "runs": {}}
    if emulator:
        results["emulator_sha256"] = hashlib.sha256(args.emulator.read_bytes()).hexdigest()
    if source_hash:
        results["source_sha256"] = source_hash
    modes = [(None, None)] if not emulator else [(b, j) for b in (39, 48) for j in (False, True)]
    failed = False
    for bits, nojit in modes:
        label = "native" if not emulator else f"sv{bits}-{'interpreter' if nojit else 'jit'}"
        selected = dict(env)
        selected.pop("RVVM_NOJIT", None)
        selected.pop("RVVM_USER_VA_BITS", None)
        if emulator:
            selected["RVVM_USER_VA_BITS"] = str(bits)
            if nojit:
                selected["RVVM_NOJIT"] = "1"
        rows = results["runs"][label] = {}
        for name in names:
            baselines = [(path, ref["runs"]["native"].get(name)) for path, ref in references]
            baseline = next(((path, row) for path, row in baselines if row and row["status"] == "PASS"), None)
            with tempfile.TemporaryDirectory(prefix="rvvm-linux-compat-") as directory:
                row = execute(([emulator] if emulator else []) + [binary, name],
                              selected, args.timeout, directory)
            code = row["code"]
            if emulator and not baseline:
                status = "UNVERIFIED"
                row["reason"] = "native reference did not pass; guest result retained, not coverage"
            elif not emulator:
                status = "PASS" if code == 0 else "SKIP" if code == 77 else "FAIL"
            elif code == 0:
                status = "XPASS" if name in expected else "PASS"
            elif code in (1, 77) and name in expected:
                status = "XFAIL"
                row["reason"] = expected[name]
            else:
                # Crashes and timeouts are never accepted as an expected assertion failure.
                status = "FAIL"
            row["status"] = status
            if baseline:
                row["reference"] = baseline[0]
            rows[name] = row
            print(f"{status} {label} {name} (exit {code})", flush=True)
            failed |= status in ("FAIL", "XPASS", "UNVERIFIED") or (
                emulator is not None and status == "XFAIL" and not args.allow_known_failures)
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
