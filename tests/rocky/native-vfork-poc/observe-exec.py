#!/usr/bin/env python3
"""Read-only host observer: prove the post-exec xz interpreter identity."""
import hashlib
import json
import pathlib
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--seconds", type=float, default=15)
options = parser.parse_args()
seen = set()
deadline = time.monotonic() + options.seconds
while time.monotonic() < deadline:
    for task in pathlib.Path("/proc").iterdir():
        if not task.name.isdecimal() or task.name in seen:
            continue
        try:
            args = (task / "cmdline").read_bytes().split(b"\0")
            if b"/usr/bin/xz" not in args or b"-cd" not in args:
                continue
            identity = (task / "exe").readlink()
            digest = hashlib.sha256((task / "exe").read_bytes()).hexdigest()
            status = (task / "status").read_text()
            credentials = [line for line in status.splitlines()
                           if line.startswith(("Uid:", "Gid:", "CapEff:"))]
            print(json.dumps(dict(pid=int(task.name), executable=str(identity),
                                  sha256=digest, credentials=credentials)), flush=True)
            seen.add(task.name)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    time.sleep(0.01)
