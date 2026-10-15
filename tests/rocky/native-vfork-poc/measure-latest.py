#!/usr/bin/env python3
"""Run one bounded dev sample and identify only its owned interpreters."""
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time

ROOT = "/var/lib/mock/rocky-10-riscv64-rvvm/root"
GUEST = "/tmp/rvvm-vfork-poc"
variant, mib, peers, sample = sys.argv[1:]
program = "/usr/bin/true" if sample == "true" else "/usr/bin/xz"
fixture = "module.xz" if sample == "true" else sample
output = f"/tmp/measure-{variant}-{mib}-{sample}"
command = (
    f"mount -t proc proc {ROOT}/proc && timeout -k 2 45 "
    f"chroot --userspec=993:135 {ROOT} {GUEST}/{variant} "
    f"{GUEST}/bench-spawn {mib} {peers} 4 {program} {GUEST}/{fixture} {output}"
)
run = subprocess.Popen(["unshare", "-m", "--propagation", "private", "sh", "-c", command],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                       start_new_session=True)
observed, seen, digests_by_inode = {}, set(), {}
deadline = time.monotonic() + 55
try:
    while run.poll() is None:
        queue = [run.pid]
        visited = set()
        while queue:
            pid = queue.pop()
            if pid in visited:
                continue
            visited.add(pid)
            try:
                for task in pathlib.Path(f"/proc/{pid}/task").iterdir():
                    queue.extend(map(int, (task / "children").read_text().split()))
                link = pathlib.Path(f"/proc/{pid}/exe")
                stat = link.stat()
                identity = (pid, stat.st_dev, stat.st_ino)
                if identity not in seen:
                    seen.add(identity)
                    path = os.readlink(link)
                    if "rvvm" in path or "installed-latest" in path or "native-prefix-latest" in path:
                        inode = (stat.st_dev, stat.st_ino)
                        if inode not in digests_by_inode:
                            digests_by_inode[inode] = hashlib.sha256(link.read_bytes()).hexdigest()
                        observed[str(identity)] = {"pid": pid, "path": path,
                            "sha256": digests_by_inode[inode]}
            except (OSError, ValueError):
                pass
        if time.monotonic() >= deadline:
            os.killpg(run.pid, signal.SIGKILL)
            raise TimeoutError("owned benchmark timed out")
        time.sleep(0.05)
    stdout, stderr = run.communicate()
finally:
    if run.poll() is None:
        os.killpg(run.pid, signal.SIGKILL)
        run.wait()
rows = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
digests = [hashlib.sha256(pathlib.Path(ROOT + output + f"-{i}").read_bytes()).hexdigest()
           for i in range(4)] if run.returncode == 0 else []
print(json.dumps(dict(variant=variant, resident_mib=int(mib), peers=int(peers),
    sample=sample, returncode=run.returncode, rows=rows, hashes=digests,
    interpreters=list(observed.values()), stdout=stdout, stderr=stderr)), flush=True)
sys.exit(run.returncode)
