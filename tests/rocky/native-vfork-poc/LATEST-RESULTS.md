# Latest native-vfork development benchmark

All 36 interleaved process runs succeeded: 108 launches, each with correct
exit status and individually verified output SHA256. Each process performs
one cold and two warmed launches. Three trials per variant/case are paired
in alternating order. Parent resident pages and concurrent peer writes are
real; each case also reserves 8GiB sparse virtual memory.

| Parent / workload | Deployed warm ms | Fastcopy warm ms | Latest warm ms | Latest cold ms |
| --- | ---: | ---: | ---: | ---: |
| 1GiB, 8 peers, small module xz | 744.111 | 662.024 | 6.272 | 6.653 |
| 3GiB, 96 peers, small module xz | 2070.283 | 1791.840 | 6.212 | 6.548 |
| 1GiB, 8 peers, large amdgpu xz | 883.273 | 722.191 | 256.960 | 265.784 |
| 1GiB, 8 peers, true | 810.097 | 665.519 | 2.184 | 2.420 |

Latest warmed ranges are 6.170–6.613ms, 6.056–6.322ms,
254.223–276.814ms and 2.072–2.646ms respectively. Warm launch-only medians
are 0.255ms, 0.240ms, 0.334ms and 0.262ms. Latest small-module/large-module
numbers remain comparable to the earlier guarded POC (6.520ms/256–257ms);
the added helper, signals and descriptor bookkeeping show no material
regression in these trials. This does not predict full kernel build time.

The latest **parent** uses the frozen candidate, SHA256
`c9cade03d35432df7ed37d2129133b8f645250e0f69d3084660e326afdd9dac4`.
Its source archive `/tmp/rvvm-native-vfork-usable-source.tar.gz` is SHA256
`f098cacb335ca26cf3b4a1d1a9e63781773b8c1c495776a6b252df922d1f1410`.
It includes owned fault jumps, caught guest signal/restart handling, real
kernel target exec and self/CLOEXEC handoff, parent-native-pthread allocation,
coherent private FD snapshot, raw private-pin relocation/close_range and
openat2 flag conversion. It retains zero bulk guest-memory copying.

After successful **exec**, xz uses the installed deployed interpreter through
the kernel's existing binfmt registration: `/usr/local/bin/rvvm-riscv64-static`,
SHA256 `0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`.
Three actual post-exec processes were observed in a dedicated untimed run;
all had UID993/GID135 and CapEff0. That observer finished before benchmarking.
These timings compare candidate pre-exec handling followed by installed xz
execution; they do not imply the candidate was installed or selected by
binfmt after exec.

The frozen candidate passed the full current default-mode POC gate set:
17 exec cases, both signal restart modes, private descriptors, real STOP/CONT
and child CPU accounting, repeated kill during delegated allocation, 256
concurrent vforks, shared/kernel stores, failed-exec writes, ordinary fork,
TID/clear-tid/pidfd, protection/discard/file-cache/fault handling and finite-AS
rollback. `correctness-usable.log` records the rerun. This remains an
experimental subset: general mapping transactions, live executable metadata,
ptrace and full syscall dispatch are incomplete. There was no deployment.

Raw evidence: `comparison-usable.jsonl`, `exec-identity-usable.jsonl`,
`correctness-usable.log`. Reproduce measurements with:

```sh
python3 tests/rocky/native-vfork-poc/benchmark.py \
  --native native-vfork-usable --output comparison-usable-repeat.jsonl
```

Matched build flags and isolated DEV launch procedure are in RESULTS.md;
DEVELOPMENT.md lists current changes and unresolved correctness boundaries.
