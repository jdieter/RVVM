# vfork memory POCs

These are historical feasibility experiments. The user subsequently ruled out
production solutions requiring privileged access, so the UFFD approach below
is not an accepted production direction. The later nonprivileged candidate
and verified measurements are in [FASTCOPY-RESULTS.md](FASTCOPY-RESULTS.md).

This isolated worktree starts at rocky commit
`0b3dbc0a2714f52b10481671ec40ef2daa87eeac`. Its source baseline is the
current deployed, uncommitted userspace implementation imported from
`/tmp/rvvm-vfork-current-source-20261013.tar.gz` (SHA256
`cb325405bf9940463c9c405a07e1d4934266e7cf28e4a79813fe5647d1693858`).
Imported source changes are baseline changes, not part of either experiment.
No production or binfmt installation is performed by these experiments.

## Methods and correctness gates

Compare the existing eager migration with two actual emulator implementations:

* Lazy anonymous shmem population using kernel-origin-capable userfaultfd.
* Persistent anonymous shmem caching, refreshed using host soft-dirty bits,
  with explicit child dirty reporting before successful exec and conservative
  full comparison after exit or uncertain mapping changes.

Both initially retain eager migration for private file mappings. This protects
page-cache coherence and beyond-EOF SIGBUS behavior while measuring the large
anonymous heaps that dominate the observed rpmbuild workload.

`bench-spawn.c` is a statically linked RISC-V guest, not a host stand-in. It
populates configurable anonymous memory, reserves an additional sparse 8 GiB,
starts up to 96 guest threads which write separate heap pages, and uses glibc
posix_spawn to execute the guest xz. The existing RVVM CLONE_VM|CLONE_VFORK
path handles those launches. Reported launch time includes the emulator's
restoration before returning to the caller; xz may have already completed.
The read-only-file case additionally maps and touches the 17 MB compressed
amdgpu file privately in the caller, while decompressing the small module.

Inputs are actual retained Rocky kernel modules: the small
`pkcs8_key_parser.ko.xz` and the 17,022,044-byte compressed debug
`amdgpu.ko.xz`, from kernel 6.12.0-211.56.1.el10_2.0.1. Their decompressed
SHA256s, independently obtained with host xz, are respectively
`251aa1f6b8df216e423df6fef0c7db76876ff9cd36d183445b7bcdd19b979bb1` and
`43a55f4bec22ad9912a75dcc3e57fa999e66b9304ee513ff2b23db1388a8d5a7`.
The launch-only control executes guest `/usr/bin/true` with the same caller.

`test-sharing.c` verifies a kernel read into a fresh shared page, concurrent
parent-thread stores seen by the child, a RO-to-RW transition, failed exec
error writeback, child SIGKILL after a store, and ordinary fork isolation after
each vfork. Native x86 Linux and the unchanged guest emulator both pass.
Existing assembly vfork tests additionally exercise descriptor limits,
concurrent callers, mapping changes, and successful exec release.

The dev host is Fedora 44 ARM64 with kernel 6.19.10-300.fc44.aarch64.
Its userfaultfd sysctl is 0 and `/dev/userfaultfd` is root-only. UFFD POC
execution uses an isolated sudo launch; host permissions and sysctls remain
unchanged. Guest programs run in a private mount namespace with proc mounted
inside the retained test buildroot so executable-descriptor handoff works.

## Reproduction

Common driver binaries are under
`/var/lib/mock/rocky-10-riscv64-rvvm/root/tmp/rvvm-vfork-poc` on dev.
The native ARM experimental sources and builds are under
`/var/tmp/rvvm-vfork-memory-poc-20261013/{uffd,softdirty}`.

Compile the common guest sources with native clang using the retained
RISC-V sysroot:

```sh
clang --target=riscv64-linux-gnu \
  --sysroot=/var/lib/mock/rocky-10-riscv64-rvvm/root \
  -B/var/lib/mock/rocky-10-riscv64-rvvm/root/usr/lib/gcc/riscv64-redhat-linux/14 \
  -L/var/lib/mock/rocky-10-riscv64-rvvm/root/usr/lib/gcc/riscv64-redhat-linux/14 \
  -fuse-ld=lld -march=rv64gc -mabi=lp64d -O2 -pthread -static \
  bench-spawn.c -o bench-spawn
```

`benchmark.py` records the exact SSH and isolated launch commands in its raw
JSONL output, checks all exit statuses and output hashes, and interleaves
variants over three independent caller processes. Each caller performs three
launches, retaining first versus warmed timings. It fails on any correctness
or output error rather than reporting a speedup from a failed run.

The production-matching build uses the existing Rocky container image
`localhost/rvvm-heap-build-env:20261008` on dev:

```sh
make -j12 USE_GUI=0 USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1 \
  USE_NO_LIBATOMIC=1 CFLAGS='-O3 -fPIE -DUSER_FAULT_META' \
  LDFLAGS=-static-pie BUILDDIR=release.matched \
  release.matched/rvvm_user_arm64
```

Apply `uffd.patch` or `softdirty.patch` separately to copies of this worktree's
baseline source. Both patches pass `patch --dry-run -p1` against it. Neither
patch is applied to the baseline in this worktree. These are alternative
experiments, not patches to apply together.

An unchanged rebuild with these flags exactly reproduces the deployed baseline
SHA256 `0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`.
The final UFFD binary is
`fe51a1570a6a3d6ce11108fcfb8843b4f55a1dae31ff06b5ccfe4fc5db861c85`;
the capability-gated soft-dirty binary is
`34714e7623200dc9c28f997e8ec357936737440c3de95883a8c2e730404937d5`.

## Results

The final campaign passed all 63 caller-process runs and all 189 actual guest
launches. Every launch writes a separate output file, verified independently
against host xz's reference SHA256. No failed or unsupported run is counted as
a speedup. `raw-comparison.jsonl` retains exact commands, stdout, stderr, CPU,
RSS, page faults, counters and hashes. `summary.json` is reproducible with
`python3 summarize.py`.

Warmed total wall times include both launch and child completion. Each median
uses six launches from three independent caller processes; parentheses show
the minimum and maximum. Times are milliseconds.

| Caller / work | Eager baseline | UFFD lazy sharing | Soft-dirty POC on ARM |
| --- | ---: | ---: | ---: |
| Small caller, small module | 17.45 (17.05–17.58) | 10.45 (10.23–10.62) | 19.26 (19.02–19.37) |
| 256 MiB, 8 peers, small module | 188.75 (176.23–226.25) | 16.60 (16.03–17.29) | 201.30 (199.71–210.39) |
| 1 GiB, 8 peers, small module | 764.29 (666.20–775.74) | 35.56 (31.62–38.28) | 755.46 (724.64–767.37) |
| 3 GiB, 96 peers, small module | 2054.74 (2032.75–2088.81) | 104.11 (101.73–105.01) | 2043.72 (2018.96–2094.50) |
| 1 GiB, 8 peers, launch-only true | 744.81 (730.80–777.45) | 32.37 (31.41–35.45) | 757.11 (746.00–767.58) |
| 1 GiB, 8 peers, large module | 853.55 (832.62–869.33) | 295.68 (292.46–297.11) | 854.80 (815.13–880.27) |
| 1 GiB, 8 peers, small module + 17 MB RO file | 780.50 (762.66–804.38) | 60.83 (58.24–62.51) | 784.07 (767.04–788.05) |

The soft-dirty column is **correctness fallback, not accelerated caching**.
The actual write probe proves this ARM kernel does not implement bit 55:
before, after clearing, and after writing all remain `8100000000000000`.
The same probe works on local x86, but that accelerated path was not accepted
or benchmarked as a working implementation. Early ungated ARM measurements
were corrupt and are deliberately excluded. See `SOFTDIRTY-POC.md`.

First versus warmed launch medians, excluding subsequent child completion:

| Caller / small module | Eager first / warm | UFFD first / warm | Soft-dirty fallback first / warm |
| --- | ---: | ---: | ---: |
| Small caller | 19.47 / 11.62 | 18.51 / 4.44 | 26.14 / 13.41 |
| 256 MiB, 8 peers | 214.54 / 188.43 | 23.09 / 11.42 | 211.44 / 201.00 |
| 1 GiB, 8 peers | 757.54 / 763.97 | 51.30 / 32.04 | 745.55 / 755.13 |
| 3 GiB, 96 peers | 2074.23 / 2054.42 | 120.08 / 103.79 | 2059.46 / 2043.37 |

For the realistic large-caller/small-child case, UFFD reduces total wall time
about 19.7 times. Aggregate child/service CPU drops from 2018.5 ms to 75.3 ms;
the eager implementation must copy at least the 3 GiB resident heap on every
launch. The UFFD counter measures 309 pages (1,265,664 bytes) populated and
compared, about 397–406 KB copied back, and actual shared backing allocation
of 1,265,664 bytes using `fstat(st_blocks)`. The 1 GiB case needs only 45 pages
or 184,320 bytes of shared backing, with 36,864 bytes copied back.

Parent and child peak RSS remain approximately 3.05–3.06 GiB in the 3 GiB case:
the caller's resident heap still exists. RSS alone does not account for the
eager temporary memfd page-cache allocation. The benchmark records both RSS
and the UFFD backing counter; eager backing allocation was not instrumented
directly. Minor-fault counts remain about 1950–2005; UFFD introduces two
reported child major faults per launch, versus zero for eager/fallback.
Full per-case CPU/RSS/fault/copy ranges are in `summary.json`.

For the large 165 MB decompressed module, useful decompression work dominates
more of the result: total time improves about 2.9 times, rather than the
roughly 20 times observed for small modules. The microbenchmarks do not predict
an entire kernel RPM build's elapsed time.

## Correctness findings and deployment gates

The final UFFD build passes the common sharing probe and the existing
`test-vfork`, `test-vfork-concurrent`, and `test-vfork-nofile` fixtures. A
privileged native VM-runtime test additionally passes sparse memory,
private-file COW, external file changes, beyond-EOF SIGBUS, and restored
ordinary-fork COW. The native `uffd-runtime-probe.c` passes on dev, servicing
kernel read() writes into missing shared pages in both parent and child,
including an actual fork event. Its registered ioctl mask is `0x13c`.

These tests exposed two genuine handler bugs, fixed in the final patch:
COPY/EEXIST requires an explicit WAKE for a competing waiter; COPY/EAGAIN
must be queued while fork events continue to be processed. Busy retrying
EAGAIN deadlocks against the pending fork notification. The final 96-peer
trials exercise 66–70 such retries per launch without lost wakes or deadlock.
Earlier failing revisions and campaigns are retained as diagnostic evidence,
separate from the final campaign. An initial build-flags mismatch was also
corrected before acceptance: missing USER_FAULT_META caused the same startup
failure in both POC and unmodified baseline builds.

**Production does not permit this out of the box.** The root agent's live
probe on Rocky 10.2 ARM64 kernel 6.12.0-211.64.1.el10_2 establishes that the
kernel supports the required API, shared-memory missing registration and COPY.
However actual rpmbuild credentials (UID 993, GID 135, no supplementary groups,
CapEff 0, Seccomp 0) get EPERM from userfaultfd and EACCES opening
`/dev/userfaultfd`. The host sysctl is 0 and the device is root-owned 0600.
Privileged dev timings establish feasibility, not permission to deploy. No
production settings were changed. The current POC creates the descriptor with
the syscall; a production device-based policy would also need code to use
`/dev/userfaultfd`'s creation ioctl.
The live evidence is retained in
[/tmp/rvvm-production-userfaultfd-20261013.md](/tmp/rvvm-production-userfaultfd-20261013.md).

Neither POC should ship. UFFD still needs synchronization with metadata
splits/reallocation and mapping mutations, review of native pthread/TLS
lifecycle inside the separate CLONE_VM resource group, a deliberate
permission/feature fallback policy, finite-limit tests, and wider child-death
and mapping races. It does not implement write-protect tracking and retains
eager copying for private files. Cached soft-dirty has additional unsupported
host, cache eviction and invalidation gaps; its accelerated path remains
unverified even on a capable architecture. See the separate POC notes.

The measured result favors **hardening the UFFD approach**, subject to an
explicit host-access policy. The suggested soft-dirty alternative cannot
provide the expected acceleration on these ARM build hosts. Main checkout,
installed emulator binaries, binfmt, services and host settings are unchanged.

## Next implementation work

1. Make region lookup and alias lifetime safe under mapping mutations. Use an
   immutable or locked registry with explicit lifetime ownership, synchronize
   registration/unregistration and queued faults with split/remap/discard,
   and test concurrent guest threads mutating mappings while faults arrive.
2. Move fault servicing onto a reviewed native helper lifecycle. Prefer a
   helper created in the primary host thread group with a private FD table,
   rather than creating pthreads inside the borrowed-TLS resource process.
   Keep handlers allocation-free during host fork and verify ordinary fork,
   successful/failed exec, signals and abrupt process death.
3. Add a feature/permission probe and an atomic fallback to the existing eager
   implementation. Decide and separately authorize host access policy before
   deployment; device access requires implementing its descriptor-creation
   ioctl and checking the actual Mock/nspawn device view.
4. Cover finite AS/DATA/NOFILE and cgroup limits, allocation failures, backing
   failures, wider mapping/protection/discard transitions, and stress races.
   Retain matching JIT/interpreter tests and the large xz spawn benchmark.
5. After those gates, run the current userspace regression suite, glibc in
   RPM launch context, and an actual kernel RPM build on dev. Neither this
   POC nor the microbenchmark authorizes production delivery.
