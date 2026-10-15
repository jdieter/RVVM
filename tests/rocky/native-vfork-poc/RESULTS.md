# Native shared-mm vfork feasibility POC

The allocation-free interpreter runs guest instructions in the actual kernel
`CLONE_VM | CLONE_VFORK | SIGCHLD` child. It avoids the eager guest-memory
backing/copy/restore service and requires no userfaultfd, capability, sysctl, or
device permission. This is a subset POC, **not a usable replacement yet**.
Development of the complete dispatcher is continuing separately; the patch and
results here freeze the measured prototype rather than claiming later changes
are validated by these numbers.

## Source and execution identity

- Isolated worktree: `/home/jdieter/resf/RVVM/worktrees/vfork-memory-poc`.
- Imported baseline archive: `/tmp/rvvm-native-vfork-current-source-20261013.tar.gz`,
  SHA256 `eee216b02d42c44b6f382a985291cc499e98a19efc1c585b75ce22a90eba80ad`.
  All earlier uncommitted main changes, including safe fastcopy, came from that
  snapshot; they are not changes made by this POC.
- `native-vfork.patch` is only the prototype source delta against that archive.
  Historical UFFD, softdirty and fastcopy artifacts remain under
  `../vfork-memory-poc/` and were not included in the prototype delta.
- DEV sources/output: `/var/tmp/rvvm-native-vfork-poc-20261013`.
- Matched Rocky static build container: `localhost/rvvm-heap-build-env:20261008`.
  Flags: `USE_GUI=0 USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1 USE_NO_LIBATOMIC=1`,
  `CFLAGS='-O3 -fPIE -DUSER_FAULT_META -DUSER_NATIVE_VFORK_POC'`,
  `LDFLAGS=-static-pie`.
- Deployed control SHA256:
  `0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`.
- Safe-fastcopy control SHA256:
  `2891cba7014d4f8422548497392b885a2022bf2a8c4f0eaecf55910b474b08af`.
  Rebuilding the fresh imported baseline reproduces this exact hash.
- Guarded prototype SHA256:
  `61dc0c9f324ff9d5f6cabdd16c7ac020f257fb02f6c5892037355c1797ee55fb`.
  Frozen source archive: `/tmp/rvvm-native-vfork-guarded-source-20261013.tar.gz`.
- Every guest benchmark runs as UID 993/GID 135. `credentials.log` verifies
  `CapEff=0`; DEV `vm.unprivileged_userfaultfd=0`. Root is used only to create a
  private mount namespace/proc mount and chroot, dropping credentials **before**
  launching the emulator. No host services, binfmt registration, sysctls, device
  permissions, packages or installed emulator were changed.

The native child borrows the kernel-suspended caller's TLS, with saved/restored
signal, CPU, SoftFloat and fault-jump state. It uses a preallocated CPU and native
stack and raw syscalls. JIT allocation/reclaim is disabled for this CPU. Child
signal dispositions are kernel-private; the child does not reset the parent's
global machine/reaper/descriptor registries. Instruction permission reads use a
preallocated snapshot to avoid a killable child taking the parent's mapping
lock. No guest-memory migration or full-region alias is performed; the source
entry bypasses all bulk-copy code and adds no vfork pipe/socket/memfd slots.

## Benchmarks

`comparison-guarded.jsonl` contains 36 interleaved process runs, 108 actual guest
launches, exact remote commands, output/statuses, rusage and individual hashes.
All outputs were valid. Each process launches three times; first is separate,
and the two later launches are warm. Three interleaved pairs per case reverse
order on the middle pair. The driver reserves 8 GiB of sparse anonymous address
space, touches the requested resident memory, and runs real concurrent peer
writes. It uses guest glibc `posix_spawn` to execute guest `/usr/bin/xz -cd`.

Warm total wall time medians (milliseconds), including launch and decompression:

| Parent/input | Deployed eager | Safe fastcopy | Native VFORK | Native warm range |
|---|---:|---:|---:|---:|
| 1 GiB / 8 peers / small module | 767.594 | 637.467 | 6.520 | 6.429–6.634 |
| 3 GiB / 96 peers / small module | 2048.831 | 1780.766 | 6.678 | 6.502–6.850 |
| 1 GiB / 8 peers / large amdgpu | 870.681 | 737.182 | 257.492 | 253.076–265.013 |
| 1 GiB / 8 peers / `/usr/bin/true` | 788.495 | 676.513 | 2.075 | 1.987–2.233 |

First launch total medians respectively were 6.744, 6.908, 267.051 and 2.149 ms
for native VFORK. The small module is 7,236 compressed / 58,437 decompressed
bytes; the large amdgpu sample is 17,022,044 / 164,902,725 bytes. These are retained
real kernel artifacts, not synthetic incompressible buffers.

The preceding hardened run (`comparison-final.jsonl`) shows aggregate guest plus
internal-helper CPU for warm small xz dropping from 731.3/614.5 ms to 6.75 ms at
1 GiB, and 1989.3/1755.7 ms to 6.72 ms at 3 GiB. Parent CPU increments drop from
20.8/21.7 to 0.30 ms and 84.8/86.1 to 1.08 ms respectively. Native child page
faults are ~1586/1589 minor, zero major; the large sample has ~87,175 minor.
Parent peak RSS is ~1,054,852 KiB / 3,192,580 KiB. A shared-mm child's rusage
high-water mark includes the parent's resident pages: adding parent and child
RSS would incorrectly claim duplicate physical memory. The helper/memfd backing
used by eager vfork is absent, but total physical memory was not separately
profiled. Zero bulk-copy bytes follows from the executed source path; no kernel
trace-based byte counter was collected.

These microbenchmarks establish the mechanism. They do not predict completion
time of a complete kernel RPM build.

## Correctness verified

Six fixtures pass in Sv39/Sv48 with JIT enabled and disabled in the parent;
the child is always interpreted. The 24-case matrix is in the retained DEV
`correctness-guarded.log`. `correctness-final.log` is the immediately preceding
same matrix before the final private-close/dup-source guard correction.

- Kernel writes to previously untouched shared pages, simultaneous parent
  writes, failed `execve(ENOENT)` errno writeback, successful exit and SIGKILL.
- Ordinary fork isolation after vfork; no eager mapping restoration is needed.
- Partial NONE/RO/write-only anonymous mappings, RO→RW, discard, private-file
  COW versus external page-cache writes, and actual SIGBUS/SIGSEGV termination.
- Actual child SIGSTOP freezes guest stores; SIGCONT resumes them. `wait4`
  accounts ~150 ms compute CPU to the child's PID.
- Repeated child SIGKILL during 4096-byte `openat2` requests while the parent
  continues native/guest allocation; 1,024 concurrent children retain distinct
  TLS ownership and failed-exec stores across the four modes.
- Kernel PID/PPID, parent/child TID publication, clear-tid cleanup and pidfds.
- Finite-AS shared writes; preparation ENOMEM rolls back without child creation
  or guest writes. Native hardware may create a vfork child at an already
  exceeded AS limit because it needs no emulator CPU/stack allocation: this
  extra preparation overhead remains a correctness/performance limitation.
- Existing 15 native harness fixtures pass on DEV and locally. The prototype
  does **not** pass the complete existing guest vfork fixtures: nofile/concurrent
  require unimplemented child mapping/descriptor actions, and the old PI test
  expects rejection specifically because the eager backend migrates futex keys.
  Those failures are not counted as acceptance or removed from the suite.

The raw fault jump uses internal static-glibc `__longjmp`: normal `siglongjmp`
unwinds the suspended lender's pthread cleanup stack. The matched ARM binary
was disassembled to verify the raw path avoids that cleanup. This is an explicit
platform qualification/portability gate, not a portable ABI promise.

## Required work before use

1. Replace the subset dispatch with audited complete existing syscall behavior.
   Child `mmap/brk/munmap/mremap`, execveat, many credential/session calls and
   `close_range` currently return ENOSYS; caught-signal arrival exits 125.
   Those are regressions from the existing backend, not permanent unsupported
   policy. No code/test/path name selects the backend; it is compile-gated only.
2. Execute the actual requested image through kernel/binfmt, preserving errno,
   argv[0], environment, NULL vectors and full argument limits. The prototype's
   faccessat/native-interpreter handoff is insufficient for malformed images,
   scripts, ETXTBSY, noexec, credentials, races and self-exec pin lifetime.
3. Parent-owned native pthread/futex service for allocation and mapping/FD
   metadata preparation and completion. Actual mapping/process kernel calls
   must remain in the child. Child death between kernel mutation and commit
   requires reconciliation before parent metadata may be used.
4. Coherent descriptor snapshot under the source guard across kernel clone;
   a separate prepared child FD guard/owner/TLS context, correct flag ABI
   translation, private pin relocation and complete close_range/self-exec.
5. Child-private signals/altstack/frame delivery and syscall restart/EFAULT
   semantics, with no inherited parent ptrace bridge or shared trusted locks.
   Direct guest pointer dereferences and private safe-syscall -512 returns must
   not escape as signals or guest errno. New exec/signal fixtures retain native
   assertions and will gate the complete implementation.
6. Live immutable executable metadata publication/reclamation: the current
   snapshot does not track parent peer changes to executable permissions.
7. Ptrace/notifications and process-context lifecycle; robust/native TLS
   qualification and allocator safety over the full child call graph.

The user has requested these gaps be implemented. This report freezes useful
feasibility evidence; it is not permission to integrate or deploy the subset.

## Reproduce

From this worktree, `python3 tests/rocky/native-vfork-poc/benchmark.py` runs the
matched guarded benchmark through SSH with the configured identity. Its JSONL
records contain self-contained commands. The matched build command used on DEV:

```sh
sudo -n podman run --rm \
  -v /var/tmp/rvvm-native-vfork-poc-20261013:/work:Z \
  localhost/rvvm-heap-build-env:20261008 \
  make -C /work -j12 USE_GUI=0 USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1 \
  USE_NO_LIBATOMIC=1 \
  CFLAGS='-O3 -fPIE -DUSER_FAULT_META -DUSER_NATIVE_VFORK_POC' \
  LDFLAGS=-static-pie BUILDDIR=release.native-poc \
  release.native-poc/rvvm_user_arm64
```

No commit, push, deployment or production experiment was performed.
