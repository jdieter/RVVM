# RVVM vfork replacement handoff

## Goal and authorization

We are replacing RVVM's expensive userspace vfork backend. Kernel builds
regressed because launching children copied large amounts of parent memory.
The replacement uses native shared-memory vfork and already has a large
measured speedup, but it is not ready to merge.

Jonathan explicitly asked to remove the old backend: this branch won't be
merged until the replacement is as good as the old one. Do not restore the
old backend as a fallback. Preserve existing functionality and real kernel
credentials, descriptor limits, process identity and syscall behavior.

The currently authorized work is to finish the observer design described
below, then run the full gamut of tests on dev. Commits, merging, production
deployment and global host configuration changes are not authorized by this
task. Do not actually exercise reboot on dev. Do not use a solution requiring
privileged userfaultfd access.

## Checkout and current state

- Main: `/home/jdieter/resf/RVVM`, branch `rocky`, clean at `cda8f13` when
  this handoff was written. Leave it alone.
- Worktree: `/home/jdieter/resf/RVVM/worktrees/vfork-memory-poc`, branch
  `vfork-memory-poc`, based on `0b3dbc0`, with substantial uncommitted work.
- This worktree includes earlier userspace changes subsequently committed
  on rocky. A diff against its old HEAD is not just the vfork replacement.
  Reconcile against current rocky before eventually preparing commits.
- Important new headers and tests are untracked. Plain `git diff` and
  `git diff --stat` omit them. Preserve the whole worktree.
- The Codex implementation agent is stopped. No merge or deployment occurred.
  Its latest turn ended with an automated cybersecurity flag. Neither root
  nor the agent was given the triggering operation. The last reported
  completed result was the integrated 48-case ARM test below.

Start with `RESUME.md` in this directory. Its opening paragraphs are current;
later sections contain historical checkpoints and superseded limitations.
`DEVELOPMENT.md`, `RESULTS.md` and `LATEST-RESULTS.md` also contain older
designs and measurements; don't treat every statement there as current.

## Runtime already implemented

The old eager-copy service/VM backend is deleted in this worktree.

- Shared-mm VFORK uses real native `CLONE_VM|CLONE_VFORK`. The actual native
  child interprets guest instructions; execution isn't proxied through the
  parent's CPU state. The real caller is blocked by kernel VFORK semantics.
- VFORK without CLONE_VM uses native COW and recovers a child-private runtime.
  Static glibc fork recovery is wrapped; this remains platform-sensitive.
- A trusted parent pthread owns allocations and mutable emulator metadata.
  Killable shared-mm children avoid shared libc allocation and lock ownership.
- Both syscall loops use `rvvm_user_kernel_dispatch.h`: 239 common routes at
  the last completed consolidation milestone. Keep conversions shared rather
  than adding a second independent syscall implementation.
- Child-private signals, tracing/replay state, fake credentials and executable
  identity are implemented. Borrowed calling-thread TLS is restored after
  kernel VFORK release, including child death.
- Focused ARM tests passed tracing register/syscall stops, VFORK/exec/exit
  events, child-as-tracer behavior with 40 peers, allocation ownership beyond
  the old 32-record ceiling, descriptor relocation, signals, fake-root and
  path-prefix behavior. These passes refer to their recorded checkpoints;
  they do not qualify every later edit.
- Build gating still uses `USER_NATIVE_VFORK_POC`. Do not call the default
  build production-ready without auditing/removing the gate after parity.

## Why the observer is being added

There are two core correctness problems.

### Clone snapshot completion

The worker holds descriptor, signal and sometimes allocator/MM locks while
Linux copies the child's native state. Those locks must be released even if
the child stops before its first emulator callback, so parent peers can run.

Originally the backend used clone3's parent_tid output as an internal kernel
completion marker. It couldn't simultaneously preserve the application's
actual parent-TID store. A later implementation used an internal shared
CHILD_SETTID cell when guest child-TID flags were unused. Mixed PTID/CTID
flags still needed a separate witness.

Don't fix this with delayed userspace writes to guest TID buffers. Preserve
kernel ordering, fault behavior and clear-TID semantics. An internal PIDFD
in the guest's table would introduce EMFILE at a full/zero descriptor limit.

The new observer has private files and limits, pinned proc interfaces and
an owner TGID pidfd. It uses raw syscalls and doesn't execute guest operations.
It detects snapshot completion without consuming guest TID outputs:

- Shared-mm child: a fresh memfd-backed marker mapping gives a unique inode.
  The observer scans the actual caller's children and their maps for it.
  Known pre-existing same-mm owners/helpers must be excluded.
- COW child: a fresh protected private page becomes shared in the parent's
  pinned smaps. The parent mmap lock taken by the kernel during duplication
  is part of the ordering argument; one copied page alone isn't a proof that
  an entire snapshot is complete without that serialization.

A newly listed PID alone is unsafe: subreapers/init can adopt unrelated
descendants. An older COW descendant lacks the newly created marker; an
existing same-mm child gains it automatically and needs explicit exclusion.
Mapping-helper creation and other relevant clone paths must serialize with
marker enrollment so a newly published helper isn't mistaken for the child.

### Mapping-helper death

The parent owns metadata, but a raw helper executes mapping syscalls using
the guest child's credentials, limits, files and MM. It can die after the
kernel changes mappings but before publishing the return value. The current
fail-closed path can terminate the parent process, which has a larger impact
than the old isolated-child backend's similar failure policy.

The proposed repair is an operation journal plus authoritative reconciliation
of actual kernel VMAs on helper death or partial errors. Do not replay a
possibly committed MAP_FIXED/mremap operation blindly. A success/error bit
is insufficient: mprotect can change an earlier VMA, then fail at a hole.

To make execute intent recoverable, the native backend now retains host
PROT_EXEC while also allowing READ for instruction decoding. Previously guest
EXEC became only host READ, making execution intent invisible in proc maps.
This representation has passed focused ARM checks; complete recovery has
not been implemented or proven. Audit noexec/LSM and execute-only behavior.

## Latest verified observer checkpoint

The first integrated observer candidate passed all 48 `test-parent-tid.c`
cases on ARM as UID 993/GID 135:

- Shared and private-mm VFORK.
- Actual parent/child kernel stores and clear-TID behavior.
- Valid, NULL and PROT_NONE parent buffers.
- Child STOP/CONT/KILL and parent-peer malloc/sigaction progress.

Source archive SHA256:
`64375aa4f0840f0f9dde58365132556e6d321b65be131f67158b5378c4f486a8`

ARM binary SHA256:
`c7b27c4df226c16687f6d21c9013697f1204d20d0805fa7935d17daa572160a1`

Dev artifacts are under
`/var/tmp/rvvm-native-vfork-poc-20261013/observer/`, including
`release.native-observer/rvvm_user_arm64`; source is retained as
`observer-source.tar.gz` at the artifact root. Local source archive:
`/tmp/rvvm-native-observer-source.tar.gz`.

Later local source edits reset inherited observer clients/locks after fork
and stream large child lists. They are explicitly not qualified by the
48-case binary above. Inspect the current source and rebuild before testing.

Foundation tests also passed native x86 and ARM without capabilities:
`test-snapshot-witness.c`, `test-observer-private-files.c`,
`test-observer-adoption.c` and `test-observer-owner-exit.c`. They cover zero
hard NOFILE, dumpability zero, pinned proc across chroot/detached mounts,
adoption discrimination, and owner death after its last thread exits.

## Unfinished work

1. Qualify the latest fork-reset and child-list streaming edits. Check
   observer initialization/call locks and copied client ownership in both
   ordinary fork and private VFORK.
2. Hide the persistent observer from guest process and wait interfaces.
   Merely filtering its exit event is insufficient: a live internal child
   changes wait(-1) ECHILD/blocking. exit_signal=0 excludes ordinary SIGCHLD
   waits, but __WALL/__WCLONE and waitid classes still need correct handling.
   Explicit internal PID access and proc enumeration also need treatment.
3. Implement namespace PID translation. Pinned proc uses its mount's PID
   namespace; caller gettid() may use another one. Don't format one as the
   other. Pending PID-namespace and init handling remain unqualified.
4. Finish mapping journaling/reconciliation and helper-death recovery. This
   is still a proposed design, not a completed algorithm. Prove unknown mmap
   return addresses, MAP_FIXED replacement, mremap and partial failures can
   be reconciled without ambiguity before claiming correctness.
5. Fix the existing partial-mprotect execution bug. Native x86/ARM pass
   `test-mprotect-partial-exec.c`; installed and pre-observer candidate fail:
   mprotect removes X from an early page but returns ENOMEM at a later hole,
   while RVVM leaves execute permission in its registry. The separate
   --kernel-only representation probe passed; the default guest-jump
   regression must still require SIGSEGV and pass after the actual fix.
6. Audit observer provisioning after COW under inherited hard NOFILE=0 and
   dumpability=0. The old observer has another mm and can't open a
   nondumpable child's maps; a new observer inherits hard0 and can't open
   proc files. Existing maps FDs remain bound to their original mm.
   `test-observer-cow-limits.c` passes natively but the installed baseline
   fails with EMFILE. That establishes an inherited limitation for that
   exact nested mixed-TID case, not permission to regress other successful
   zero-limit paths or claim full native parity.
7. Finish remaining platform/CET/static-glibc and launch-context qualification.
   Then remove experimental gating appropriately and run final acceptance.

## Code map

- `src/core/rvvm_user_native_vfork.h`: clone, worker, raw mapping helper,
  child runtime and borrowed TLS restoration.
- `src/core/rvvm_user_observer.h`: new observer protocol and witnesses.
- `src/core/rvvm_user_kernel_dispatch.h`: shared syscall conversion/routes.
- `src/core/rvvm_user_memory.h`, `rvvm_user_vma.h`: executable snapshots and
  mapping bookkeeping.
- `src/core/rvvm_user.c`, `rvvm_user_fork.h`: integration and fork recovery.
- `src/core/user_ptrace/`: child-private tracing/replay contexts and adapters.
- This directory: observer/TID/lifecycle/proc fixtures and benchmark evidence.
- `tests/rocky/TODO.txt`: known gaps, including partial mprotect.

## Build and dev test context

Dev SSH: `ssh -F /home/jdieter/.ssh/config fedora@3.144.135.42`.
The ARM dev server is the approved experiment system. Don't replace its
installed interpreter or change binfmt registration to test a candidate.

Artifacts: `/var/tmp/rvvm-native-vfork-poc-20261013`.
Retained RISC-V root: `/var/lib/mock/rocky-10-riscv64-rvvm/root`.
Build image: `localhost/rvvm-heap-build-env:20261008`.

Matched build settings (consult the Makefile for target/output names):

```text
USE_GUI=0 USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1 USE_NO_LIBATOMIC=1
CFLAGS='-O3 -fPIE -DUSER_FAULT_META -DUSER_NATIVE_VFORK_POC'
LDFLAGS=-static-pie
```

Use CCACHE_DISABLE=1 locally when needed. Test candidates explicitly, with
bounded timeouts and cleanup. Dev guest fixtures use a private mount
namespace with proc mounted inside the retained root, then UID993/GID135
and no capabilities. A previous GCC failure was incorrectly attributed to
PTID: the real cause was a missing private proc mount. GCC passed the earlier
candidate under the proper launch context.

Use quick directed tests while implementing. When complete, Jonathan has
asked for full Rocky regressions, native/emulated differential and lifecycle
tests, full glibc in the actual RPM launch context, representative builds,
and matched performance checks. `tests/rocky/run-tests.sh` is one entry point;
it is not a substitute for the full acceptance work. Don't count skipped or
UNSUPPORTED tests as passes. The replacement has not completed that work.

## Performance: measured before observer integration

`latest-prefix-performance.jsonl` and `measure-latest.py` retain a matched dev
comparison: four launches per variant/case, discard first, median of three.
All 40 output hashes/statuses were verified.

| Workload | Installed | Prefix candidate |
|---|---:|---:|
| Small xz, 1 GiB parent / 8 peers | 697.26 ms | 7.31 ms |
| Small xz, 3 GiB parent / 96 peers | 1,981.43 ms | 6.91 ms |
| Exec true, 1 GiB parent | 695.45 ms | 4.56 ms |
| Exec true, 3 GiB parent | 2,017.65 ms | 4.31 ms |
| Large debug amdgpu xz, 1 GiB parent | 717.32 ms | 186.82 ms |

Measured candidate:
`c64d64ac142ed79a763119d02ae09d644ad6b12ae0625af56567070f2cddbf07`.
Installed baseline and both variants' actual post-exec interpreter:
`0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`.
Thus these measure candidate parent/vfork plus installed execution after
exec, not an entirely candidate-run workload. Compare total times; baseline
spawn returns late, so launch-only ratios exaggerate gains. No measurements
yet establish the observer version's performance.

## Working preferences and cleanup

Use the edit/apply-patch tool for tracked changes. Keep documentation concise,
plain and explicit about observed results versus proposed mechanisms.
Don't stop for routine reversible experiments or repeated permission requests.
If work is blocked, report it immediately with the actual reason.

Keep process ownership and timeouts explicit. Sandbox process listings can
miss laptop-host processes: an earlier local RVVM was accidentally left
running. It was identified and stopped before the reboot. Do not launch an
unbounded local VM or claim host-wide absence from sandbox ps alone.
The latest agent reported all its owned observer build/test sessions finished;
that report is not a fresh host-wide process audit.
