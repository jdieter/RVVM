# Checkpoint: October 15, 2026, evening (Claude session)

Branch `vfork-memory-poc` (base `rocky` cda8f13) now holds the whole
native-vfork backend as signed commits; the sections below this one are
history. Production (`rocky@10.32.36.218`) still runs `claude11`, built from
`66403ae`; nothing after it is deployed. Rollback for that deployment:
`sudo bash /var/tmp/rollback.sh` on the builder.

## Commits after the deployed `66403ae`

- `ce0fed8` generic mmap flags reach Linux; x86-only bits masked;
  MAP_SHARED_VALIDATE reserves then replaces; mprotect rejects unknown
  protection bits (`test-mmap-flags.c`).
- `561205c` stopped mapping helpers get SIGCONT every 100ms (no kill
  timeout: a tracer stop can't be told from a long populate); at
  RLIMIT_NPROC the child serves its own mapping calls
  (`test-nproc-mapping.c`, stop mode of `test-helper-death.c`).
- `28ccc4e`, `4559a63` internal tasks (observer, intermediates, helpers)
  are hidden from proc-root listings, `/proc/<pid>` paths and PID-argument
  calls; `__WALL`/`__WCLONE` waits by an init or subreaper guest poll
  instead of selecting the observer (`test-internal-hidden.c`,
  `test-observer-visibility.c`).
- `1eeee28` proc from an ancestor PID namespace (`GUEST_PROC=outer`).
- `1743806` VFORK into a new PID namespace after unshare/setns
  (`test-pidns-vfork.c`); unshare(NEWUSER|NEWPID) runs as two steps.
- `bbb660e` static glibc fork recovery audited through 2.43.
- `7872717` x86 CET: the fault jump restores the shadow stack
  (`test-child-fault.c`; pass a fault count to stress it).
- `959fc05` no more `USER_FAULT_META`/`USER_FAULT_POC`/
  `USER_NATIVE_VFORK_POC`: the code is unconditional in userland files and
  `RVVM_USER_TEST` in shared ones. Userland harts use a separate interpreter
  instance (`riscv64_user_interpreter.c`, `RISCV_USERLAND`) with the fault
  sites; JIT fault metadata needs native pointers (userland only). The
  full-system emulator runs no userland fault tracking.
- `10a07b1` a plain `make` builds a static-pie `rvvm_user` (dynamic PIE
  without glibc-static) with `--wrap=_Fork` on that link only. New Makefile
  hook: `bin_ldflags_<name>`. `rvvm_user` builds only on arm64/x86_64.
- `30d4ae8` private-mm children (fork-like or private VFORK, including from
  a shared-mm child) accept CLONE_FILES and CLONE_NEW* like an ordinary fork
  (`test-child-fork-flags.c`; needs `GUEST_PIVOT=1` for namespaces).

## Building and testing

Build: `make` (or the production options: `make USE_GUI=0 USE_SOUND=0
USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1 USE_NO_LIBATOMIC=1 CFLAGS='-O3 -fPIE'
LDFLAGS=-static-pie`). No defines are needed. Static glibc fork recovery is
enabled automatically for static links with glibc 2.34-2.43.

Latest ARM dev candidate: `claude31` (= `30d4ae8` plus a test-only change).
All fixtures pass under `claude1/runall.sh` except the four that need their
own launchers (fake-root, observer-adoption, observer-private-files,
parent-tid-early-stop); helper death passes in kill and stop modes; the
regular suite passes 30/30. On x86_64 (i7-12700H, kernel 7.2.9, glibc 2.43)
the same fixtures pass with a CET shadow stack enabled, except
`test-exec-errors` (the host's qemu-riscv64 binfmt intercepts self-exec) and
`test-observer-visibility`, which fail the same way without the shadow stack
and pass on ARM; not investigated on x86.

Full-system check: the Rocky 10.3 SBC image
(`Rocky-10-SBC-Generic-10.3-20261014.0.riscv64.raw.xz`, LekKit's 2026.01
`fw_payload.bin`, `-m 4G -smp 4 -nogui -nonet`) boots to a login prompt on
`rvvm` from both `rocky` and this branch; only `rngd` fails (no hardware
RNG). On the x86 laptop, one run each:

| | rocky | this branch |
|---|---|---|
| login prompt | 50.3 s | 49.8 s |
| 300 x `/bin/true` | 2.67 s | 2.72 s |
| `sha256sum /usr/bin/*` | 2.32 s | 2.38 s |
| Python sum of squares, 3M | 2.66 s | 1.74 s |

Single runs, not profiled. The `rocky` build was a default build, so it had
no fault tracking either: the Python difference is unexplained. Read this
as evidence of no regression, not of a speedup.

## Known gaps

- `/proc/<pid>/task/<tid>/children` contents and proc lookups relative to
  an open proc directory descriptor still show internal tasks.
- A process that inherits a near-zero NOFILE hard limit can't provision the
  observer, so VFORK cases that need it fail (EMFILE). Lowering the limit
  inside the guest works: the observer is provisioned first.
- Mixed-TID VFORK when the pinned `/proc` belongs to a descendant or
  unrelated PID namespace returns ESRCH rather than guessing a PID.
- unshare(CLONE_NEWUSER|CLONE_NEWPID) runs as two steps. If the PID step
  fails, the user namespace stays entered.
- A tracer-stopped mapping helper is resumed but never timed out.
- A shared-mm child can't create threads (EAGAIN), and its clones can't
  combine CLONE_VM with CLONE_FILES or namespaces (EINVAL). CLONE_FS is
  unsupported for any fork, as before.
- A dynamically linked `rvvm_user` (no glibc-static) has no private-mm
  VFORK (EOPNOTSUPP): only a static link redirects libc's `_Fork`.
- Not yet run: the kernel build and package builds on dev, or another
  production deployment.

# Checkpoint: October 15, 2026 (Claude session)

Latest ARM candidate `claude8`: source `/var/tmp/rvvm-native-vfork-poc-20261013/claude8/src.tar.gz`
(SHA256 `80cac362...`), binary SHA256 `e5ffe9b4...`. Launch: `claude1/guest.sh`
(user/mount/binfmt/pid namespaces, proc in root, `/sys` bind, UID993/GID135,
empty bounding set, guest not PID 1). No commit, merge or deployment.

Changes since the 48-case observer checkpoint, each with a regression that
fails before the change and passes after it on ARM:

- Partial mprotect keeps the kernel's completed prefix in the executable
  registry (`test-mprotect-partial-exec.c`, now also mid-range EACCES).
- The observer is no longer the guest's child: a raw intermediate creates
  it and exits, so `__WALL`/`__WCLONE` waits keep ECHILD. Guest waits hide
  that intermediate until reaped. An init or subreaper guest keeps a direct
  exit_signal-0 child (remaining `__WALL` gap). Exec and exit_group stop an
  idle observer, which previously kept the pre-exec mm alive
  (`test-observer-visibility.c`).
- Proc PIDs are translated through NSpid when the pinned proc belongs to an
  ancestor PID namespace (`GUEST_PROC=outer`; fixes a `test-tids` regression
  against the installed baseline).
- Mapping-helper death no longer exits the parent. The child is killed, as
  if SIGKILL arrived in its syscall; the operation's outcome is read from
  kernel mappings (mincore/maps) for bookkeeping; nothing is replayed.
  ELF segments, stack and signal trampoline keep host EXEC so maps mirror
  guest execute intent (`test-helper-death.c` with `helper-death-killer.c`
  covers mmap, populate, mprotect and munmap kills).
- The observer is provisioned before the guest lowers NOFILE below 16, so
  `test-observer-cow-limits.c` passes (installed baseline: EMFILE).

Later candidate `claude10` (binary SHA256 `d2474edc...`) also routes every
syscall the parent handles in a shared-mm VFORK child: mount, umount2,
mincore, accept4, sendmmsg, process_vm_readv/writev, shmget/shmctl, bpf and
fchmodat2 through the shared dispatcher; shmat/shmdt through the mapping
helper; unshare directly. clone from such a child supports fork and nested
VFORK (prepare/finish run on the child's worker with its tracing context;
the child issues clone3). Thread creation from it returns EAGAIN: a thread
would need TLS of its own while the child borrows its caller's. Tests:
`test-child-routes.c`, `test-child-clone.c` (fail on `claude9`, pass on
`claude10`). A fork with namespace or CLONE_FILES/FS flags from such a child
still returns EINVAL, as for a native VFORK.

All other fixtures pass on `claude8` and `claude10`. Not run here: fake-root/prefix
direct-API launchers, native early-stop tracer, native-only kernel probes.
Remaining: full acceptance (glibc in RPM context, builds, performance),
platform/CET/static-glibc gating (private VFORK needs static glibc
2.34-2.39), helper clone EAGAIN at RLIMIT_NPROC, observer `/proc` visibility.

# Reboot checkpoint: October 14, 2026

The first integrated observer candidate passes all 48 parent-TID cases on
ARM as UID993/GID135: shared/private VFORK, actual parent/child stores and
clear, NULL/PROT_NONE parent buffers, STOP/CONT/KILL, and parent-peer
malloc/sigaction progress. Source `observer-source.tar.gz` is SHA256
`64375aa4f0840f0f9dde58365132556e6d321b65be131f67158b5378c4f486a8`;
binary `observer/release.native-observer/rvvm_user_arm64` is SHA256
`c7b27c4df226c16687f6d21c9013697f1204d20d0805fa7935d17daa572160a1`.
The observer owns private files/limits and pinned proc interfaces, watches an
owner pidfd, and uses a fresh memfd inode or COW smaps witness. Snapshot and
mapping-helper creation now serialize under the mm guard. The owned build
and test sessions finished; a subsequent exact-name process check found no
remaining `native-observer` process.

Later unqualified source resets inherited observer clients/locks in ordinary
fork and private VFORK and streams large child lists without a fixed PID
count ceiling. Wait/proc visibility, namespace PID translation and mapping
reconciliation/helper-death recovery are still incomplete. No full matrix,
commit, merge or deployment has occurred. An automated cybersecurity flag
was reported by the parent after the build launch, without a visible trigger;
diagnostic inventory finished normally, then work explicitly resumed. No
identified restricted action was retried.

Observer foundation probes now pass on native x86 and ARM as UID993/GID135
with an empty capability bounding set. `test-snapshot-witness.c` preopens own
smaps, creates a fresh protected private page, then observes the stopped COW
child's shared page after setting dumpability and hard NOFILE to zero. Killing
and reaping the child restores the page's private accounting.
`test-observer-private-files.c` uses a separate CLONE_VM process with its own
files and limits. It reads caller children and opens same-mm child maps after
those reductions, preserving actual mixed parent/child TID stores and clear
on exit. These are foundation probes, not integrated runtime qualification.
Dev source and native binaries are retained at the POC artifact root.
The pinned-proc probe also passes after its proc mount is detached in a
private mount namespace and the guest chroots to an empty directory; the
observer drops to UID993/GID135 before opening that proc root.
`test-observer-adoption.c` passes native x86/ARM: a newly adopted older COW
descendant lacks a fresh memfd inode, while the stopped same-mm child has it.
`test-observer-owner-exit.c` passes native x86/ARM: the owner TGID pidfd stays
unreadable while a peer lives and becomes readable after the last exit.

Integration must not treat any newly listed PID as the requested child:
subreapers can adopt descendants during clone. A fresh marker must exclude
older COW children and known existing mm sharers, and all COW snapshot paths
must serialize marker publication. A remaining provisioning problem is a
new private-mm process inheriting hard NOFILE=0 and dumpability=0: its new
observer cannot open proc files, while the old observer cannot open that
nondumpable mm. Pinned maps files stay bound to their original mm. This was
reported to the parent; no limit or permission workaround was added.
The exact inherited-limit comparison is now retained in
`test-observer-cow-limits.c`: native x86/ARM pass ordinary COW fork followed by
dumpability0/hard NOFILE0 and mixed-TID shared-mm VFORK. Installed baseline
`0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`
fails the same guest-static fixture as UID993/GID135 with errno24 (EMFILE).
This establishes an existing deployed limitation, not observer integration
or permission to regress successful marker-only cases.

Work resumed after reboot. No commit, merge, deployment or installed host
changes. Worktree: `/home/jdieter/resf/RVVM/worktrees/vfork-memory-poc`.
Do not import or modify main; its unrelated deployed drafts are now committed.
The old eager vfork backend must remain removed.

The first resumed change resets executable snapshot ownership in ordinary
fork and private-mm VFORK, freeing inherited snapshots after libc recovery.
Matched ARM binary `7daf8ee7d0b6d6019286a5c38f328e5fffc45866b425b676ec48003b5e12e50c`
passed the retained gates plus ordinary fork during a live reader, with
200,000 permission changes under bounded AS. Evidence: `raw-latest/resume-reset-gates.log`.
`test-parent-tid.c` supplies 48 native ARM/x86 reference cases, including
faulted parent buffers and stopped/killed children. Guest PTID remains open.
Both execution loops now use `rvvm_user_kernel_dispatch.h` for 216 common
routes, including ABI/path/credential/signal conversion. The last matched ARM
binary is `d878c7accbb20705e917d9c0a96e137b0bb8a5350eb048892338a9e7f8704727`,
at dev `common-delegates/release.native-common-delegates/rvvm_user_arm64`.
Its source archive is `common-delegates-source.tar.gz`, SHA256
`f62b3cc32c768ca14272e786fcc05530240584063ab18018717b37ecc732e43d`.
Focused ordinary-fork and shared-mm child runs passed clocks/EFAULT,
credentials, epoll/inotify/timerfd/splice, sched_attr/ioprio, IPC/IO argument
errors and the filesystem fixture. The preceding 177-route artifact also
passed descriptor relocation, upper-bit aliases, close_range and openat2.
Evidence remains in dev `common-delegates-directed.log` and
`common-epoll-directed.log`. Ptrace bridge guards now clone a retained shared
marker VMA without allocating another FD; a concurrent 96-bridge native
fixture passes with hard NOFILE and FSIZE both zero. Tracing TLS/replay and
helper lifecycle work remains open, as does actual guest PARENT_SETTID.

Shared-mm tracee hooks are now wired through a prepared private bridge and
borrowed TLS/replay context. Replay storage is owned by the trusted worker,
and parent tracing state is restored after kernel VFORK release. Candidate
`ptrace-v1/release.native-ptrace-v1/rvvm_user_arm64`, SHA256
`92e1886fcfd02a6d7ffe034222cd77470fb35f8924dc280afbedc154a57efacb`,
passed native VFORK/exec/VFORK_DONE/exit wait-event ownership and the common
child fixture. Both caught-signal modes pass in the established launch
context. The source archive is `ptrace-v1-source.tar.gz`, SHA256
`0ddb672c4436305972df6777398eaf626f3be11e47cb0ba8f71f2fe03f4d1973`.
Logs: dev `ptrace-v1-directed.log`, `ptrace-v1-signals-hostpid.log`.
The replay-context allocation/isolation unit passes locally. The isolated
PID-namespace wrapper's exit 125 also reproduces on the previous binary and
a pure native `timeout 5 sh -c 'exit 13'` command; it is not evidence of an
emulator regression.

Latest qualified ARM source is `events-context-source.tar.gz`, SHA256
`d2b63b1d9afd98e026ef25f870f1a01665f11891420bc0fa566c9836862ec6bd`.
Binary `events-context/release.native-events-context/rvvm_user_arm64`, SHA256
`e4615529ece3e9364da248514a1748cb539a0716844d964710fddcc995a45459`,
passes register/syscall/event assertions in both shared and private VFORK.
Both forms prepare distinct bridges before clone; a recovered COW child
retires its copied parent bridge. Six zero/custom/SIGCHLD exit-signal cases
passed the preceding `ptrace-cow-v2` candidate. Shared-mm tracees now select
private event contexts, preserving parent tracer queues and locks. The
directed ARM native fixture kills a child with its own lock held and verifies
that the parent's context remains usable. Logs: `events-context-directed.log`
and `events-context-unit.log`. Proc bridge/task/mount readers use bounded
stack buffers without FILE allocation. CPU/proc synthetic-file allocation
adapters are in progress; these later source edits are not in that artifact.
Child-as-tracer allocation/replay adapters, actual guest PARENT_SETTID,
helper death/namespace-init handling, and launch-platform parity remain open.

CPU/proc/open adapters are now qualified in `proc-views-v2`: binary SHA256
`0f5d9ea06c090d548f07f227b399670b75614b25223f1402717d49c60c4d805a`,
source archive SHA256
`5d277541ac3158655498c29d16b4944bc3cf70c397dd9b7d317a1e4e876af8ae`.
Shared/COW VFORK and ordinary fork pass executable identity through
open/openat/openat2, CPU/sysfs and auxv views, hardware-probe selection, and
last-slot executable open. Normal and native loops share 219 routes; CPU
views use raw streams and worker-owned storage.

The allocation-owner and private event/replay record adapters are now qualified
on ARM. Source archive `owned-context-source.tar.gz` is SHA256
`cc750d59f6c08303d9406ba89cf47b01300539d67acbc6cd5d078f194bb91334`;
binary `owned-context/release.native-owned-context/rvvm_user_arm64` is
`f0179e66e459771bcd0d1fff7f76710b576793185b17eb4d5636eb4229f85fbd`.
Native ARM fixtures pass replay isolation/ownership and 96 private tracing
records followed by child SIGKILL while its own normalization lock is held.
The guest tracing fixture passes VFORK/exec/exit wait-event ownership on that
binary. Worker allocations no longer have a fixed 32-record ceiling.

Two automated cybersecurity interruptions were reported by the parent agent;
no visible tool output identified a trigger. The diagnostic task completed
normally, and ordinary work resumed under explicit authorization. No rejected
action was retried.

The next candidate consolidates ptrace and normalized waitid/wait4 into the
common dispatcher (222 routes), with private tracing allocations in shared-mm
children. It also removes FILE locking from ptrace debug output and clears
matching stale clone hints when a prepared bridge is cancelled. ARM binary
`child-tracer/release.native-child-tracer/rvvm_user_arm64` is SHA256
`763bc9a0204f3a49fe9d36bb1579b98e16a4ae4af1365714a763c25aa2b11e0a`;
runtime source archive `child-tracer-source.tar.gz` is
`5e55dd4921772c706a242ad7c61d907d1eb5b927d0f1f112342276d66ab710f5`.
The new directed fixture passes native x86 and guest RISC-V: a shared-mm child
attaches to 40 independent peers, retains their WNOWAIT events, consumes them
with wait4, and detaches. This exceeds the former worker allocation ceiling.
The parent then reaps all targets. Logs: dev `child-tracer-40-directed.log`;
the preceding one-peer run also passes with debug logging enabled in
`child-tracer-debug.log`. The archive contains the earlier one-peer fixture;
the expanded fixture is retained separately as dev `test-child-tracer.c`.
The first GCC attempt lacked the private proc mount and failed namespace
preflight. A control under the 238-route candidate with proc mounted compiles
successfully; that failure was not evidence of a PARENT_SETTID problem.
Earlier fixture compilation used the retained baseline with private proc,
followed by explicit candidate execution.

Process/thread queued-signal routes now share their existing siginfo conversion
too (224 common routes). ARM binary
`child-sigqueue/release.native-child-sigqueue/rvvm_user_arm64` is SHA256
`4460fd08ec5bac13fb0272faaa6b4b06f5eefe9eab40d7c9e36ff2e66c0332f6`;
source `child-sigqueue-source.tar.gz` is
`97438aa7185d3e5346cae3693d5428d307f25370cbea1977b1482cefdcab166f`.
`test-child-sigqueue.c` passes native x86 and guest RISC-V, checking sender,
value and EFAULT for both queue syscalls in ordinary and shared-mm children.
Evidence: dev `child-sigqueue-directed.log`. All bounded commands returned.

The existing path/descriptor host-delegation helpers now serve both loops
(238 common routes); mount_attr snapshots use the trusted runtime allocator.
Candidate `child-host-errors/release.native-child-host-errors/rvvm_user_arm64`
is SHA256 `94a320cce4f629fb701c56225e2d986ed0f9fdd523714123cb87c4db95da060a`,
source `child-host-errors-source.tar.gz` is
`fcd34251ddc0b7a3b6671ff35acd17a7b8580747a48a22fc82bda495af988f9d`.
The short invalid-argument fixture passes in native ARM and emulated RISC-V
as UID993/GID135: all 14 errno values match, including ordinary/shared child
contexts. It uses only invalid paths/descriptors/commands and an invalid-fd
no-op mount_attr; it changes no host resources. Logs:
`child-host-errors-native.log` and `child-host-errors-directed.log`.

Actual kernel PARENT_SETTID is now qualified when guest child-TID flags are
unused. A separate anonymous MAP_SHARED cell receives
kernel CHILD_SETTID before pending STOP, so the worker can release snapshot
locks even in a private-mm child. Guest parent stores still go directly to
the guest buffer, including faulted buffers. Mixed parent/child-TID flags
remain unresolved and rejected. The original 48-case fixture is unchanged by
default; its new `--parent-only` mode checks the 12 newly supported cases and
passes native x86 and guest RISC-V. ARM binary
`parent-store/release.native-parent-store/rvvm_user_arm64` is SHA256
`c52a3fdb524571ab0b8296c366357792c68339a5029ebb828bf14080f0bdba27`;
source archive `parent-store-source.tar.gz` is
`fda53387ea7f08acc89a1733a5b76944acbe663553688d7149d7fa7d41158c06`.
The same 12 cases also pass native x86 and guest RISC-V with hard NOFILE=0,
so the completion marker does not need a spare descriptor. Logs:
dev `parent-store-directed.log` and `parent-store-nofile-zero.log`.
An independent native ARM tracer also holds the child at its automatic kernel
ptrace stop before the first callback. Parent peers complete malloc, executable
open and sigaction before the tracer kills that child; both shared and COW
modes pass as UID993/GID135 with no privileged tracing feature. This is a
deterministic early-stop check, rather than a scheduling race. Source:
`test-parent-tid-early-stop.c`; logs `parent-store-before-callback-shared.log`
and `parent-store-before-callback-cow.log`. The source archive predates these
later fixture-only additions; matching runtime source is unchanged.
The native helper-exit diagnostic now passes on x86 and ARM as UID993/GID135.
`test-helper-exit-registers.c` holds an owned child at its kernel ptrace EXIT
stop after SIGKILL, sends another SIGKILL, and verifies that NT_PRSTATUS is
still readable and unchanged before reaping it. Evidence:
dev `helper-exit-registers-native.log`. The initial opposite expectation failed
on native x86 and was corrected; it was not an emulator failure. This proves
register retention at the stop, not a viable permission-independent tracing
protocol. Tracer ownership, external tracing, dumpability and namespace-init
lifetime remain unresolved, so no internal ptrace dependency was added.
Fake-root launch is now supported: shared-mm children use private fake UID/GID
state, while COW children initialize their recovered process state. Direct
interpreter exec is shared by both dispatch loops. ARM source archive
`fake-root-source.tar.gz` is
`63183d3ad6e1514f805906f2337d7eae62186c97bcc53cd542bac3438f5cae4f`;
candidate `fake-root/release.native-fake-root/rvvm_user_arm64` is
`0d1bf15c3689c4f439ad85ac7781a1ad9098b884a2ae2a432dea517a6f528722`.
The direct-API test harness `fake-root/fake-root-launch` is
`f06baa157ce7e9b9375231749d35abfbbef0c84738638e1befa9d8cb1ad2507e`;
its retained `fake-root-main.c` is an additional fixture source, not included
in the archive. `test-fake-root.c` passes as real UID993/GID135: ordinary fork,
shared VFORK and COW VFORK each isolate fake credential changes and exec
through the interpreter. Log: dev `fake-root-directed.log`.
Prefix mode is now qualified too. Readlink uses the common converter in both
loops (239 common routes), replacing the narrower native-only handler.
Source `prefix-source.tar.gz` is
`34b793e87a5a0c82dfaaacaab5820bb6e0e332142852f08c2e632ff02fec4eec`;
binary `prefix/release.native-prefix/rvvm_user_arm64` is
`c64d64ac142ed79a763119d02ae09d644ad6b12ae0625af56567070f2cddbf07`;
direct-API harness `prefix/prefix-launch` is
`944e97d74892d6597d683ecd5b4cd6da7fea8a1cce483fbc8b53c4c2b10659a7`.
The extended fixture passes prefixed open, cwd/symlink stripping and guest
`/proc/self/exe` identity in ordinary/shared/COW children, alongside fake
credentials and exec. Log: dev `prefix-directed.log`. Both fixture sources
are included in this archive. Mixed TID flags, kill-safe mapping lifetime,
namespace-init, CET/platform support and proc dependency remain open.
The remaining snapshot design cannot be fixed by resetting child locks alone.
Allocator/libc recovery still needs coherent private-mm state, and executable
pin relocation can reuse a descriptor while the kernel copies the files table.
The existing relocation journal needs a retained spare OFD reference to resolve
that race; inode, flags or offset comparisons do not identify an OFD. Internal
PIDFD creation fails with hard NOFILE=0, while a proc observer or mandatory
ptrace adds contexts where native clone succeeds but the emulator would fail.
PR_SET_MM_MAP with exe_fd also requires checkpoint/restore capability, so it
cannot replace the private executable pin under the unprivileged requirement.
The latest prefix candidate now has fresh matched performance measurements.
`latest-prefix-performance.jsonl` retains all 40 verified outputs/statuses:
four launches per case/variant, discarding the first and taking the remaining
three-sample median. Total seconds installed -> candidate: small xz 1GiB/8
peers 0.69726 -> 0.00731; small xz 3GiB/96 peers 1.98143 -> 0.00691; true
1GiB 0.69545 -> 0.00456; true 3GiB 2.01765 -> 0.00431; large debug amdgpu
xz 1GiB 0.71732 -> 0.18682. Candidate launch medians are 0.262-0.357ms.
Parent candidate is the qualified c64d64ac binary above. Installed parent
and both variants' post-exec interpreters are
`0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`,
verified by hashing owned running processes' native `/proc/PID/exe`.
The retained `baseline-parity` binary is older and was not used. Both launches
use the same private proc mount and UID993/GID135. Baseline spawn returns
almost at workload completion; compare total times rather than launch ratios.
The initial harness output-directory permission failure is retained separately
in `latest-prefix-performance-setup-failure.jsonl`; outputs now use guest /tmp.
`measure-latest.py` retains the bounded measurement and identity collector.
All measurement processes exited; nothing was deployed.
The mapping architecture audit found an existing partial-mprotect execute
permission bug. `test-mprotect-partial-exec.c` passes on native x86 and ARM:
a READ-only change across an RX VMA and a later hole returns ENOMEM, but
the earlier VMA has already lost execute permission. Both the installed
0af5216c baseline and the c64d64ac candidate fail its first ordinary-fork
case because the executable registry updates only on success. The other
guest modes are not counted as run. Logs: dev `mprotect-partial-native.log`,
`mprotect-partial-guest.log`, `mprotect-partial-installed.log`. All owned
processes exited; this is recorded in tests/rocky/TODO.txt, not hidden by
changing the expected result. No unsafe page-by-page workaround was added.
No deployment, host settings, commits or broad matrices.
Use directed regressions until implementation is complete; don't repeat
the full matrix at each revision. The reboot checkpoint below is historical.

Current source, fixture and evidence archive:
`/tmp/rvvm-native-vfork-cow-checkpoint-20261014.tar.gz`
SHA256 `b8e35656d946567f827caf9b1be3f1506f94453bf6aaad45d4f48c6796b15f9a`.
It predates this checkpoint document; runtime source is identical.
Earlier pre-fixture build source archive:
`/tmp/rvvm-native-vfork-cow-source-20261014.tar.gz`.
Both source archives include imported baseline changes; git HEAD predates those
imports, so git diff against HEAD is not a standalone replacement patch.
Imported baseline is `/tmp/rvvm-native-vfork-original`.

Tested ARM binary:
`fedora@3.144.135.42:/var/tmp/rvvm-native-vfork-poc-20261013/cow/release.native-cow/rvvm_user_arm64`
SHA256 `61629f4aa1c39cd991b01e03acfb9f93d0597ebfbdb8e62b12d58aed277d1131`.
Isolated guest path `/tmp/rvvm-vfork-poc/native-vfork-cow` in
`/var/lib/mock/rocky-10-riscv64-rvvm/root`.
Local static x86 binary `release.native-next/rvvm_user_x86_64`:
SHA256 `d9f2d6e4cf60b3d2287295cfc04000d3286430cd07c36e87ebdd75345bff4683`.

Matched flags: USE_GUI=0 USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1
USE_NO_LIBATOMIC=1, CFLAGS `-O3 -fPIE -DUSER_FAULT_META -DUSER_NATIVE_VFORK_POC`,
LDFLAGS `-static-pie`; dev image
`localhost/rvvm-heap-build-env:20261008`. Local build uses CCACHE_DISABLE=1.

Completed: real CLONE_VFORK without CLONE_VM now executes in the actual native
private-mm child. Parent watcher snapshots allocator/stdio/emulator state,
releases parent locks after the kernel PID publication, and the actual caller
remains kernel-VFORK suspended. Static-glibc child recovery then enables the
existing general dispatcher in the private mm. This is not ordinary fork plus
userspace waiting. Shared-mm vfork retains its allocation-free interpreter and
trusted helper dispatcher.

Validation: all18 targeted dev processes passed; raw log
`raw-latest/cow-gates.log` and dev `cow-gates.log`. UID993/GID135, CapEff0.
The formerly failing existing `test-vfork-concurrent` now passes including
its no-VM case. New `test-vfork-cow.c` passes native x86 and guest RISC-V:
16 private-mm children, COW/protection isolation, shared-map communication,
parent-peer malloc/mmap, failed exec, statx/getrandom and STOP/CONT. Other
gates include exec17cases, signals/restart, descriptors/nofile, memory/limits,
256 shared-mm children, PI, CPU accounting,20SIGKILL trials,200k mapping churn.
Latest early-stop run reported early=0; previous unchanged shared-mm handshake
had a verified early=1 run. Do not describe this new log as a fresh early=1
observation. Local static build and native harness passed; logs
`/tmp/rvvm-native-cow-build.log`, `/tmp/rvvm-native-cow-native-tests.log`.
All bounded commands have returned. No active experiment requires monitoring.

Next implementation requirements, not accepted ENOSYS regressions:

- Guest PARENT_SETTID: preserve the actual kernel guest store and early-STOP
  ordering while obtaining a separate coherent descriptor/action snapshot
  completion marker. Current clone3 parent_tid is used internally. Original
  test-tids and original process-control/signal publication modes remain
  unsupported and are not counted among passes.
- Reset executable hazard/snapshot enrollment in new ordinary-fork mms.
  The COW path currently drops inherited snapshot pointers; consolidate a
  safe child-reset helper under the coherent mmap snapshot, and audit leaks.
- Broader shared-mm child syscall dispatch and child-private ptrace/replay
  contexts; the private-mm path already uses the general dispatcher, but the
  shared-mm subset still returns ENOSYS for previously supported interfaces.
- General ptrace clone/exec/exit/wait visibility and the COW parent's clone
  bridge publication need targeted assertions, not just ordinary fixture
  success.
- Mapping helper death/visibility across several shared-mm children, namespace
  init death and ambiguous kernel-mutation completion remain architectural
  requirements. Current unexpected helper death fails closed.
- Fake-root/prefix, pending PID namespaces, CET/shadow-stack, unavailable
  clone3 and nonqualified static-glibc platforms remain preflight gaps.
- Audit glibc snapshot/recovery contracts in the new COW path for concurrent
  loader/NSS/thread-creation state. It currently snapshots allocator/stdio
  plus emulator locks and invokes libc child recovery via wrapped _Fork.
- Remove experimental build gating only when the replacement has parity.
  Builds without USER_NATIVE_VFORK_POC currently return ENOSYS for vfork.
- Remaining exec/proc aliases, helper inheritance/robust/clear_tid and finite
  resource overhead require wider acceptance. No full glibc/RPM/kernel run
  has been completed for this replacement.

This exact COW/native-only revision has no performance measurements. The
earlier medians in LATEST-RESULTS.md refer to c9cade03 source and an installed
baseline interpreter after exec. Preserve prior archives/raw reports.
Continue isolated engineering and matched benchmarks after the user returns.

Always SSH/SCP with `-F /home/jdieter/.ssh/config`. Dev launches use a private
mount namespace, mount proc in the isolated buildroot, drop to UID993/GID135,
and timeout. Local process listings inside the sandbox are not evidence of
the host's entire process table. All local runs must be bounded with tracked
cleanup. No privileged-feature solution, production changes or global host
configuration changes are authorized.
