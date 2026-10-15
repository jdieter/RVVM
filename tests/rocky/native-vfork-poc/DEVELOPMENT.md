# Native shared-mm runtime development

The guarded POC and its measurements in RESULTS.md remain frozen. This file
tracks the subsequent implementation; it is not ready for production.

## Measured source

The next benchmark uses `/tmp/rvvm-native-vfork-usable-source.tar.gz`, SHA256
`f098cacb335ca26cf3b4a1d1a9e63781773b8c1c495776a6b252df922d1f1410`.
The matched Rocky static ARM binary is SHA256
`c9cade03d35432df7ed37d2129133b8f645250e0f69d3084660e326afdd9dac4`,
copied to the isolated buildroot as `native-vfork-usable`. That artifact name
does not mean the incomplete syscall dispatcher is usable in general.

The new runtime owns its ARM/x86 fault jump instead of depending on glibc's
internal __longjmp. x86 shadow-stack configurations select the old backend
before clone. Guest instructions still execute in the real native child.
Caught actions and alternate stacks are child-private; EINTR and SA_RESTART
preserve guest signal delivery. Exec targets the requested file through the
kernel, preserving error checking, argv and environment. Self-exec retains
the existing readable pin; CLOEXEC ELF execveat retains a handoff descriptor.

An independent parent native pthread performs allocation and owns its TLS.
It holds the source descriptor guard until the kernel private-files snapshot
has been taken, copies a private table/guard, and registers a separate child
owner node. All borrowed descriptor TLS state is restored without changing
parent robust-list nodes or the process-global guard. Child dup3 relocation
and close_range use raw syscalls and preserve private pins. openat2 scratch
allocation runs in the parent worker, with native flag conversion in child.

## Verified gates

On DEV, credentials are dropped before RVVM starts: UID993/GID135/CapEff0.
The latest matched build passed all 17 exec cases, both signal restart modes,
private-pin relocation/close_range/openat2 conversion, STOP/CONT and child
CPU accounting, repeated SIGKILL during delegated allocation, 256 concurrent
vforks, kernel buffer writes/shared stores, failed-exec writes, ordinary-fork
isolation, TID/clear-tid/pidfd, partial protections/discard/private-file cache
and SIGBUS/SIGSEGV, and finite-AS rollback. This is one default-mode matrix;
the earlier four-mode guarded matrix does not validate these new changes.

Native ARM confirmed that unknown execveat flags with an empty path can return
ENOENT before the flags check on this kernel. The regression now uses valid
nonempty /bin/true and still requires EINVAL; native ARM and emulation pass.

## Post-exec identity

A dedicated untimed read-only observer verified three real xz execs use
`/usr/local/bin/rvvm-riscv64-static`, SHA256
`0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`.
Each remains UID993/GID135 with CapEff0. Thus benchmark parent pre-exec code
uses the candidate, while xz after kernel binfmt exec uses the installed
deployed interpreter. The observer finishes before timed trials begin.

## Still incomplete

The native dispatcher still returns ENOSYS for many previously supported
calls; this is an experimental gate, not an acceptable production behavior.
General mmap/brk/munmap/mremap and executable protection changes, live
immutable executable metadata, process credentials/namespaces and remaining
syscall conversion, and ptrace interactions need implementation and testing.
Kernel mapping transactions require a proof for SIGKILL after kernel commit
but before acknowledgement; replay or a naive maps comparison can corrupt
MAP_FIXED changes. A fresh transaction helper also risks incorrectly making
mmap depend on RLIMIT_NPROC. No candidate is integrated or deployed.

## Subsequent tested runtime: clone-marker

The ARM binary `native-vfork-clone-marker` has SHA256
`2827a641a9d84e2499f2cf708d8e2c8d9f76911383d22267b387c81282bca5d4`.
Its source archive `/tmp/rvvm-native-vfork-clone-marker-source.tar.gz` has
SHA256 `4a852bffd72c588723ba7603cf92d6757b3415b076a28d91cf2c87b3143c0d49`.
Raw DEV evidence is `clone-marker-gates.log` and
`clone-marker-native-control.log` under the isolated POC directory.

This revision delegates process attributes and anonymous/private-file
mmap, brk, mremap, munmap, protection and discard transactions. A temporary
raw-syscall process performs actual mapping operations using the child's
inherited credentials, limits and files; the parent pthread owns allocation
and metadata. Kernel clear-tid proves helper quiescence before storage is
released after guest death. Unexpected helper death remains a fail-closed
transaction gap, particularly with several simultaneous shared-mm children.

The FD/action snapshot handshake now observes a clone3 kernel parent-TID
marker, so SIGSTOP before the first child callback cannot leave parent peers
waiting on the snapshot guard. The early-stop regression passed with
`early=1`. Guest CLONE_PARENT_SETTID selects the compatibility backend before
entry, preserving that buffer's kernel store; missing clone3 support,
fake-root/path-prefix translation, pending PID namespaces and active x86
shadow stacks also select compatibility before entry.

All 17 exec cases, both caught-signal restart cases, all three descriptor
cases including upper-bit FD aliases, and private-file mapping/COW checks
passed as UID993/GID135/CapEff0. The independent process-control fixture's
`--guest-publish` mode avoids CLONE_PARENT_SETTID: all 21 native-backend runs
passed, including real STOP/CONT, 150965us child CPU time, ten allocator-kill
and ten mapping-kill trials. The original kernel-published PID mode remains
available as a compatibility-path check.

These changes have not been benchmarked. LATEST-RESULTS.md remains the last
measured artifact and must not be presented as measuring these later edits.
Live executable metadata, ptrace state and general syscall closure remain
pending. This backend is still gated experimental code, not a deployable
replacement for the complete existing dispatcher.

## October 14: live executable mappings and bounded snapshots

Latest tested ARM binary: `native-vfork-live-exec-hazard`, SHA256
`1c8bcbe88955c59463a1731c3da5372b9312ebe248b1b044991f124bc96bbb25`.
Source archive `/tmp/rvvm-native-vfork-live-exec-hazard-source.tar.gz`, SHA256
`023bab6109a9377485dd0e42b5a0c4de9f965cc32b20d34eba9a29b3e6857861`.
DEV raw evidence: `live-exec-hazard-gates.log`, plus the earlier
`live-exec-matrix.log` and `live-exec-native-signals.log`.

The child no longer uses an executable-range copy frozen at clone time.
Trusted mmap writers publish immutable current ranges. Each preallocated
child reader publishes a hazard pointer before reading a snapshot and checks
publication again before dereferencing it. Writers reclaim retired versions
with no readers; SIGKILL can retain at most that child's referenced version
until parent cleanup. Mapping transactions reserve publication storage
before their kernel mutation, and mremap coalesces its range updates.

The executable regression passed child RX mmap/mprotect/mremap, parent-peer
execute grants, and a real SIGSEGV after execute revocation. Its churn mode
passed 200,000 permission changes while a native child remained running with
32MiB additional RLIMIT_AS headroom. The earlier lifetime-only retirement
implementation would retain every version until that child exited.

The matched binary also passed the complete targeted default-mode matrix:
early-stop snapshot, descriptors and full NOFILE, 17 exec cases, both native
caught-signal modes, real STOP/CONT and child CPU accounting, 20 allocator/
mapping SIGKILL trials, 256 concurrent vforks, kernel writes and parent stores,
failed exec and ordinary fork isolation, mapping/protection/file/COW/discard
checks, finite-AS rollback, TID/pidfd, pipe/poll/socket/filesystem operations,
and private child credentials/group/name/umask/limits/scheduler/affinity.

An old assembly assertion required ENOSYS when a parent PI futex was held,
because the eager backend migrates futex keys. The new shared-mm path needs
no migration. A separate native and emulated regression verified the real
parent owner TID, child TRYLOCK_PI returning EAGAIN, and parent unlock/relock.
The assembly fixture now accepts the old explicit ENOSYS limitation or a
successful child followed by wait and intact parent unlock; both deployed
baseline and candidate passed it. No ownership assertions were removed.

These edits remain unbenchmarked. The four-mode executable/signal matrix
preceded the hazard/scheduler revision; do not count it as a four-mode test
of this exact binary. Kernel/binfmt post-exec code still uses the installed
interpreter, as documented above.

Remaining integration blockers include complete syscall dispatch, private
ptrace/replay contexts and safe allocation, native/compatibility peer-pause
and PI ownership enrollment, unexpected mapping-helper death with several
shared-mm children, internal helper visibility, snapshot-registry reset in
new ordinary-fork address spaces, and remaining exec/proc-path aliases.
In particular the native signal handler currently bypasses the legacy pause
hook, so mixed eager/native children cannot yet be claimed correct. No
integration, deployment or host configuration changes have occurred.

### October 14: native-only backend and private-mm VFORK

The eager memory migration backend, its private service/channel registry,
transition/pause callbacks and backing/RPC headers have been removed from this
branch. Ordinary fork, thread reaping, executable pins, JIT accounting and the
semantic guest fixtures remain. Two implementation-only backing unit tests
were removed with their implementation. This supersedes the mixed-backend
concerns above; compatibility fallbacks are no longer present.

The first native-only ARM binary (`1fae83f8...`) passed eleven targeted fixtures
before the existing concurrent-vfork test reached its no-CLONE_VM case and
failed with EOPNOTSUPP. That failure was a missing parity requirement.

The new private-mm path now performs actual kernel CLONE_VFORK without
CLONE_VM. A parent-owned watcher takes coherent libc allocator/stdio and
emulator metadata snapshots, then releases its parent locks once the kernel
publishes the clone PID. The original caller remains kernel-VFORK suspended
until the real child execs or exits. The private-mm child can allocate safely
and uses the full existing guest dispatcher after static-glibc fork child
recovery. It does not share the parent's allocator or migrate guest memory.
This currently depends on the existing qualified static GNU libc fork wrapper;
other libc/platform combinations remain explicit implementation requirements.

Matched Rocky static ARM binary SHA256:
`61629f4aa1c39cd991b01e03acfb9f93d0597ebfbdb8e62b12d58aed277d1131`.
Build flags remain `-O3 -fPIE -DUSER_FAULT_META -DUSER_NATIVE_VFORK_POC`,
static PIE/LTO, no dynamic loading/libatomic. Source archive before the new
fixture was added: `/tmp/rvvm-native-vfork-cow-source-20261014.tar.gz`.
Its isolated dev build is `cow/release.native-cow/rvvm_user_arm64` under
`/var/tmp/rvvm-native-vfork-poc-20261013`.

`raw-latest/cow-gates.log` records eighteen passing targeted fixture processes
on ARM dev as UID993/GID135, CapEff0. These include all seventeen exec cases,
caught signal restart/EINTR, private descriptors/full NOFILE, mapping/file/COW/
protection/discard/finite-AS behavior, 256 concurrent shared-mm children,
existing concurrent-vfork including the no-VM case, PI futex ownership,
STOP/CONT and child CPU, twenty allocator/mapping SIGKILL trials and 200,000
executable permission changes. The new `test-vfork-cow.c` passed native x86
and guest RISC-V: sixteen private-mm VFORKs with anonymous/protection COW,
shared mappings, failed exec, statx/getrandom, parent-peer malloc/mmap activity
and real SIGSTOP/SIGCONT. Local native harness and matched static x86 build
also passed. This is a targeted suite, not the full glibc/RPM acceptance run.

Guest PARENT_SETTID remains unsupported: its actual kernel publication must
coexist with the early-stopped-child snapshot handshake. Original assertions
requiring it are unchanged and are not counted as passes. Broader shared-mm
syscall dispatch, ptrace, mapping-helper visibility/death across multiple
children, fake-root/prefix and namespace/CET/clone3-unavailable configurations
remain parity requirements. The exact new binary has not been benchmarked;
previous timing tables describe earlier source and installed post-exec child
interpreters. No deployment or host configuration changes occurred.
