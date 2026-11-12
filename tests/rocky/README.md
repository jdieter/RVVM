# Linux userspace multiprocessing

The host kernel owns guest page allocation, protection, residency, file
bindings and ordinary fork copy-on-write. RVVM records which mappings belong
to the guest; native heaps, stacks, TLS, locks and JIT allocations are separate
from that ownership record. This is process emulation, not a security sandbox.

| Operation | Implementation |
| --- | --- |
| Ordinary fork | Host `fork`, retaining native private/file/shared mappings |
| Guest pthread | Host pthread with private emulator TLS and CPU state |
| `CLONE_VFORK` without `CLONE_VM` | Host fork plus exec/exit completion channel |
| `CLONE_VM \| CLONE_VFORK` | Private forked emulator and temporary shared guest views |
| File/SysV shared memory | Existing kernel shared mappings |

For shared vfork, a helper first copies its host descriptor table. It retains
native aliases of the original private guest mappings and temporarily maps
guest-only memfds at their addresses. The child then starts through the same
host-fork recovery path as ordinary fork. Emulator memory stays private;
guest stores, including a failed exec's errno, remain visible to the parent.
A private CLOEXEC socket completes vfork on successful exec or kernel exit.
Failed exec keeps it open. Child death therefore needs no userspace handshake.

Guest writers and outstanding kernel buffer writes are quiesced during view
changes. The guest-thread registry includes exiting tasks until native join;
it also works after the original process thread exits. Internal helpers block
guest signals. Every pause generation drains its signal acknowledgments before
the next begins. Preparation allocates before parking writers; the parked
phase uses kernel operations and preallocated buffers only.

The VM helper coordinates child `mmap`, `munmap`, `mprotect`, ordinary private
`mremap`, `madvise` and an already initialized `brk` heap. The kernel performs
the actual mapping operations in each process. Other parent threads can run,
but their mapping mutations wait until vfork completes. Native aliases retain
private file bindings and anonymous COW. Restoration copies changed pages
back and moves these original mappings into place. Sparse anonymous heaps copy
only populated/swapped pages; temporary file baselines distinguish guest
writes from external file writes. Concurrent external file changes are not
reflected live in the temporary private file views.

Guest pthread exit notification follows host pthread completion, so kernel
robust-mutex cleanup precedes guest TLS reclamation. One internal reaper joins
finished native threads and clears/wakes guest TIDs. Its final exit preserves
the last guest thread's exit status. Fork discards inherited reaper queues and
resets process reference counts. Shared-vfork completion publishes child TID
clearing after kernel exec/exit cleanup and before restoring the parent view.

## Supported boundaries

Guest seccomp supports classic BPF policies returning `ALLOW` or `ERRNO`,
installed through `seccomp` or `prctl`. Filters apply to the original RISC-V
syscall number, arguments and instruction pointer. Each thread owns its policy;
new threads, fork and emulated exec inherit it. Exec carries filter snapshots
in private environment entries that the new emulator consumes before starting
the guest. This does not constrain native executables or turn RVVM into a
security sandbox. Other actions, strict mode, TSYNC, register division and
installing new filters inside a shared-vfork child remain unsupported.

`test-seccomp-inherit.c` checks thread isolation, inherited filters and a
fork/exec round trip, including failed exec and an empty guest environment.
Build it with the guest libc compiler and run it under a private binfmt
registration pointing at the candidate emulator:

```sh
gcc -O2 -Wall -Wextra -Werror -pthread \
    tests/rocky/test-seccomp-inherit.c -o /tmp/test-seccomp-inherit
/tmp/test-seccomp-inherit
```

This enables spawn-style vfork. General separate-process `CLONE_VM`, `clone3`,
and additional clone calls from a shared-vfork child remain unsupported.
Shared-vfork child private futex operations return `ENOSYS`, because its host
mm cannot use the parent's private futex keys. Vfork with live kernel PI futex
owners/waiters, and new PI acquisitions while temporary views exist, also
return `ENOSYS` rather than migrating live kernel PI state.

The child VM protocol does not yet support SysV attach/detach, first-time heap
initialization, shared/zero-old-size `mremap` or `MREMAP_DONTUNMAP`. Those cases
return explicit errors; ordinary processes retain their existing kernel paths.
Guest resource limits still account for native worker allocations as well as
guest memory. Temporary backing descriptors also use the helper's descriptor
limit. This change does not implement separate guest resource budgets.

## Regression checks

### Linux compatibility backlog probes

`test-linux-compat.c` contains 33 independent behavioral cases for the TODO
backlog. It requires Linux headers and a libc toolchain for the target.
Build a static RISC-V binary inside the Rocky buildroot and run that identical
binary on native RISC-V and through RVVM. The fixture uses private working
directories and isolates irreversible credential, limit and sandbox changes
in separate processes. It requires procfs; privileged credential cases need
root. Core checks deliberately crash a child and inspect a direct core or
retrieve it through systemd-coredump. They do not change global core settings.

```sh
gcc -O2 -Wall -Wextra -Werror -static -pthread \
    tests/rocky/test-linux-compat.c -o /tmp/test-linux-compat
python3 tests/rocky/run-linux-compat.py /tmp/test-linux-compat \
    --source tests/rocky/test-linux-compat.c --output /tmp/native-compat.json
# Run on the emulator host, using the same RISC-V binary and copied reference:
python3 tests/rocky/run-linux-compat.py /tmp/test-linux-compat \
    --emulator /usr/local/bin/rvvm-riscv64-static \
    --reference /tmp/native-compat.json --output /tmp/guest-compat.json
```

Guest acceptance fails on any known gap as well as unexpected failures or
unverified cases. `--allow-known-failures` explicitly selects backlog inventory
mode: known assertion failures/unsupported calls are XFAIL, never PASS.
Crashes/timeouts remain FAIL; a passing known-gap case is XPASS and requires
updating the expectation after investigation. Native feature/privilege skips
are recorded as SKIP. Without a passing native reference, the guest result
is UNVERIFIED and fails even inventory mode. JSON retains stderr, exit codes,
reference identity, fixture/source/emulator hashes, host and UID. Existing
evidence files cannot be overwritten. `--case NAME` selects individual probes.

For unavailable native RISC-V prerequisites, add a supplemental native Linux
reference with another `--reference`. Different fixture binaries require
`--allow-cross-architecture-reference` and identical `--source` hashes in
both reports. RISC-V results remain the preferred reference; supplemental
ARM64 results are suitable for the shared Linux ABI/credential cases, not
an oracle for architecture-specific execution. Use matching source/build
flags and review permissions, kernel features and ABI before comparison.

Coverage includes clone3 fork/pidfd/handler reset/argument size; separate
process VM/FS/SysVSEM/parent sharing; nested shared-vfork and private/PI futex
operations; executable stat/statx; thread visibility after pthread_join;
shared-validate/unknown/populate/locked/grow-down mappings; a fixed memory
budget; actual filesystem UID/GID permission changes; seccomp through both
interfaces; Landlock rule creation/enforcement; rseq registration; io_uring
setup/register/enter/completion; guest syscall tracing and ELF core machine
type; ioctl/bad-buffer handling, alternate signal stacks and contended atomics.

These are focused backlog reproducers and conformance controls, not exhaustive
tests of every TODO requirement. Full syscall/ISA matrices, every ioctl family,
signal stress, fake-root identity, advanced clone3 controls, asynchronous I/O
lifetime races, rseq critical-section aborts, PI handoff/owner death, complete
procfs views and core register/mapping notes remain audit/implementation work
in TODO.txt. The fixed memory-budget probe measures a documented emulator
accounting difference; it does not claim to isolate every resource limit.

### Host delegation syscall probes

`test-host-delegation.c` adds 11 cases for add_key, request_key, keyctl,
quotactl/quotactl_fd, statmount/listmount, lsm_get_self_attr and
lsm_list_modules. Use the same native-reference runner described above, with
this fixture instead of test-linux-compat.c. Build with
`gcc -O2 -Wall -Wextra -Werror -static`; Linux 6.12 headers provide the
mount/LSM structure declarations even when the execution kernel is older.

Tests create only process-local keys, revoke payload keys, query mount/LSM
data and exercise quota-query errors. They do not change mount state, quotas
or security labels. Keyctl buffer faults must retain EFAULT; commands taking
descriptors must treat hidden pins as closed guest descriptors. Quota tests
cover pathname lookup and invalid descriptor errors, including descriptor
numbers used for private pins. They do not validate quota updates or a
successful data query on a quota-enabled filesystem.

The Linux 5.10 native reference cannot exercise the five newer syscall
interfaces; supplement it with a newer native Linux reference compiled from
identical source. Feature/permission denials remain explicit prerequisites.
No known failures are allowed for this implemented batch.

`test-host-state-delegation.c` covers the next 17 handlers: vhangup, acct,
delete_module, reboot, settimeofday, swapon/swapoff, lsm_set_self_attr,
pivot_root, setns and the seven newer mount operations.
Compile and run it with the same flags and native-reference runner.

Mount and pivot-root tests first unshare the mount namespace and make its
mounts private. The UTS test changes a new namespace and then rejoins the
original namespace. The vhangup success probe allocates its own PTY and
session. No probe changes the host clock, swaps, modules, accounting settings
or security labels. Those operations have permission/error coverage only.
The reboot probe clears and verifies all effective capabilities and uses
invalid magic values; it never requests a valid reboot with CAP_SYS_BOOT.

Descriptor tests cover hidden pins, descriptor relocation,
fsconfig command-dependent descriptors, and mount_setattr's embedded
userns_fd. The latter also checks extensible request tails and no-op calls
with inaccessible pathnames. There are 22 cases.
Run successful namespace/mount probes as root
on dev. Native feature/configuration gaps and missing capabilities remain
SKIP prerequisites; a newer native reference must pass before guest runs
count as verified.

pidfd_getfd and kcmp intentionally return ENOSYS for all arguments until remote
descriptor inspection can reliably hide emulator-private handles. The
guest-only test-pidfd-getfd.S checks this policy and the continued operation
of pidfd_open/pidfd_send_signal; it also checks getfd with NOFILE=0.
test-kcmp.S covers all object types, malformed arguments and NOFILE=0.
Both policy tests run in the existing regression suite.

`test-signalfd.S` checks blocked signal delivery, mask replacement, epoll
readiness, descriptor flags and errors, and inherited signalfds in ordinary
fork and shared-mm VFORK children. Its optional `exec` argument also checks
inheritance and CLOEXEC across guest exec; run that mode with the candidate
registered in a private binfmt namespace so exec uses the same emulator.

test-pidfd-getfd-conformance.c retains the four
native behavioral oracles for future support; it is not a passing guest
acceptance suite while the syscall is disabled. See TODO.txt for the reason
and re-enablement requirements.

`test-kcmp-cross-process.c` retains four native oracles: file and epoll
comparisons, closed descriptors in an independent child, and KCMP_VM
equality for CLONE_VM | CLONE_VFORK. Before disabling guest kcmp, the
shared-VM case failed in all guest modes. The remote-pin case also failed
under `kcmp-deny-metadata.c`, which denies process_vm_readv/ptrace while
allowing kcmp: native passed, but RVVM compared a hidden child descriptor.
These are future conformance probes, not guest acceptance while kcmp is
unsupported. TODO.txt records the rationale and re-enablement requirements.

### Hosts that refuse EXEC

Guest code is decoded and translated, never run by the host, so guest
execute permission never needs host EXEC. RVVM asks for it, so kernel maps
show guest execute intent, and maps or protects without it where the host
refuses: prctl MDWE (systemd `MemoryDenyWriteExecute=` on Linux 6.3+) and
SELinux execmem with EACCES, systemd's seccomp variant and noexec mounts with
EPERM. The execute registry stays authoritative. RVVM deliberately accepts
exec mappings of noexec files, as before host EXEC was requested, so sysroots
on /tmp or /dev/shm keep working; a RISC-V kernel would refuse them.

`mdwe-exec.c` runs a program under MDWE (exit status 77 without kernel
support). `run-tests.sh` builds it and runs `test-exec-refused.S` with each
emulator: plainly, under MDWE, and with a code file on a noexec tmpfs in a
user and mount namespace. Unavailable MDWE or namespaces are reported as SKIP.
To run the shared-mm VFORK fixture by hand:

```sh
cc -O2 tests/rocky/mdwe-exec.c -o /tmp/mdwe-exec
# test-exec-refused built for RISC-V from native-vfork-poc/test-exec-refused.c
/tmp/mdwe-exec rvvm_user_arm64 ./test-exec-refused
unshare -rm sh -c 'mount -t tmpfs -o noexec tmpfs /mnt &&
    exec rvvm_user_arm64 ./test-exec-refused /mnt'
```

test-helper-death judges execute permission from the guest's
/proc/self/maps, so it needs a host that grants EXEC.

Where the host refuses writable-executable memory, the JIT code cache is
one memfd mapped twice, writable and executable. Those mappings are shared,
so a fork child that kept its parent's cache would compile into the same
pages, and each process would run the other's code. A fork child therefore
maps a cache of its own before it next runs guest code; an RWX cache is a
private mapping and is kept. VFORK children are interpreted and never
compile. `native-vfork-poc/test-jit-fork.c` has a parent and its fork,
CLONE_FILES fork, private VFORK and shared-mm VFORK children compile at the
same time and checks every result; run it under `mdwe-exec` with the JIT
enabled.

### Existing implementation regressions

JIT metadata starts with a bounded reserve and grows fallibly. Under finite
RLIMIT_AS, cache mappings and metadata share a process budget of 50% of the
limit; growth accounts for temporary replacement buffers. At 80% mapped
process virtual memory, contexts are freed when their owners leave generated
code. They can resume JIT execution below 70%, avoiding repeated eviction and
regrowth near the threshold. The kernel continues to enforce the real limit.
The native fixtures check growth with a 1 GiB limit, preserved lookups/fault
metadata, failed allocations, shared budgeting, reclamation and recovery.

Pressure sampling uses a short-lived native helper with a private descriptor
table. Tests verify sampling with exhausted descriptor slots and preservation
of POSIX locks. Sampling is throttled to ten times per second for finite
limits; missing procfs, denied unshare or exhausted native thread capacity
disable the heuristic, while budgeting and kernel enforcement remain active.
On glibc hosts, launch with a finite limit also bounds RVVM's native allocator
to one arena to reduce unused virtual reservations. This does not change the
guest allocator or its environment. Guest mappings can still consume enough
address space to trigger eviction; finite-limit performance depends on that
headroom rather than just the numerical limit.

Run native tests with `bash tests/rocky/run-tests.sh`. To add guest tests, pass
one or more emulator binaries; the runner requires Clang and LLD and exercises
Sv39/Sv48 with JIT enabled and disabled:

```sh
bash tests/rocky/run-tests.sh release.linux.arm64/rvvm_user_arm64
```

The runner also runs the vfork and clone-thread guests under `noclone3`, a
host wrapper whose seccomp filter refuses clone3 with ENOSYS, as Docker's and
Podman's default profiles do. RVVM then makes VFORK children, its observer
and special forks with clone(2). Run any guest that way by hand:

```sh
cc -O2 -o noclone3 tests/rocky/noclone3.c
./noclone3 release.linux.x86_64/rvvm_user_x86_64 ./guest
./noclone3 --eperm release.linux.x86_64/rvvm_user_x86_64 ./guest
```

The filter is inherited across exec, so it may also wrap a guest started
through binfmt_misc. With `--eperm`, glibc's own pthread_create fails, since
glibc falls back to clone only on ENOSYS: RVVM cannot start the threads a
VFORK needs, and the guest gets ENOMEM. `native-vfork-poc/test-no-clone3.c`
covers vfork, posix_spawn, private VFORK, the CLONE_PIDFD and TID flag
combinations and nested VFORK children; build it like the other fixtures
there and run it under `noclone3`.

Coverage includes private/native isolation, sparse backing, file COW and EOF,
SysV detach ownership, exec completion and failed-exec visibility, child VMA
changes, private descriptor relocation, robust cleanup before guest TID
clearing, and vfork/exit status after process-leader exit.

The fork-cache fixtures check reuse after kernel reaping, rejection of a
fabricated exit while the child is live or a zombie, and a surviving
`CLONE_FILES` grandchild after repeated parent forks. Cached mappings are
bounded to 16 pairs. Further process/helper creation marks a guard as escaped;
retirement then drops only the parent's mapping, without resetting shared
state or following pointers allocated in another process.

The descriptor-limit fixture also stresses concurrent executable opens during
pin relocation. It compares the canonical executable inode and checks that
each open starts with an independent file offset. Pin readers holding the outer
descriptor guard need no nested metadata lock; readlink and wait bookkeeping
retain their metadata locking.

The proc executable fixture reads and opens a child's guest executable before
debugger attachment. Proc identity discovery uses kernel-authorized memory
reads; debugger operations retain their attachment checks. Process namespace
clone flags are passed to Linux inside the static libc fork recovery path.

Run the six namespace/FUSE glibc regressions on dev against its installed
interpreter and preserved Mock root:

```sh
sudo bash tests/rocky/run-glibc-namespace-tests.sh \
    /srv/rvvm-backups-storage/glibc-suite-801413-20261008/root \
    /var/tmp/rvvm-glibc-namespace-results
```

This uses Mock's nspawn launch settings, including `SYSTEMD_SECCOMP=0` and
`/dev/fuse`, without an enclosing user namespace. Machine registration is
disabled because these checks do not need host machine-manager integration.
It archives each target's old results and executes its original Makefile
recipe, including container wrappers and per-test environment. All six must
report PASS in Sv39/Sv48 with JIT enabled and disabled; UNSUPPORTED fails
acceptance. This is a targeted rerun, not a complete RPM build. An optional
third argument supplies a target list, and a fourth selects one mode such as
`48:jit` for additional coverage.

Filesystem classification reads kernel mount information instead of issuing
`fstatfs` on guest files. Such a probe changes the protocol on FUSE and can
deadlock a guest filesystem server while the descriptor guard is held.

The ARM64 static performance candidate uses this build command (the mandatory
floating-point flags remain enabled):

```sh
make -j16 USE_GUI=0 USE_SOUND=0 USE_NO_DLIB=1 \
    CFLAGS='-O3 -fPIE -DUSER_FAULT_META' LDFLAGS=-static-pie
```

Compare candidate and installed binaries in the same private binfmt namespace,
with identical flags, environment and CPU affinity. Record binary hashes and
paired trials, and check workload output hashes before interpreting timings.

The dev acceptance workload is `rust-sequoia-sq-1.4.0.1-2.el10_2` in the
preserved Rocky 10.2 buildroot 179561/repository 156250. Test the candidate in
a private binfmt mount/PID namespace, with no diagnostic preload, leaving the
installed emulator and shared binfmt registration unchanged.
