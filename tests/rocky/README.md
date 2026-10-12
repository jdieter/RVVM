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

### Existing implementation regressions

Run native tests with `bash tests/rocky/run-tests.sh`. To add guest tests, pass
one or more emulator binaries; the runner requires Clang and LLD and exercises
Sv39/Sv48 with JIT enabled and disabled:

```sh
bash tests/rocky/run-tests.sh release.linux.arm64/rvvm_user_arm64
```

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
