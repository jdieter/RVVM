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

The dev acceptance workload is `rust-sequoia-sq-1.4.0.1-2.el10_2` in the
preserved Rocky 10.2 buildroot 179561/repository 156250. Test the candidate in
a private binfmt mount/PID namespace, with no diagnostic preload, leaving the
installed emulator and shared binfmt registration unchanged.
