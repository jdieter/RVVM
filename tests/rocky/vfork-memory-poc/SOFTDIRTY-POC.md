# Cached backing / soft-dirty vfork POC

This is an isolated emulator experiment, not a production change. The benchmark
snapshot is `softdirty-poc.patch`, against the supplied current-source tarball.
The ARM static binary SHA-256 is
`34714e7623200dc9c28f997e8ec357936737440c3de95883a8c2e730404937d5`.

## Decisive result: unavailable on the ARM64 development host

The host exposes `/proc/self/clear_refs`, and writing `4` succeeds. That alone
does **not** establish soft-dirty support. The actual write probe produced:

```
before=8100000000000000 clean=8100000000000000 written=8100000000000000 supported=0
```

No soft-dirty bit appeared after writing an anonymous page. The development
kernel's configuration also has no `CONFIG_MEM_SOFT_DIRTY` or
`CONFIG_HAVE_ARCH_SOFT_DIRTY` selection. The same native probe on local x86_64
produced:

```
before=8180000000000000 clean=8100000000000000 written=8180000000000000 supported=1
```

The emulator now probes the actual behavior once per guest-process epoch and
fails closed. On this ARM host, it retains the current full population and full
comparison. An initial ungated experiment appeared much faster but corrupted
guest state: its zero dirty bits were misinterpreted as unchanged pages. Those
accelerated measurements are invalid and must not be used.

## Implemented mechanism for capable hosts

- A persistent native helper has a private file-descriptor table and retains
  anonymous-region memfds across vfork launches. Services reopen them through
  `/proc/<tid>/fd/<fd>`; no cache descriptors enter the guest's descriptor table.
- Cache keys are guest mapping address and size. Present/swapped pages with
  soft-dirty bit 55 refresh the backing. Absent clean pages punch sparse holes.
- Private file mappings always refresh and retain their existing baseline
  comparison, so caching cannot hide an external file change.
- Shared-view installation clears soft-dirty state before the guest fork.
  Before exec, a child RPC asks the resource service to collect the child's
  dirty bits while its old mm still exists. A failed exec revokes the completion
  proof before resuming guest code.
- Restoration examines parent dirty bits and the collected child bitmap.
  Exit, guest robust-list registration, mapping mutations, missing tracking,
  and unreported death take the existing full-comparison path. This is essential
  because kernel robust-list cleanup can modify guest bytes after a pre-exit
  handshake and immediately before the old page tables disappear.
- After restoration, dirty state resets while guest peers remain parked;
  resetting after resuming them would lose intervening parent writes.
- Ordinary-fork process epochs reset the keeper metadata rather than referring
  to a helper that did not survive the fork.

## Verified development-host checks

Built in `localhost/rvvm-heap-build-env:20261008` with production flags:

```
make -j8 USE_LIB=1 USE_GUI=0 USE_SOUND=0 USE_NO_DLIB=1 USE_NO_LIBATOMIC=1 \
  CFLAGS='-O3 -fPIE -DUSER_FAULT_META' LDFLAGS=-static-pie
```

Actual RISC-V common conformance passed with the capability fallback active:
kernel `read()` into shared memory, concurrent parent writes, RO-to-RW changes,
failed-exec errno publication, SIGKILL stores, and subsequent ordinary-fork COW.

Actual RISC-V xz, launched from the common RISC-V spawn fixture with 1 GiB
resident memory and eight peer threads, completed in 0.8653, 0.8587, and 0.8712
seconds. These are **fallback results**, not soft-dirty acceleration results.
The parent experiment owns the interleaved baseline/UFFD/fallback matrix.

Tests use an isolated mount namespace and chroot, with the real buildroot xz
and a kernel module input. No host sysctl, global binfmt, service, installed
emulator, or production host was changed.

## Remaining supported-host work

The fast path has not passed real guest conformance on a soft-dirty-capable
host; only native capability behavior was verified locally. Do not ship it.
Cache retention currently caps entries at 256, not resident bytes. Full mapping
replacement/discard tests and a resident-byte eviction policy are required.
In particular, an absent page from a newly replaced VMA may itself be marked
soft-dirty and must still evict stale backing data. A separate unbenchmarked
draft addressing absent pages and a 2 GiB resident cache budget is saved at
`/tmp/rvvm-softdirty-supportedhost-unverified.h`; it is intentionally excluded
from the frozen benchmark source and binary.

For ARM64 builders, soft-dirty is unavailable; implementing this design would
require a different dirty-tracking mechanism or host-kernel support.
