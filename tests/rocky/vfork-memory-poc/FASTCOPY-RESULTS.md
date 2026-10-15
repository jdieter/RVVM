# Nonprivileged eager vfork copy optimization

The accepted candidate retains the existing eager sharing and restoration
model. For readable anonymous regions, population passes the source directly
to the existing kernel pwrite, avoiding the staging pread from proc/mem.
Restoration compares backing bytes against the readable original alias,
avoiding its staging pread. All writes back to originals still use the old
kernel path, including readonly/protected originals. Private files and
anonymous mappings without PROT_READ keep the old copying path.

It adds no mappings, buffers, descriptors, privilege requirement, persistent
backings, dirty tracking, or changes to fork/vfork lifecycle. Sparse pagemap
selection, file EOF/SIGBUS behavior, unchanged file page-cache ownership,
mapping order, rollback and real address-space accounting are unchanged.

`fastcopy.patch` contains only the production header change and the extended
native VM-runtime regression. It applies to the current imported baseline;
it does not include those imported changes or either earlier POC.
The exact candidate binary SHA256 is
`2891cba7014d4f8422548497392b885a2022bf2a8c4f0eaecf55910b474b08af`.
Build flags match the deployed baseline exactly:

```sh
make -j12 USE_GUI=0 USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1 \
  USE_NO_LIBATOMIC=1 CFLAGS='-O3 -fPIE -DUSER_FAULT_META' \
  LDFLAGS=-static-pie BUILDDIR=release.matched \
  release.matched/rvvm_user_arm64
```

## Measured performance

The same actual RISC-V posix_spawn/xz driver and retained Rocky kernel modules
were used for an interleaved comparison with the deployed baseline
`0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf`.
Each caller reserves 8 GiB sparsely in addition to its resident heap. Three
independent caller processes per variant each perform three launches. Every
output is hashed independently against native xz's decompressed reference.
All **42 runs / 126 launches passed**.

| Caller and input | Baseline warm total | Candidate warm total | Improvement |
| --- | ---: | ---: | ---: |
| 1 GiB, 8 writing peers, small module | 729.11 ms | 610.21 ms | 16.3% |
| 3 GiB, 96 writing peers, small module | 2029.41 ms | 1762.30 ms | 13.2% |
| 1 GiB, 8 writing peers, large module | 845.75 ms | 743.46 ms | 12.1% |

First / warmed launch medians (the large-module total above includes waiting
for useful decompression work after launch):

| Caller and input | Baseline first / warm | Candidate first / warm |
| --- | ---: | ---: |
| 1 GiB, small module | 737.17 / 728.77 ms | 609.92 / 609.86 ms |
| 3 GiB, small module | 2047.10 / 2029.04 ms | 1761.44 / 1761.96 ms |
| 1 GiB, large module | 766.51 / 768.66 ms | 661.91 / 664.20 ms |

Warm total ranges were 649.63–739.53 versus 591.08–629.73 ms for the 1 GiB
case, 1992.63–2041.73 versus 1711.50–1795.38 ms for 3 GiB, and
834.57–867.19 versus 696.83–760.39 ms for the large module.
`fastcopy-comparison.jsonl` records all seven cases, including launch-only,
small callers and an additional 17 MB readonly private file mapping, with
exact commands, CPU, RSS, faults and output hashes.

This is a modest improvement, not a restoration of historical kernel build
times. The full resident heap is still copied and compared on every vfork.

## Correctness and permissions

The complete dev regression harness passed **15 native tests and 80 guest
configurations**, including interpreter/JIT and VA39/48 modes, concurrent
vfork, descriptor limits, clone/fork behavior and protection errors. Its log
is `/var/tmp/rvvm-vfork-memory-poc-20261013/fastcopy/full-regression.log`.

The extended VM-runtime test passes partial RW/write-only/PROT_NONE/readonly
alias restoration, split regions with nonzero backing offsets, tight finite
RLIMIT_AS sharing with unchanged VmSize, and an ENOMEM rollback preserving
guest bytes. Existing sparse mapping, private-file external-change/COW,
beyond-EOF SIGBUS and ordinary-fork isolation tests also pass.

Real guest xz and the sharing/vfork/concurrent-vfork/nofile fixtures additionally
passed under numeric production build credentials **UID 993 / GID 135**.
The mount namespace/chroot was prepared by the test launcher, then credentials
were dropped before running the emulator. The emulator needs no UFFD access,
host capability, device permission change or sysctl change.

Standalone VM-runtime tests must use the harness's `ulimit -c 0`: the expected
SIGBUS child otherwise dumps the sparse shared mapping and allocates its holes
before the allocation assertion. The same launch error affected the unchanged
baseline; it was corrected before acceptance.

## Rejected extra optimization and delivery limits

A second experiment also compared directly against the existing shared guest
mapping. It produced similar/slower timings and doubled recorded parent peak
RSS through shared-view page faults (about 6 GiB for a 3 GiB caller). That
variant is not in the accepted patch. No new aliases or additional address
space were used in either experiment.

No deployed emulator, binfmt registration, service or host setting was changed.
Main-source integration belongs to the root agent. Replacing a binary cannot
modify the already-running rpmbuild parent's copy loop: existing builds keep
their loaded emulator. Restarting a build would repay its compilation and
packaging time; these microbenchmarks do not establish that restarting the
current long-running tasks would finish sooner.
