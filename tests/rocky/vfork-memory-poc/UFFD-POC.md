# Lazy vfork sharing with userfaultfd

This is a disposable RVVM source copy. It must not be installed as a builder
emulator. The primary checkout and deployed binary were not modified.

Only guest private VMAs are migrated. Anonymous guest VMAs use missing-shmem
fault handling; original anonymous mappings stay at private aliases. A handler
copies an original page into shared shmem on its first access. Fork events give
the handler descriptors for child address spaces. A racing COPY returning
EEXIST must explicitly WAKE that address, since another process may already
have populated the shared page. Both parent and child then see the same page.
COPY returning EAGAIN is queued for later retry while fork events continue to
be processed. Retrying it inline can deadlock against the pending fork event.
The copy buffer is preallocated and handler readiness is established before
the primary can fork; the handler must not allocate under libc fork locks.

Private file VMAs retain the existing eager population and baseline comparison.
Restoration scans only allocated shmem extents and compares pages with original
aliases, retaining ordinary anonymous/file-backed COW mappings afterward. There
is no write-protection optimization: accessed clean pages can still be compared.

Production-matching ARM64 build (inside the existing Rocky builder container):

    make -j12 USE_GUI=0 USE_LIB=1 USE_LTO=1 USE_NO_DLIB=1 \
      USE_NO_LIBATOMIC=1 CFLAGS='-O3 -fPIE -DUSER_FAULT_META' \
      LDFLAGS=-static-pie BUILDDIR=release.matched \
      release.matched/rvvm_user_arm64

An unmodified source rebuild with these flags reproduces installed SHA256
0af5216c270dd2255f717dee79ff1055673d1574871ddbe4a1b60bfe09fb1adf.

The development kernel is 6.19.10-300.fc44.aarch64. Kernel-fault-capable
userfaultfd fails EPERM as fedora. Under isolated sudo execution, API 170
reports features 0x1ffff and ioctls 0x8000000000000003: MISSING_SHMEM,
EVENT_FORK, and WP_HUGETLBFS_SHMEM are available. The host sysctl remains zero;
no device permissions, services, binfmt registrations, or installed binaries
were changed.

The production-flags common sharing probe passes kernel writes to a previously
untouched page, concurrent parent writes visible to the child, RO-to-RW,
failed-exec writes, SIGKILL write survival, and ordinary-fork isolation.
The original assembly vfork, concurrent vfork, and nofile fixtures all passed
the final production-flags build. A privileged native VM-runtime probe passed
private-file COW, external file updates, beyond-EOF SIGBUS, sparse memory, and
restored ordinary-fork COW as well.

Known POC gaps: metadata reallocation and splits need synchronization against
the handler; the native pthread lifecycle in a separate CLONE_VM resource group
needs review; private file memory still copies eagerly; host permissions and
feature failure need a deliberate production fallback policy; finite memory
limits and wider VMA mutation/child-death races need additional coverage.
The final frozen revision passes 3 GiB with 96 peers (three real xz launches;
warm launch times 95.4 and 95.9 ms) after fixing COPY EAGAIN event handling.
The allocated shared backing in that probe was 1,257,472 bytes, measured with
fstat st_blocks, despite the 3 GiB resident parent memory. Earlier revisions
failed this case and are retained only as diagnostic evidence.
The final binary SHA256 is
fe51a1570a6a3d6ce11108fcfb8843b4f55a1dae31ff06b5ccfe4fc5db861c85.
