/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Generic Linux mmap flags reach the kernel with their native effect, and
 * protection bits are validated as Linux does. Native and emulated runs must
 * both pass. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef MAP_DROPPABLE
#define MAP_DROPPABLE 0x08
#endif
#ifndef PROT_SEM
#define PROT_SEM 0x8
#endif
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif

static size_t page;

/* VmFlags of the smaps entry containing address. */
static void vm_flags(void* address, char* out, size_t size)
{
    FILE* smaps = fopen("/proc/self/smaps", "r");
    assert(smaps);
    char line[512];
    int inside = 0;
    out[0] = 0;
    while (fgets(line, sizeof(line), smaps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx ", &start, &end) == 2)
            inside = start <= (uintptr_t)address && (uintptr_t)address < end;
        else if (inside && !strncmp(line, "VmFlags:", 8)) {
            snprintf(out, size, "%s", line + 8);
            break;
        }
    }
    fclose(smaps);
}

static int has_flag(void* address, const char* flag)
{
    char flags[512];
    vm_flags(address, flags, sizeof(flags));
    char needle[8];
    snprintf(needle, sizeof(needle), " %s", flag);
    return strstr(flags, needle) != NULL;
}

static int kernel_at_least(int major, int minor)
{
    struct utsname name;
    int a = 0, b = 0;
    return !uname(&name) && sscanf(name.release, "%d.%d", &a, &b) == 2
        && (a > major || (a == major && b >= minor));
}

int main(void)
{
    page = sysconf(_SC_PAGESIZE);
    const size_t size = 16 * page;

    /* MAP_POPULATE faults the pages in before returning. */
    unsigned char* p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    assert(p != MAP_FAILED);
    unsigned char resident[16];
    assert(!mincore(p, size, resident));
    for (int i = 0; i < 16; ++i) assert(resident[i] & 1);
    assert(!munmap(p, size));

    /* MAP_LOCKED, MAP_NORESERVE and MAP_GROWSDOWN set their VMA flags. */
    p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    assert(p != MAP_FAILED && has_flag(p, "lo"));
    assert(!munmap(p, page));
    p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    assert(p != MAP_FAILED && has_flag(p, "nr"));
    assert(!munmap(p, page));
    p = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);
    assert(p != MAP_FAILED && has_flag(p + 3 * page, "gd"));
    assert(!munmap(p, 4 * page));
    p = mmap(NULL, page, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_NONBLOCK, -1, 0);
    assert(p != MAP_FAILED && !munmap(p, page));

    /* Legacy mapping types ignore unknown bits, including x86's MAP_32BIT
     * value, which RISC-V does not define. */
    p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x200000, -1, 0);
    assert(p != MAP_FAILED && !munmap(p, page));
    p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x40, -1, 0);
    assert(p != MAP_FAILED && !munmap(p, page));

    /* MAP_SHARED_VALIDATE rejects unknown bits for a file mapping. */
    char path[] = "/tmp/rvvm-mmap-flags-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0 && !unlink(path) && !ftruncate(fd, page));
    p = mmap(NULL, page, PROT_READ, MAP_SHARED_VALIDATE, fd, 0);
    assert(p != MAP_FAILED && !munmap(p, page));
    errno = 0;
    assert(mmap(NULL, page, PROT_READ, MAP_SHARED_VALIDATE | 0x200000, fd, 0) == MAP_FAILED
           && errno == EOPNOTSUPP);
    close(fd);

    /* MAP_DROPPABLE is its own mapping type since Linux 6.11. */
    if (kernel_at_least(6, 11)) {
        p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_DROPPABLE | MAP_ANONYMOUS, -1, 0);
        assert(p != MAP_FAILED && !munmap(p, page));
    }

    /* mprotect rejects protection bits Linux does not define. (arm64 defines
     * 0x10 and 0x20 as BTI and MTE; RISC-V does not, so RVVM must check.) */
    p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    errno = 0;
    assert(mprotect(p, page, PROT_READ | 0x40) == -1 && errno == EINVAL);
    assert(!mprotect(p, page, PROT_READ | PROT_SEM));
    assert(!munmap(p, page));
    puts("PASS mmap flags reach Linux and mprotect validates protection bits");
    return 0;
}
