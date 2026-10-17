/* SPDX-License-Identifier: GPL-3.0-or-later */
/* The guest's main stack, laid out as Linux lays out a process stack. The
 * host kernel grows a MAP_GROWSDOWN mapping on demand and refuses to grow it
 * past RLIMIT_STACK, read at the fault, so an overflow faults just below the
 * stack VMA. Below it lies a free gap, which guest placement never chooses:
 * stack-overflow detection (gnulib's c-stack and sigsegv) tells an overflow
 * from a stray access by the fault's distance from the stack VMA compared
 * with the mapping below it. */
#ifndef RVVM_USER_STACK_H
#define RVVM_USER_STACK_H

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "rvvm_user_vma.h"

/* Linux's defaults: stack_guard_gap, mmap_base's minimum gap below the stack
 * and setup_arg_pages' initial expansion past the arguments. */
#define USER_STACK_GUARD_GAP (UINT64_C(256) << 12)
#define USER_STACK_MIN_GAP   (UINT64_C(128) << 20)
#define USER_STACK_EXPAND    (UINT64_C(128) << 10)

/* The range the stack may grow into: RLIMIT_STACK as exec saw it, with the
 * guard gap, within Linux's minimum. An unlimited or huge limit gets a large
 * gap of the guest's address space, as Linux's layout would. */
static size_t user_stack_gap(const struct rlimit* limit)
{
    size_t page = user_vma_page();
    size_t max = (user_vma_layout.top - user_vma_layout.low) / 16;
    if (max > (UINT64_C(4) << 30)) max = UINT64_C(4) << 30;
    if (max < USER_STACK_MIN_GAP) max = USER_STACK_MIN_GAP;
    size_t gap = max;
    if (limit->rlim_cur != RLIM_INFINITY && limit->rlim_cur < max - USER_STACK_GUARD_GAP)
        gap = limit->rlim_cur + USER_STACK_GUARD_GAP;
    if (gap < USER_STACK_MIN_GAP) gap = USER_STACK_MIN_GAP;
    return (gap + page - 1) & ~(page - 1);
}

/* The host kernel places mappings it chooses itself, such as RVVM's heap,
 * thread stacks and JIT caches, top-down from its mmap_base, filling the
 * highest free hole that fits. The stack's growth range is such a hole. On
 * x86-64, mmap_base lies a random distance, up to a TiB or more, below the
 * host stack, inside the 48-bit guest window, so host mappings could take
 * the range and stop the stack short of RLIMIT_STACK. Find where host
 * mappings start with a kernel-placed probe, and keep the range at least
 * USER_STACK_HOST_ROOM below it: the host would need that much of its own
 * mappings to reach it. Where host mappings start above the window (arm64)
 * or grow bottom-up from far below it (the legacy layout), the window's
 * top is kept. */
#define USER_STACK_HOST_ROOM (UINT64_C(256) << 30)

static uintptr_t user_stack_ceiling(size_t gap)
{
    size_t page = user_vma_page();
    uintptr_t top = user_vma_layout.top;
    void* probe = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) return top;
    munmap(probe, page);
    uintptr_t host = (uintptr_t)probe;
    if (host < USER_STACK_HOST_ROOM) return top;
    uintptr_t ceiling = (host - USER_STACK_HOST_ROOM) & ~(uintptr_t)(page - 1);
    /* Leave guest placement's heap arena and the window's floor alone. */
    uintptr_t floor = user_vma_layout.low + user_vma_layout.brk_window * 2;
    if (ceiling >= top || ceiling < floor + gap) return top;
    return ceiling;
}

/* Labels the guest stack [stack] in /proc/self/maps, and reports it as the
 * start of the stack in /proc/self/stat, by moving mm->start_stack there.
 * Unprivileged PR_SET_MM_MAP replaces all of the mm's layout fields, so it
 * re-supplies the current ones; brk among them, which only a concurrent brk
 * can change, so this runs only while the process has a single thread. The
 * kernel may lack checkpoint/restore support: the label is then missing. */
static void user_stack_label(uintptr_t start_stack)
{
#ifdef PR_SET_MM_MAP
    char buffer[2048];
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t length = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (length <= 0) return;
    buffer[length] = 0;
    /* The command name may contain anything up to its last ')'. */
    char* fields = strrchr(buffer, ')');
    if (!fields) return;
    unsigned long long value[52] = {0};
    char* cursor = fields + 2;
    /* Field 3 is the state, a character; parse the numbers after it. */
    for (int field = 3; field <= 51; ++field) {
        while (*cursor == ' ') ++cursor;
        if (!*cursor) return;
        if (field > 3) value[field] = strtoull(cursor, NULL, 10);
        while (*cursor && *cursor != ' ') ++cursor;
    }
    long threads = (long)value[20];
    if (threads != 1) return;
    struct prctl_mm_map map = {
        .start_code = value[26], .end_code = value[27],
        .start_data = value[45], .end_data = value[46],
        .start_brk = value[47], .brk = (uint64_t)syscall(SYS_brk, 0),
        .start_stack = start_stack,
        .arg_start = value[48], .arg_end = value[49],
        .env_start = value[50], .env_end = value[51],
        .exe_fd = (uint32_t)-1,
    };
    if (!map.start_code || !map.end_code || !map.arg_start || !map.env_start) return;
    if (prctl(PR_SET_MM, PR_SET_MM_MAP, (unsigned long)&map, sizeof(map), 0)) {
        rvvm_info("Cannot label the guest stack: %s", strerror(errno));
    }
#else
    UNUSED(start_stack);
#endif
}

/* Maps the guest's main stack with room for used bytes of arguments, and
 * returns its top, or NULL. Call it once, before any guest thread runs. */
static uint8_t* user_stack_map(size_t used, bool executable)
{
    size_t page = user_vma_page();
    struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };
    getrlimit(RLIMIT_STACK, &limit);
    size_t gap = user_stack_gap(&limit);
    used = (used + page - 1) & ~(page - 1);
    if (used >= gap) { errno = E2BIG; return NULL; }
    /* As setup_arg_pages: the arguments and 128 KiB, within RLIMIT_STACK. */
    size_t initial = used + USER_STACK_EXPAND;
    size_t cap = limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > gap ? gap
        : (size_t)limit.rlim_cur & ~(page - 1);
    if (initial > cap) initial = cap > used ? cap : used;

    /* Claim the whole range at once, then leave all but the stack free.
     * Under a tight RLIMIT_AS, even briefly, settle for a smaller range. */
    user_fd_lock();
    size_t least = initial + USER_STACK_GUARD_GAP;
    uint8_t* low;
    uintptr_t ceiling = user_stack_ceiling(gap);
    for (;;) {
        low = MAP_FAILED;
        if (ceiling < user_vma_layout.top)
            low = user_vma_map((void*)(ceiling - gap), gap, PROT_NONE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
        if (low == MAP_FAILED && (ceiling >= user_vma_layout.top || errno == EEXIST))
            low = user_vma_map(NULL, gap, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (low != MAP_FAILED || errno != ENOMEM || gap <= least) break;
        size_t half = (gap / 2) & ~(page - 1);
        gap = half > least ? half : least;
    }
    if (low == MAP_FAILED) { user_fd_unlock(); return NULL; }
    uint8_t* top = low + gap;
    void* stack = mmap(top - initial, initial, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
    if (stack == MAP_FAILED) {
        int error = errno;
        user_vma_unmap(low, gap);
        user_fd_unlock();
        errno = error;
        return NULL;
    }
    /* Not user_vma_unmap: placement must keep descending below the range. */
    munmap(low, gap - initial);
    user_vma_stack_low = (uintptr_t)low;
    user_vma_stack_high = (uintptr_t)top;
    user_fd_unlock();

    if (executable) user_exec_protect(stack, initial, PROT_READ | PROT_WRITE, true);
    /* The whole range: the stack takes its protection as it grows. */
    spin_lock(&mmap_lock);
    user_exec_update((uintptr_t)low, gap, executable);
    spin_unlock(&mmap_lock);
    rvvm_info("Guest stack %p-%p, growing to %p", stack, top, low);
    return top;
}

#endif
