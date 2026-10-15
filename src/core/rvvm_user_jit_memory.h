/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_JIT_MEMORY_H
#define RVVM_USER_JIT_MEMORY_H

#if defined(__linux__) && defined(USE_JIT)
#include "threading.h"

static void* user_jit_probe_worker(void* opaque)
{
    uint64_t* size = opaque;
    uint64_t all = UINT64_MAX;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &all, NULL, 8);
    /* Never open a monitoring fd in the guest's table, even transiently.
     * Closing a private files_struct also preserves the guest's POSIX locks. */
    if (syscall(SYS_unshare, CLONE_FILES)) return NULL;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 0U, ~0U, 0)) return NULL;
#else
    return NULL;
#endif
    int fd = open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    char text[128];
    ssize_t count = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (count > 0) {
        text[count] = 0;
        uint64_t pages = strtoull(text, NULL, 10);
        size_t page = vma_page_size();
        if (pages <= UINT64_MAX / page) *size = pages * page;
    }
    return NULL;
}

static uint64_t user_jit_memory_probe(void)
{
    /* Finite limits only. Avoid creating a native helper for every mmap;
     * metadata growth and guest VM changes need at most ten samples/sec. */
    static uint64_t next_sample;
    static uint64_t last_size;
    uint64_t now = rvtimer_clocksource(1000);
    uint64_t next = atomic_load_uint64(&next_sample);
    if (now < next || !atomic_cas_uint64(&next_sample, next, now + 100))
        return atomic_load_uint64(&last_size);
    int saved_errno = errno;
    uint64_t size = 0;
    /* Keep copied descriptors from outliving a guest close while the
     * helper separates its table. The caller has blocked all signals.
     * rvvm_thread_* keeps the helper's lifecycle out of raw forks. */
    user_fd_lock();
    rvvm_thread_t* helper = rvvm_thread_create_ex(user_jit_probe_worker, &size, 256 * 1024);
    if (helper) {
        rvvm_thread_join(helper);
        user_private_signals_restore();
    }
    user_fd_unlock();
    atomic_store_uint64(&last_size, size);
    errno = saved_errno;
    /* Missing procfs, seccomp, NOFILE=0 or exhausted thread capacity disable
     * the heuristic; the shared JIT budget and real kernel limit still apply. */
    return size;
}
#endif
#endif
