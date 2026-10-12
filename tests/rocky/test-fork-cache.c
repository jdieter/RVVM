/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "util/utils.h"
static long errno_ret(long ret) { return ret == -1 ? -errno : ret; }
static void user_ptrace_set_exe_fd_pointer(uint32_t* fd) { (void)fd; }
static void user_exe_relocation_held(void) {}
#include "core/rvvm_user_fd_table.h"
#include "core/rvvm_user_fork_cache.h"

int main(void)
{
    assert(!prctl(PR_SET_CHILD_SUBREAPER, 1));
    user_fd_table_t* source = user_fd_table();
    user_fd_table_t* reused = NULL;
    for (unsigned i = 0; i < 32; ++i) {
        struct user_fork_slot* slot = user_fork_cache_prepare(source, true);
        assert(slot && (!reused || slot->table == reused));
        reused = slot->table;
        pid_t pid = fork();
        assert(pid >= 0);
        user_fork_cache_finish(slot, pid);
        if (!pid) {
            user_fd_guard_child();
            /* These pointers exist only in the child's mm. Parent retirement
             * must not run the ordinary table destructor on this header. */
            assert(user_fd_waits_init(reused));
            _exit(0);
        }
        int status;
        user_fork_cache_reaped(pid); // A fabricated exit must not reuse a live/zombie child.
        assert(slot->pid == pid);
        assert(waitpid(pid, &status, 0) == pid && status == 0);
        user_fork_cache_reaped(pid);
    }
    struct user_fork_slot* slot = user_fork_cache_prepare(source, true);
    user_fd_table_t* inherited = slot->table;
    int channel[2];
    assert(!pipe(channel));
    pid_t pid = fork();
    assert(pid >= 0);
    user_fork_cache_finish(slot, pid);
    if (!pid) {
        user_fd_guard_child();
        atomic_store_uint32(&inherited->guard->escaped, 1);
        assert(user_fd_mutex_share(&inherited->guard->lock));
        pid_t grandchild = fork();
        assert(grandchild >= 0);
        if (!grandchild) {
            user_fd_guard_child();
            close(channel[1]);
            char byte;
            assert(read(channel[0], &byte, 1) == 1);
            /* Its parent was reaped, but the shared mapping is still ours. */
            assert(atomic_load_uint32(&inherited->guard->escaped) == 1);
            _exit(0);
        }
        _exit(0);
    }
    close(channel[0]);
    int status;
    assert(waitpid(pid, &status, 0) == pid && status == 0);
    user_fork_cache_reaped(pid);
    assert(!slot->table);
    slot = user_fork_cache_prepare(source, true);
    assert(slot && !atomic_load_uint32(&slot->guard->escaped));
    user_fork_cache_finish(slot, -1);
    assert(write(channel[1], "x", 1) == 1);
    close(channel[1]);
    assert(waitpid(-1, &status, 0) > 0 && status == 0);
    for (size_t i = 0; i < 16; ++i)
        if (user_fork_slots[i].table) user_fork_slot_discard(&user_fork_slots[i]);
    return 0;
}
