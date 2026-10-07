/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FD_TABLE_H
#define RVVM_USER_FD_TABLE_H

#include "util/user_fd_guard.h"

struct user_fd_wait {
    struct user_fd_wait* next;
    int fd, placeholder;
    pid_t tid;
};

struct user_fd_relocation {
    int target, pin;
    // owner identifies the operation; recovery_pending means it died and a
    // surviving holder must reconcile it in its own kernel fd table.
    uint32_t recovery_pending, owner;
};

typedef struct {
    uint32_t exe_fd;
    uint32_t vm_fd;
    bool vm_service;
    uint32_t refs;
    user_fd_mutex_t lock;
    user_fd_guard_t* guard;
    struct user_fd_wait* waits;
    struct user_fd_relocation relocation;
    char descriptor[64];
} user_fd_table_t;

static user_fd_table_t user_fd_initial = {.exe_fd = UINT32_MAX, .vm_fd = UINT32_MAX, .refs = 1};
static __thread user_fd_table_t* user_fd_current;

typedef struct user_fd_owner {
    struct user_fd_owner* next;
    user_fd_table_t* table;
    pid_t tid;
} user_fd_owner_t;
static user_fd_mutex_t user_fd_owners_lock;
static user_fd_owner_t* user_fd_owners;
static __thread user_fd_owner_t user_fd_owner;
static void user_exe_relocation_held(void);

static user_fd_table_t* user_fd_table(void)
{
    return user_fd_current ? user_fd_current : &user_fd_initial;
}

static user_fd_table_t* user_fd_table_retain(void)
{
    user_fd_table_t* table = user_fd_table();
    atomic_add_uint32(&table->refs, 1);
    return table;
}

static void user_fd_waits_remove(user_fd_table_t* table, pid_t tid)
{
    user_fd_mutex_lock(&table->lock);
    struct user_fd_wait** link = &table->waits;
    while (*link) {
        struct user_fd_wait* wait = *link;
        if (!tid || wait->tid == tid) { *link = wait->next; free(wait); }
        else link = &wait->next;
    }
    user_fd_mutex_unlock(&table->lock);
}

static void user_fd_table_release(user_fd_table_t* table)
{
    if (table && atomic_sub_uint32(&table->refs, 1) == 1 && table != &user_fd_initial) {
        user_fd_waits_remove(table, 0);
        user_fd_guard_release(table->guard);
        free(table);
    }
}

static void user_fd_table_enter(user_fd_table_t* table)
{
    user_fd_current = table ? table : &user_fd_initial;
    user_fd_guard_select(user_fd_current->guard);
    user_fd_guard_set_resume(user_exe_relocation_held);
    user_fd_mutex_lock(&user_fd_owners_lock);
    user_fd_owner.table = user_fd_current;
    if (!user_fd_owner.tid) {
        user_fd_owner.tid = syscall(SYS_gettid);
        user_fd_owner.next = user_fd_owners;
        user_fd_owners = &user_fd_owner;
    }
    user_fd_mutex_unlock(&user_fd_owners_lock);
    user_ptrace_set_exe_fd_pointer(&user_fd_current->exe_fd);
}

static void user_fd_table_leave(void)
{
    user_fd_waits_remove(user_fd_table(), user_fd_owner.tid);
    user_fd_mutex_lock(&user_fd_owners_lock);
    user_fd_owner_t** owner = &user_fd_owners;
    while (*owner && *owner != &user_fd_owner) owner = &(*owner)->next;
    if (*owner) *owner = user_fd_owner.next;
    user_fd_owner.tid = 0;
    user_fd_mutex_unlock(&user_fd_owners_lock);
    user_fd_guard_select(NULL);
    user_fd_table_release(user_fd_table());
    user_fd_current = NULL;
}

static void user_fd_table_fork_child(void)
{
    user_fd_waits_remove(user_fd_table(), 0); // Other threads' lock waits vanished.
    atomic_store_uint32_relax(&user_fd_table()->refs, 1);
    user_fd_owners_lock = (user_fd_mutex_t){0};
    user_fd_owner.tid = syscall(SYS_gettid);
    user_fd_owner.table = user_fd_table();
    user_fd_owner.next = NULL;
    user_fd_owners = &user_fd_owner;
}

static user_fd_table_t* user_fd_table_lookup(pid_t tid)
{
    user_fd_table_t* table = NULL;
    user_fd_mutex_lock(&user_fd_owners_lock);
    for (user_fd_owner_t* owner = user_fd_owners; owner; owner = owner->next) {
        if (owner->tid != tid) continue;
        table = owner->table;
        atomic_add_uint32(&table->refs, 1);
        break;
    }
    user_fd_mutex_unlock(&user_fd_owners_lock);
    return table;
}

// Called with the guard held: the kernel and metadata change together.
static long user_fd_table_unshare(unsigned long flags, bool range)
{
    user_fd_table_t* old = user_fd_table();
    user_fd_table_t* next = NULL;
    if (flags & CLONE_FILES) {
        next = calloc(1, sizeof(*next));
        if (!next) return -ENOMEM;
        next->refs = 1;
        // Keep the active guard through unshare and its caller's unlock.
        next->guard = user_fd_guard_retain(old->guard);
        next->exe_fd = atomic_load_uint32_relax(&old->exe_fd);
        next->vm_fd = atomic_load_uint32_relax(&old->vm_fd);
        next->vm_service = old->vm_service;
        memcpy(next->descriptor, old->descriptor, sizeof(next->descriptor));
    }
    long ret = range ? syscall(SYS_close_range, UINT32_MAX, UINT32_MAX, 2)
                     : syscall(SYS_unshare, flags);
    if (ret < 0) { int error = errno; user_fd_table_release(next); return -error; }
    if (next) {
        user_fd_table_enter(next);
        user_fd_table_release(old);
    }
    return ret;
}

static long user_fd_unshare(unsigned long flags)
{
    user_fd_lock();
    long ret = user_fd_table_unshare(flags, false);
    user_fd_unlock();
    return ret;
}

static long user_fd_close_range(unsigned first, unsigned last, unsigned flags)
{
    if (first > last || (flags & ~6U)) return -EINVAL;
    user_fd_lock();
    long ret = 0;
    if (flags & 2) ret = user_fd_table_unshare(CLONE_FILES, true);
    if (!ret) {
        unsigned pins[2] = {atomic_load_uint32_relax(&user_fd_table()->exe_fd),
                            atomic_load_uint32_relax(&user_fd_table()->vm_fd)};
        if (pins[1] < pins[0]) { unsigned swap = pins[0]; pins[0] = pins[1]; pins[1] = swap; }
        flags &= ~2U;
        // The pin is always CLOEXEC, including when the guest asks to mark a
        // range. Do not let guest close_range invalidate proc/exe emulation.
        for (unsigned i = 0; !ret && i < 2; ++i) {
            unsigned pin = pins[i];
            if (pin < first || pin > last || pin == UINT32_MAX) continue;
            if (first < pin) ret = errno_ret(syscall(SYS_close_range, first, pin - 1, flags));
            first = pin + 1;
        }
        if (!ret && first <= last) ret = errno_ret(syscall(SYS_close_range, first, last, flags));
    }
    user_fd_unlock();
    return ret;
}

#endif
