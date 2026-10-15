/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FD_TABLE_H
#define RVVM_USER_FD_TABLE_H

#include "util/user_fd_guard.h"
#include <sys/mman.h>

struct user_fd_wait {
    struct user_fd_wait* next;
    int fd, placeholder;
    pid_t tid;
    uint32_t marker;
    uint64_t marker_address;
};

struct user_fd_relocation {
    int target, pin;
    // owner identifies the operation; recovery_pending means it died and a
    // surviving holder must reconcile it in its own kernel fd table.
    uint32_t recovery_pending, owner;
};

typedef struct {
    uint32_t exe_fd;
    /* The pointer is inherited at the same address, but its allocation is
     * private: references count native threads in this process. Other
     * processes own their mappings independently, including after SIGKILL. */
    uint32_t* refs;
    uint32_t exec_owner;
    int exec_handoff;
    user_fd_mutex_t lock;
    user_fd_guard_t* guard;
    bool guard_adjacent;
    struct user_fd_wait* waits;
    struct user_fd_wait* wait_slots;
    struct user_fd_relocation relocation;
    char descriptor[64];
} user_fd_table_t;

static user_fd_table_t* user_fd_initial;
static __thread user_fd_table_t* user_fd_current;

typedef struct user_fd_owner {
    struct user_fd_owner* next;
    user_fd_table_t* table;
    pid_t tid;
} user_fd_owner_t;
static user_fd_mutex_t user_fd_owners_lock;
static user_fd_owner_t* user_fd_owners;
static __thread user_fd_owner_t user_fd_thread_owner;
static __thread user_fd_owner_t* user_fd_owner_override;
#define user_fd_owner (*(user_fd_owner_override ? user_fd_owner_override : &user_fd_thread_owner))
static void user_exe_relocation_held(void);

static user_fd_table_t* user_fd_table_alloc(user_fd_guard_t* guard)
{
    size_t page = sysconf(_SC_PAGESIZE);
    if (sizeof(user_fd_table_t) > page || sizeof(user_fd_guard_t) > page) {
        errno = ENOMEM;
        return NULL;
    }
    size_t bytes = guard ? sizeof(user_fd_table_t) : page + sizeof(user_fd_guard_t);
    user_fd_table_t* table = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (table == MAP_FAILED) return NULL;
    table->refs = calloc(1, sizeof(*table->refs));
    if (!table->refs) { munmap(table, bytes); return NULL; }
    *table->refs = 1;
    table->exe_fd = UINT32_MAX;
    table->exec_handoff = -1;
    table->guard_adjacent = !guard;
    table->guard = guard ? user_fd_guard_retain(guard)
                         : user_fd_guard_init((void*)((char*)table + page));
    if (!table->guard) { free(table->refs); munmap(table, bytes); return NULL; }
    return table;
}

static user_fd_table_t* user_fd_table(void)
{
    if (user_fd_current) return user_fd_current;
    if (!user_fd_initial) {
        user_fd_initial = user_fd_table_alloc(NULL);
        if (!user_fd_initial) rvvm_fatal("Cannot allocate descriptor table");
        user_fd_guard_default(user_fd_initial->guard);
        user_fd_guard_set_resume(user_exe_relocation_held);
    }
    return user_fd_initial;
}

/* The metadata lock protects slot allocation and the linked list. Map the
 * slots before a process CLONE_FILES, so all sharers inherit their address. */
static bool user_fd_waits_init(user_fd_table_t* table)
{
    if (table->wait_slots) return true;
    struct user_fd_wait* slots = mmap(NULL, 4096 * sizeof(*slots), PROT_READ | PROT_WRITE,
                                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (slots == MAP_FAILED) return false;
    table->wait_slots = slots;
    return true;
}

static struct user_fd_wait* user_fd_wait_alloc(void)
{
    if (!user_fd_waits_init(user_fd_table())) return NULL;
    for (size_t i = 0; i < 4096; ++i) {
        struct user_fd_wait* wait = &user_fd_table()->wait_slots[i];
        if (!wait->tid) {
            *wait = (struct user_fd_wait){.tid = syscall(SYS_gettid), .placeholder = -1};
            user_fd_owner_marker(&wait->marker_address, &wait->marker);
            return wait;
        }
    }
    /* Normally the list reaper frees abandoned waits. Also reclaim a slot
     * whose owner was killed between allocation and list insertion. */
    for (size_t i = 0; i < 4096; ++i) {
        struct user_fd_wait* wait = &user_fd_table()->wait_slots[i];
        if (!user_fd_owner_dead(wait->tid, wait->marker_address, wait->marker)) continue;
        struct user_fd_wait** link = &user_fd_table()->waits;
        while (*link && *link != wait) link = &(*link)->next;
        if (*link) *link = wait->next;
        wait->tid = 0;
        return user_fd_wait_alloc();
    }
    return NULL;
}

static void user_fd_wait_free(struct user_fd_wait* wait) { wait->tid = 0; }

static void user_fd_waits_reap(void)
{
    user_fd_table_t* table = user_fd_table();
    struct user_fd_wait** link = &table->waits;
    while (*link) {
        struct user_fd_wait* wait = *link;
        if (user_fd_owner_dead(wait->tid, wait->marker_address, wait->marker)) {
            *link = wait->next;
            user_fd_wait_free(wait);
        } else link = &wait->next;
    }
}

static user_fd_table_t* user_fd_table_retain(void)
{
    user_fd_table_t* table = user_fd_table();
    atomic_add_uint32(table->refs, 1);
    return table;
}

static void user_fd_waits_remove(user_fd_table_t* table, pid_t tid)
{
    user_fd_mutex_lock(&table->lock);
    struct user_fd_wait** link = &table->waits;
    while (*link) {
        struct user_fd_wait* wait = *link;
        if (!tid || wait->tid == tid) { *link = wait->next; user_fd_wait_free(wait); }
        else link = &wait->next;
    }
    user_fd_mutex_unlock(&table->lock);
}

static void user_fd_table_free(user_fd_table_t* table)
{
    size_t bytes = sizeof(*table);
    if (table->guard_adjacent) {
        /* A copied files table may retain this guard after its original table
         * disappears. Keep its second page until that last reference drops. */
        if (user_fd_guard_put(table->guard))
            bytes = (char*)table->guard - (char*)table + sizeof(*table->guard);
    } else user_fd_guard_release(table->guard);
    user_fd_mutex_destroy(&table->lock);
    if (table->wait_slots) munmap(table->wait_slots, 4096 * sizeof(*table->wait_slots));
    free(table->refs);
    munmap(table, bytes);
}

static void user_fd_table_release(user_fd_table_t* table)
{
    if (table && atomic_sub_uint32(table->refs, 1) == 1 && table != user_fd_initial) {
        /* Other processes may still own waits in this shared mapping. */
        user_fd_table_free(table);
    }
}

static void user_fd_table_enter(user_fd_table_t* table)
{
    user_fd_current = table ? table : user_fd_table();
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
    *user_fd_table()->refs = 1;
    *user_fd_table()->guard->refs = 1;
    user_fd_owners_lock = (user_fd_mutex_t){0};
    user_fd_owner.tid = syscall(SYS_gettid);
    user_fd_owner.table = user_fd_table();
    user_fd_owner.next = NULL;
    user_fd_owners = &user_fd_owner;
}

/* Other native threads disappeared. Drop their bootstrap/table mappings in
 * this mm without modifying metadata still used by processes sharing files. */
static void user_fd_table_fork_discard(user_fd_table_t* table)
{
    user_fd_table_free(table);
}

static user_fd_table_t* user_fd_table_lookup(pid_t tid)
{
    user_fd_table_t* table = NULL;
    user_fd_mutex_lock(&user_fd_owners_lock);
    for (user_fd_owner_t* owner = user_fd_owners; owner; owner = owner->next) {
        if (owner->tid != tid) continue;
        table = owner->table;
        atomic_add_uint32(table->refs, 1);
        break;
    }
    user_fd_mutex_unlock(&user_fd_owners_lock);
    return table;
}

// Called with the guard held: the kernel and metadata change together.
static user_fd_table_t* user_fd_table_copy_guard(user_fd_table_t* old, bool private_guard)
{
    user_fd_table_t* next = user_fd_table_alloc(private_guard ? NULL : old->guard);
    if (!next) return NULL;
    next->exe_fd = atomic_load_uint32_relax(&old->exe_fd);
    memcpy(next->descriptor, old->descriptor, sizeof(next->descriptor));
    return next;
}

static user_fd_table_t* user_fd_table_copy(user_fd_table_t* old)
{
    return user_fd_table_copy_guard(old, false);
}

static long user_fd_table_unshare(unsigned long flags, bool range)
{
    user_fd_table_t* old = user_fd_table();
    user_fd_table_t* next = NULL;
    if (flags & CLONE_FILES) {
        next = user_fd_table_copy(old);
        if (!next) return -ENOMEM;
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
        unsigned pin = atomic_load_uint32_relax(&user_fd_table()->exe_fd);
        flags &= ~2U;
        // The pin is always CLOEXEC, including when the guest asks to mark a
        // range. Do not let guest close_range invalidate proc/exe emulation.
        if (pin >= first && pin <= last && pin != UINT32_MAX) {
            if (first < pin) ret = errno_ret(syscall(SYS_close_range, first, pin - 1, flags));
            first = pin + 1;
        }
        if (!ret && first <= last) ret = errno_ret(syscall(SYS_close_range, first, last, flags));
    }
    user_fd_unlock();
    return ret;
}

#endif
