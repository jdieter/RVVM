/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FORK_CACHE_H
#define RVVM_USER_FORK_CACHE_H

/* Keep parent mappings until a real terminal kernel wait. Child-created
 * pointers in shared headers do not name allocations in the parent's mm. */
struct user_fork_slot {
    user_fd_table_t* table;
    user_fd_guard_t* guard;
    uint32_t *table_refs, *guard_refs;
    size_t bytes;
    pid_t pid;
};
static struct user_fork_slot user_fork_slots[16];
static user_fd_mutex_t user_fork_cache_lock;

static void user_fork_slot_discard(struct user_fork_slot* slot)
{
    free(slot->table_refs);
    free(slot->guard_refs);
    munmap(slot->table, slot->bytes);
    *slot = (struct user_fork_slot){0};
}

/* Caller owns the descriptor guard. Hold this private lock through fork and
 * publication so another parent thread cannot reap before recording the PID. */
static struct user_fork_slot* user_fork_cache_prepare(user_fd_table_t* source, bool eligible)
{
    user_fd_mutex_lock(&user_fork_cache_lock);
    if (!eligible) return NULL;
    for (size_t i = 0; i < 16; ++i) {
        struct user_fork_slot* slot = &user_fork_slots[i];
        if (slot->pid) continue;
        if (!slot->table) {
            slot->table = user_fd_table_alloc(NULL);
            if (!slot->table) return NULL;
            slot->guard = slot->table->guard;
            slot->table_refs = slot->table->refs;
            slot->guard_refs = slot->guard->refs;
            slot->bytes = (char*)slot->guard - (char*)slot->table + sizeof(*slot->guard);
        }
        *slot->table = (user_fd_table_t){.refs = slot->table_refs, .guard = slot->guard,
            .guard_adjacent = true, .exec_handoff = -1};
        *slot->guard = (user_fd_guard_t){.refs = slot->guard_refs};
        *slot->table_refs = *slot->guard_refs = 1;
        slot->table->exe_fd = atomic_load_uint32_relax(&source->exe_fd);
        memcpy(slot->table->descriptor, source->descriptor, sizeof(source->descriptor));
        return slot;
    }
    return NULL; // Ignored/autoreaped children cannot grow the cache unboundedly.
}

static void user_fork_cache_finish(struct user_fork_slot* selected, pid_t pid)
{
    if (!pid) {
        /* Only the selected table belongs to this child. Drop inherited cache
         * views locally without touching shared locks or child-only pointers. */
        for (size_t i = 0; i < 16; ++i) {
            struct user_fork_slot* slot = &user_fork_slots[i];
            if (slot != selected && slot->table) user_fork_slot_discard(slot);
            else *slot = (struct user_fork_slot){0};
        }
        user_fork_cache_lock = (user_fd_mutex_t){0};
    } else {
        if (selected) selected->pid = pid > 0 ? pid : 0;
        user_fd_mutex_unlock(&user_fork_cache_lock);
    }
}

static void user_fork_cache_reaped(pid_t pid)
{
    user_fd_mutex_lock(&user_fork_cache_lock);
    for (size_t i = 0; i < 16; ++i) {
        struct user_fork_slot* slot = &user_fork_slots[i];
        if (slot->pid != pid) continue;
        /* Guest wait buffers are writable by other guest threads. Confirm
         * disappearance independently before trusting their PID/status; a
         * recycled PID simply leaves this bounded slot unavailable. */
        if (!syscall(SYS_kill, pid, 0) || errno != ESRCH) continue;
        if (atomic_load_uint32(&slot->guard->escaped)) user_fork_slot_discard(slot);
        else slot->pid = 0;
    }
    user_fd_mutex_unlock(&user_fork_cache_lock);
}
#endif
