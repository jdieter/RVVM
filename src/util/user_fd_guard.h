/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FD_GUARD_H
#define RVVM_USER_FD_GUARD_H

#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "locking.h"
typedef struct user_fd_mutex {
    uint32_t owner, sequence, waiters;
    bool shared;
    uint32_t* robust_marker;
    uint32_t registered;
    uint64_t lease, published, marker_address;
} user_fd_mutex_t;
void user_fd_mutex_lock(user_fd_mutex_t* lock);
void user_fd_mutex_unlock(user_fd_mutex_t* lock);
/* Recovery requires proof that the owner has exited. */
void user_fd_mutex_recover(user_fd_mutex_t* lock, uint32_t tid);
/* Promote while held, or acquire it internally, before exposing another mm. */
bool user_fd_mutex_share(user_fd_mutex_t* lock);
void user_fd_mutex_destroy(user_fd_mutex_t* lock);
void user_fd_owner_marker(uint64_t* address, uint32_t* value);
bool user_fd_owner_dead(uint32_t tid, uint64_t address, uint32_t value);
typedef struct user_fd_guard {
    user_fd_mutex_t lock;
    uint32_t* refs;
    /* A further process/helper may retain this mapping after its owner dies. */
    uint32_t escaped;
} user_fd_guard_t;
user_fd_guard_t* user_fd_guard_create(void);
/* Initialize a zeroed, separately unmap-able shared page supplied by caller. */
user_fd_guard_t* user_fd_guard_init(user_fd_guard_t* guard);
user_fd_guard_t* user_fd_guard_retain(user_fd_guard_t* guard);
/* Drop native references; the last holder owns unmapping the guard page. */
bool user_fd_guard_put(user_fd_guard_t* guard);
void user_fd_guard_release(user_fd_guard_t* guard);
/* The selected guard is owned by the current fd table. */
void user_fd_guard_select(user_fd_guard_t* guard);
void user_fd_guard_default(user_fd_guard_t* guard);
/* Finish pending table recovery after acquiring the outermost guard. */
void user_fd_guard_set_resume(void (*resume)(void));
/* Protect the entire lifetime of private temporary descriptors. */
void user_fd_lock(void);
void user_fd_unlock(void);
/* Select a new table after fork without releasing the parent's shared lock. */
unsigned user_fd_fork_select(user_fd_guard_t* guard);
void user_fd_guard_unmap(user_fd_guard_t* guard);
void user_fd_guard_child(void);
void user_fd_guard_recover(uint32_t tid);
#else
static inline void user_fd_lock(void) {}
static inline void user_fd_unlock(void) {}
#endif
#endif
