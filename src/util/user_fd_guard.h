/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FD_GUARD_H
#define RVVM_USER_FD_GUARD_H

#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "locking.h"
typedef struct user_fd_mutex { uint32_t owner; } user_fd_mutex_t;
void user_fd_mutex_lock(user_fd_mutex_t* lock);
void user_fd_mutex_unlock(user_fd_mutex_t* lock);
/* Recovery requires proof that the owner has exited. */
void user_fd_mutex_recover(user_fd_mutex_t* lock, uint32_t tid);
typedef struct user_fd_guard {
    user_fd_mutex_t lock;
    uint32_t refs;
} user_fd_guard_t;
user_fd_guard_t* user_fd_guard_create(void);
user_fd_guard_t* user_fd_guard_retain(user_fd_guard_t* guard);
void user_fd_guard_release(user_fd_guard_t* guard);
/* The selected guard is owned by the current fd table. */
void user_fd_guard_select(user_fd_guard_t* guard);
/* Finish pending table recovery after acquiring the outermost guard. */
void user_fd_guard_set_resume(void (*resume)(void));
/* Protect the entire lifetime of private temporary descriptors. */
void user_fd_lock(void);
void user_fd_unlock(void);
/* Called after fork while the calling thread owns the guard. */
void user_fd_fork_reset(void);
void user_fd_guard_child(void);
void user_fd_guard_recover(uint32_t tid);
#else
static inline void user_fd_lock(void) {}
static inline void user_fd_unlock(void) {}
static inline void user_fd_fork_reset(void) {}
#endif
#endif
