/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_MALLOC_H
#define RVVM_USER_MALLOC_H

/* rvvm_user replaces libc's malloc family (rvvm_user_malloc.c). libc's own
 * fork() runs these through pthread_atfork. A raw fork takes the lock before
 * its clone and calls one of the others after it. */
void user_malloc_fork_lock(void);
void user_malloc_fork_unlock(void);
void user_malloc_fork_child(void);

#endif
