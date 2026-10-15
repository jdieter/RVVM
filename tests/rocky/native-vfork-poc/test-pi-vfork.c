/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static int lock, owner;
static int child(void* unused)
{
    (void)unused;
    if (gettid() == owner || (lock & FUTEX_TID_MASK) != owner) _exit(101);
    if (syscall(SYS_futex, &lock, FUTEX_TRYLOCK_PI_PRIVATE, 0, NULL, NULL, 0) != -1
        || errno != EAGAIN || (lock & FUTEX_TID_MASK) != owner) _exit(102);
    _exit(0);
}
int main(void)
{
    alarm(20);
    owner = gettid();
    assert(!syscall(SYS_futex, &lock, FUTEX_LOCK_PI_PRIVATE, 0, NULL, NULL, 0));
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && !status);
    assert((lock & FUTEX_TID_MASK) == owner);
    assert(!syscall(SYS_futex, &lock, FUTEX_UNLOCK_PI_PRIVATE, 0, NULL, NULL, 0));
    assert(!syscall(SYS_futex, &lock, FUTEX_LOCK_PI_PRIVATE, 0, NULL, NULL, 0));
    assert(!syscall(SYS_futex, &lock, FUTEX_UNLOCK_PI_PRIVATE, 0, NULL, NULL, 0));
    puts("PASS native shared-mm vfork retains parent's PI futex ownership and key");
}
