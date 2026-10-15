/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/mount.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const long calls[][6] = {
    {SYS_acct, 1}, {SYS_swapon, 1}, {SYS_swapoff, 1}, {SYS_pivot_root, 1, 1},
    {SYS_setns, -1}, {SYS_open_tree, -1, 1, UINT_MAX},
    {SYS_move_mount, -1, 1, -1, 1, UINT_MAX}, {SYS_fsconfig, -1, UINT_MAX},
    {SYS_fsmount, -1, UINT_MAX}, {SYS_fspick, -1, 1, UINT_MAX},
    {SYS_keyctl, UINT_MAX}, {SYS_quotactl, 0, 1}, {SYS_quotactl_fd, -1},
};
static char stack[128 * 1024];
static int expected[sizeof(calls) / sizeof(*calls) + 1];
static void errors(int* result)
{
    for (unsigned i = 0; i < sizeof(calls) / sizeof(*calls); ++i) {
        const long* a = calls[i];
        assert(syscall(a[0], a[1], a[2], a[3], a[4], a[5]) == -1);
        result[i] = errno;
    }
    struct mount_attr attr = {0};
    assert(syscall(SYS_mount_setattr, -1, "", 0, &attr, sizeof(attr)) == -1);
    result[sizeof(calls) / sizeof(*calls)] = errno;
}
static int child(void* unused)
{
    (void)unused;
    int got[sizeof(expected) / sizeof(*expected)];
    errors(got);
    assert(!memcmp(expected, got, sizeof(got)));
    _exit(0);
}
int main(void)
{
    alarm(10);
    errors(expected);
    for (unsigned shared = 0; shared < 2; ++shared) {
        pid_t pid = clone(child, stack + sizeof(stack),
            SIGCHLD | (shared ? CLONE_VM | CLONE_VFORK : 0), NULL);
        int status;
        assert(pid > 0 && waitpid(pid, &status, 0) == pid);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    for (unsigned i = 0; i < sizeof(expected) / sizeof(*expected); ++i) printf("%d ", expected[i]);
    puts("PASS host error ordering in ordinary/shared children");
}
