/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_int ready;
static void check_random(int filtered)
{
    char byte;
    errno = 0;
    long ret = syscall(SYS_getrandom, &byte, 1, 0);
    assert(filtered ? ret == -1 && errno == ENOSYS : ret == 1);
}
static void* original_thread(void* unused)
{
    (void)unused;
    while (!atomic_load(&ready)) sched_yield();
    check_random(0);
    return NULL;
}
static void* inherited_thread(void* unused)
{
    (void)unused;
    check_random(1);
    assert(prctl(PR_GET_SECCOMP) == SECCOMP_MODE_FILTER);
    return NULL;
}
static void install(int via_prctl, int nr, int error)
{
    struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_RISCV64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EINVAL),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | error),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {sizeof(insns) / sizeof(insns[0]), insns};
    assert(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    assert(!(via_prctl ? prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
                      : syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)));
    memset(insns, 0, sizeof(insns)); // The runtime must own its policy snapshot.
}
int main(int argc, char** argv)
{
    if (argc > 1) {
        extern char** environ;
        check_random(1);
        errno = 0;
        assert(syscall(SYS_getppid) == -1 && errno == EACCES);
        for (char** env = environ; *env; env++) assert(strncmp(*env, "RVVM_USER_SECCOMP", 17));
        return 0;
    }
    pthread_t original, inherited;
    check_random(0);
    assert(!pthread_create(&original, NULL, original_thread, NULL));
    install(0, SYS_getrandom, ENOSYS);
    check_random(1);
    atomic_store(&ready, 1);
    assert(!pthread_join(original, NULL));
    assert(!pthread_create(&inherited, NULL, inherited_thread, NULL));
    assert(!pthread_join(inherited, NULL));
    install(1, SYS_getppid, EACCES);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        check_random(1);
        /* A failed exec must leave the filters and environment intact. */
        char* args[] = {argv[0], "--child", NULL};
        execve("/nonexistent-seccomp-test", args, NULL);
        assert(errno == ENOENT);
        check_random(1);
        execve(argv[0], args, NULL);
        _exit(90);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}
