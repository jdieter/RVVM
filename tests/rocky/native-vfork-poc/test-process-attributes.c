/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char stack[128 * 1024];
static volatile int failure;
static pid_t child_pid, child_group;
static cpu_set_t original_affinity, child_affinity;

static int child(void* unused)
{
    (void)unused;
    struct rlimit limit;
    struct timespec resolution;
    struct rusage usage;
    uid_t r, e, s;
    gid_t gr, ge, gs;
    char name[16];
    struct sched_param scheduling = {.sched_priority = 0};
    cpu_set_t observed;
    child_pid = getpid();
    if (setpgid(0, 0) || (child_group = getpgid(0)) != child_pid) goto fail;
    if (syscall(SYS_getresuid, &r, &e, &s) || r != getuid() || e != geteuid()) goto fail;
    if (syscall(SYS_getresgid, &gr, &ge, &gs) || gr != getgid() || ge != getegid()) goto fail;
    if (syscall(SYS_setresuid, r, e, s) || syscall(SYS_setresgid, gr, ge, gs)) goto fail;
    if (syscall(SYS_getgroups, 0, NULL) < 0) goto fail;
    if (getrlimit(RLIMIT_NOFILE, &limit) || setrlimit(RLIMIT_NOFILE, &limit)) goto fail;
    if (getrusage(RUSAGE_SELF, &usage) || clock_getres(CLOCK_MONOTONIC, &resolution)) goto fail;
    if (prctl(PR_SET_NAME, "vfork-attribute") || prctl(PR_GET_NAME, name)
        || strcmp(name, "vfork-attribute")) goto fail;
    if (sched_setaffinity(0, sizeof(child_affinity), &child_affinity)
        || sched_getaffinity(0, sizeof(observed), &observed)
        || !CPU_EQUAL(&observed, &child_affinity)
        || sched_setscheduler(0, SCHED_OTHER, &scheduling)
        || sched_setparam(0, &scheduling) || sched_getparam(0, &scheduling)
        || sched_getscheduler(0) != SCHED_OTHER || scheduling.sched_priority
        || sched_get_priority_min(SCHED_OTHER) || sched_get_priority_max(SCHED_OTHER)
        || sched_yield() || setpriority(PRIO_PROCESS, 0, 19) || getpriority(PRIO_PROCESS, 0) != 19) goto fail;
    umask(077);
    _exit(0);
fail:
    failure = errno ? errno : EIO;
    _exit(117);
}

int main(void)
{
    pid_t group = getpgid(0);
    mode_t old_mask = umask(022);
    char before[16], after[16];
    int priority = getpriority(PRIO_PROCESS, 0);
    if (sched_getaffinity(0, sizeof(original_affinity), &original_affinity)) return 2;
    CPU_ZERO(&child_affinity);
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu)
        if (CPU_ISSET(cpu, &original_affinity)) { CPU_SET(cpu, &child_affinity); break; }
    if (prctl(PR_GET_NAME, before)) return 2;
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status = 0;
    cpu_set_t observed;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || status || failure
        || child_pid != pid || child_group != pid || getpgid(0) != group
        || umask(old_mask) != 022 || prctl(PR_GET_NAME, after) || strcmp(before, after)
        || getpriority(PRIO_PROCESS, 0) != priority
        || sched_getaffinity(0, sizeof(observed), &observed) || !CPU_EQUAL(&observed, &original_affinity)) {
        fprintf(stderr, "FAIL attributes status=%d errno=%d pid=%d/%d group=%d\n",
                status, failure, pid, child_pid, child_group);
        return 1;
    }
    puts("PASS private child process group, credentials, limits, clocks, name, umask and scheduling");
    return 0;
}
