/* SPDX-License-Identifier: GPL-3.0-or-later */
/* An external SIGKILL of an emulator mapping helper (a process whose parent
 * is the shared-mm VFORK child) during mapping calls must not
 * terminate the parent. Afterwards execute permission at the target matches
 * the kernel: a remaining RWX mapping runs, a fresh RW mapping faults.
 * Natively there is no helper and every round completes normally. Usage:
 * test-helper-death [native helper-death-killer path [stop]]
 * With stop, helpers are stopped instead: every round must still finish. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define SIZE ((size_t)256 << 20)
static char stack[256 * 1024];
static atomic_int child_pid, done, helpers_killed, finished, warm, phase;
static atomic_int phase_kills[4], wanted;
static volatile sig_atomic_t fault_signal;
static int stop_mode, last_stopped;
static uintptr_t target;
static sigjmp_buf fault;

#if defined(__riscv)
static const uint32_t code[] = {0x02a00513, 0x00008067};
#elif defined(__aarch64__)
static const uint32_t code[] = {0x52800540, 0xd65f03c0};
#elif defined(__x86_64__)
static const unsigned char code[] = {0xb8, 42, 0, 0, 0, 0xc3};
#endif

static int child(void* unused)
{
    (void)unused;
    atomic_store(&child_pid, getpid());
    for (int i = 0; i < 8; ++i) {
        atomic_store(&phase, 0);
        void* p = mmap((void*)target, SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) _exit(10);
        memcpy(p, code, sizeof(code));
        __builtin___clear_cache((char*)p, (char*)p + sizeof(code));
        /* Populating, write-protecting and freeing many pages keeps each
         * call running long enough for the killer to find a helper. */
        atomic_store(&phase, 1);
        if (madvise(p, SIZE, 23 /* MADV_POPULATE_WRITE */)) _exit(12);
        atomic_store(&phase, 2);
        if (mprotect(p, SIZE, PROT_READ | PROT_EXEC)) _exit(13);
        atomic_store(&phase, 3);
        if (munmap(p, SIZE)) _exit(11);
    }
    _exit(0);
}

/* Polls the child's children list. A helper stopped and then killed after
 * its syscall returned has completed the call but lost its result; one
 * killed earlier has not started it. Both outcomes occur. */
static void* killer(void* unused)
{
    (void)unused;
    /* Create this thread's malloc arena before the target hole is chosen. */
    free(malloc(64));
    atomic_store(&warm, 1);
    char path[96], list[256];
    while (!atomic_load(&finished)) {
        int parent = atomic_load(&done) ? 0 : atomic_load(&child_pid);
        if (!parent) { sched_yield(); continue; }
        snprintf(path, sizeof(path), "/proc/%d/task/%d/children", parent, parent);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        ssize_t n = read(fd, list, sizeof(list) - 1);
        close(fd);
        if (n <= 0) continue;
        list[n] = 0;
        int helper = atoi(list), current = atomic_load(&phase);
        if (helper <= 0 || current != atomic_load(&wanted)) continue;
        if (stop_mode && helper == last_stopped) continue; /* once, as job control would */
        last_stopped = helper;
        if (!stop_mode && (atomic_load(&helpers_killed) & 1)) kill(helper, SIGSTOP);
        if (!kill(helper, stop_mode ? SIGSTOP : SIGKILL)) {
            atomic_fetch_add(&phase_kills[current], 1);
            atomic_fetch_add(&helpers_killed, 1);
        }
    }
    return NULL;
}

static void on_fault(int signo)
{
    fault_signal = signo;
    siglongjmp(fault, 1);
}

/* Returns 1 when code at the target ran, 0 when executing it faulted. */
static int runs(void)
{
    if (sigsetjmp(fault, 1)) return 0;
    return ((int (*)(void))target)() == 42;
}

/* Kernel state at the target: -1 unmapped, else whether it is executable. */
static int kernel_exec(void)
{
    FILE* maps = fopen("/proc/self/maps", "r");
    assert(maps);
    char line[4096], mode[5];
    unsigned long start, end;
    int state = -1;
    while (fgets(line, sizeof(line), maps))
        if (sscanf(line, "%lx-%lx %4s", &start, &end, mode) == 3 && start <= target && target < end)
            state = mode[2] == 'x';
    fclose(maps);
    return state;
}

int main(int argc, char** argv)
{
    alarm(120);
    /* Optional native helper-death-killer also covers munmap/mmap windows. */
    stop_mode = argc == 3 && !strcmp(argv[2], "stop");
    if (argc == 2 || stop_mode) {
        char guest[16], phase_address[32], wanted_address[32];
        snprintf(guest, sizeof(guest), "%d", getpid());
        snprintf(phase_address, sizeof(phase_address), "%lx", (unsigned long)&phase);
        snprintf(wanted_address, sizeof(wanted_address), "%lx", (unsigned long)&wanted);
        pid_t external = fork();
        assert(external >= 0);
        if (!external) {
            execl(argv[1], argv[1], guest, phase_address, wanted_address, stop_mode ? "stop" : NULL, NULL);
            _exit(127);
        }
    }
    struct sigaction action = {.sa_handler = on_fault};
    assert(!sigaction(SIGSEGV, &action, NULL) && !sigaction(SIGBUS, &action, NULL));
    /* Thread stacks must not land in the target hole chosen below. */
    pthread_t thread;
    atomic_store(&done, 1);
    assert(!pthread_create(&thread, NULL, killer, NULL));
    while (!atomic_load(&warm)) sched_yield();
    void* probe = mmap(NULL, SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    assert(probe != MAP_FAILED && !munmap(probe, SIZE));
    target = (uintptr_t)probe;
    int killed_rounds = 0;
    for (int round = 0; round < 16; ++round) {
        atomic_store(&wanted, round % 4);
        atomic_store(&child_pid, 0);
        int before = atomic_load(&helpers_killed);
        atomic_store(&done, 0);
        pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
        assert(pid > 0);
        atomic_store(&done, 1);
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        if (stop_mode) {
            /* Stopped helpers are resumed: the child finishes normally. */
            assert(WIFEXITED(status) && !WEXITSTATUS(status));
        } else if (atomic_load(&helpers_killed) != before
            && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
            /* Contained to the child, as if it had been killed in the call.
             * A helper killed after publishing its result costs nothing. */
            ++killed_rounds;
        } else {
            if (!WIFEXITED(status) || WEXITSTATUS(status))
                fprintf(stderr, "round %d: child status %#x after %d kills\n", round, status,
                        atomic_load(&helpers_killed) - before);
            assert(WIFEXITED(status) && !WEXITSTATUS(status));
        }
        /* Whatever the kernel left at the target, execute permission and
         * mapping bookkeeping must agree with it. */
        int state = kernel_exec();
        if (state >= 0) {
            fault_signal = 0;
            int ran = runs();
            if (state) assert(ran);
            else assert(!ran && fault_signal == SIGSEGV);
        }
        if (munmap((void*)target, SIZE)) abort();
        void* page = mmap((void*)target, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        assert(page == (void*)target);
        memcpy(page, code, sizeof(code));
        __builtin___clear_cache((char*)page, (char*)page + sizeof(code));
        assert(!runs());
        assert(!munmap(page, 4096));
        void* again = mmap((void*)target, SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        assert(again == (void*)target);
        memcpy(again, code, sizeof(code));
        __builtin___clear_cache((char*)again, (char*)again + sizeof(code));
        assert(runs());
        assert(!munmap(again, SIZE));
    }
    atomic_store(&finished, 1);
    assert(!pthread_join(thread, NULL));
    printf("PASS parent survives helper %s; execute permission matches kernel ", stop_mode ? "SIGSTOP" : "SIGKILL");
    printf(
           "(contained rounds=%d; kills during mmap=%d populate=%d mprotect=%d munmap=%d)\n", killed_rounds,
           atomic_load(&phase_kills[0]), atomic_load(&phase_kills[1]),
           atomic_load(&phase_kills[2]), atomic_load(&phase_kills[3]));
}
