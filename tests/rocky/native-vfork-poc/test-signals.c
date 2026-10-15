/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Native VFORK shares writes, but not the child's installed signal actions.
 * A controller thread signals the blocked child while its caller is asleep. */
struct state {
    _Atomic int pid, ready;
    volatile sig_atomic_t inherited, handled, on_altstack;
    char *alt;
    size_t alt_size;
    int pipefd[2], restart, error, result;
};
static struct state *active;
static int publish_pid;

static void inherited(int sig)
{
    (void)sig;
    ++active->inherited;
}

static void handler(int sig)
{
    char local;
    (void)sig;
    ++active->handled;
    uintptr_t sp = (uintptr_t)&local, lo = (uintptr_t)active->alt;
    active->on_altstack = sp >= lo && sp < lo + active->alt_size;
}

static int child(void *arg)
{
    struct state *s = arg;
    if (publish_pid) atomic_store(&s->pid, getpid());
    if (kill(getpid(), SIGUSR1) || s->inherited != 1) _exit(10);
    stack_t stack = { .ss_sp = s->alt, .ss_size = s->alt_size };
    struct sigaction action = { .sa_handler = handler,
        .sa_flags = SA_ONSTACK | (s->restart ? SA_RESTART : 0) };
    sigemptyset(&action.sa_mask);
    if (sigaltstack(&stack, NULL) || sigaction(SIGUSR1, &action, NULL)) _exit(11);
    atomic_store(&s->ready, 1);
    char byte;
    errno = 0;
    s->result = read(s->pipefd[0], &byte, 1);
    s->error = errno;
    _exit(0);
}

static void *controller(void *arg)
{
    struct state *s = arg;
    for (int i = 0; i < 10000 && (!atomic_load(&s->pid) || !atomic_load(&s->ready)); ++i)
        usleep(1000);
    int pid = atomic_load(&s->pid);
    if (!pid || !atomic_load(&s->ready)) return NULL;
    /* Wait until the read is blocked, then deliver the guest handler. */
    usleep(50000);
    kill(pid, SIGUSR1);
    usleep(50000);
    if (write(s->pipefd[1], "x", 1) != 1) abort();
    return NULL;
}

static void run(int restart)
{
    struct state s = { .restart = restart, .alt_size = 128 * 1024 };
    size_t stack_size = 256 * 1024;
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    s.alt = mmap(NULL, s.alt_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED || s.alt == MAP_FAILED || pipe(s.pipefd)) {
        perror("setup"); exit(1);
    }
    active = &s;
    struct sigaction action = { .sa_handler = inherited }, previous;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, &previous)) { perror("sigaction"); exit(1); }
    pthread_t thread;
    if (pthread_create(&thread, NULL, controller, &s)) abort();
    pid_t pid = clone(child, (char *)stack + stack_size,
        CLONE_VM | CLONE_VFORK | (publish_pid ? 0 : CLONE_PARENT_SETTID) | SIGCHLD,
        &s, &s.pid);
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) { perror("clone/wait"); exit(1); }
    pthread_join(thread, NULL);
    struct sigaction after;
    if (sigaction(SIGUSR1, NULL, &after)) abort();
    int ok = WIFEXITED(status) && !WEXITSTATUS(status)
        && s.inherited == 1 && s.handled == 1 && s.on_altstack
        && after.sa_handler == inherited
        && (restart ? s.result == 1 : s.result == -1 && s.error == EINTR);
    printf("%s caught signal restart=%d status=%d inherited=%d handled=%d alt=%d read=%d errno=%d\n",
        ok ? "PASS" : "FAIL", restart, status, s.inherited, s.handled,
        s.on_altstack, s.result, s.error);
    sigaction(SIGUSR1, &previous, NULL);
    close(s.pipefd[0]); close(s.pipefd[1]);
    munmap(stack, stack_size); munmap(s.alt, s.alt_size);
    if (!ok) exit(1);
}

int main(int argc, char** argv)
{
    publish_pid = argc == 2 && !strcmp(argv[1], "--guest-publish");
    if (argc != 1 && !publish_pid) return 2;
    run(0);
    run(1);
    return 0;
}
