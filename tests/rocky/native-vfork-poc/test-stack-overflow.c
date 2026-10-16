/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A guest that overflows its main stack must get SIGSEGV on its alternate
 * signal stack, as on Linux: the stack grows on demand up to RLIMIT_STACK,
 * read when it overflows, and the fault lies just below the stack VMA, with
 * free space below that, and near the stack pointer in the signal context.
 * gnulib's c-stack and sigsegv modules (diffutils' test-c-stack.sh and
 * test-sigsegv-catch-stackoverflow1/2) recognise an overflow that way: from
 * /proc/self/maps, the fault address must be nearer the stack VMA than the
 * mapping below it.
 *
 * Also checks a second overflow in a row, the main stack's [stack] label,
 * an overflow in a thread (into its libc guard page), a VFORK child growing
 * the shared stack, and the same main-stack checks after exec. */
#define _GNU_SOURCE
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define STACK_LIMIT (8UL << 20)

static __thread sigjmp_buf resume;
static __thread char* alt_stack;
static __thread volatile uintptr_t fault_addr, fault_sp, handler_sp, deepest;
static __thread volatile int caught, fault_code;
static char main_alt_stack[64 * 1024], thread_alt_stack[64 * 1024];

static void on_segv(int sig, siginfo_t* info, void* context)
{
    (void)sig;
    ucontext_t* uc = context;
    char here;
    caught = 1;
    fault_code = info->si_code;
    fault_addr = (uintptr_t)info->si_addr;
#if defined(__riscv)
    fault_sp = uc->uc_mcontext.__gregs[REG_SP];
#elif defined(__x86_64__)
    fault_sp = uc->uc_mcontext.gregs[REG_RSP];
#elif defined(__aarch64__)
    fault_sp = uc->uc_mcontext.sp;
#endif
    handler_sp = (uintptr_t)&here;
    siglongjmp(resume, 1);
}

#pragma GCC diagnostic ignored "-Winfinite-recursion"
static long recurse(long depth)
{
    volatile char pad[4096];
    pad[0] = (char)depth;
    deepest = (uintptr_t)pad;
    return recurse(depth + 1) + pad[0];
}

/* Overflows the current stack, then reports whether the handler ran on this
 * thread's alternate stack with a coherent context. Linux reports a refused
 * stack expansion as SEGV_MAPERR; code 0 accepts any. */
static int overflow(const char* what, int code)
{
    caught = 0;
    deepest = UINTPTR_MAX;
    if (!sigsetjmp(resume, 1)) recurse(0);
    uintptr_t alt_lo = (uintptr_t)alt_stack, alt_hi = alt_lo + sizeof(main_alt_stack);
    int on_alt = handler_sp >= alt_lo && handler_sp < alt_hi;
    printf("%s: caught=%d on_alt=%d code=%d fault=%#lx fault_sp=%#lx deepest=%#lx\n", what, caught,
           on_alt, fault_code, (unsigned long)fault_addr, (unsigned long)fault_sp, (unsigned long)deepest);
    if (!caught || !on_alt) { printf("FAIL %s: overflow not caught on the alternate stack\n", what); return 1; }
    if (code && fault_code != code) { printf("FAIL %s: si_code %d, not %d\n", what, fault_code, code); return 1; }
    /* The faulting access lies in the current frame: below every completed
     * frame, near the stack pointer the handler reports. */
    if (fault_addr >= deepest || fault_sp >= deepest
        || (fault_addr > fault_sp ? fault_addr - fault_sp : fault_sp - fault_addr) > 64 * 1024) {
        printf("FAIL %s: fault address or context stack pointer is not at the overflowing frame\n", what);
        return 1;
    }
    return 0;
}

struct vma { uintptr_t start, end, prev_end; int labelled, labels; };

static int find_vma(uintptr_t addr, struct vma* vma)
{
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) { perror("maps"); return -1; }
    char line[512];
    uintptr_t prev_end = 0;
    int found = -1;
    memset(vma, 0, sizeof(*vma));
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        int labelled = strstr(line, "[stack]") != NULL;
        vma->labels += labelled;
        if (found < 0 && addr >= start && addr < end) {
            vma->start = start; vma->end = end; vma->prev_end = prev_end;
            vma->labelled = labelled;
            found = 0;
        }
        prev_end = end;
    }
    fclose(maps);
    return found;
}

static void dump_maps(uintptr_t from, uintptr_t to)
{
    FILE* maps = fopen("/proc/self/maps", "r");
    char line[512];
    while (maps && fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2 && end >= from && start <= to) fputs(line, stdout);
    }
    if (maps) fclose(maps);
}

static int main_stack(void)
{
    char top;
    alt_stack = main_alt_stack;
    stack_t ss = {.ss_sp = main_alt_stack, .ss_size = sizeof(main_alt_stack)};
    if (sigaltstack(&ss, NULL)) { perror("sigaltstack"); return 1; }
    for (int pass = 1; pass <= 2; ++pass) {
        char what[32];
        snprintf(what, sizeof(what), "main pass %d", pass);
        if (overflow(what, SEGV_MAPERR)) return 1;
        struct vma vma;
        if (find_vma((uintptr_t)&top, &vma)) { puts("FAIL main stack VMA not found"); return 1; }
        printf("%s: stack %#lx-%#lx (%lu KiB), below %#lx, gap %lu KiB, [stack] %d/%d\n", what,
               (unsigned long)vma.start, (unsigned long)vma.end,
               (unsigned long)((vma.end - vma.start) >> 10), (unsigned long)vma.prev_end,
               (unsigned long)((vma.start - vma.prev_end) >> 10), vma.labelled, vma.labels);
        /* gnulib's stackvma heuristic: nearer the stack than the VMA below. */
        if (fault_addr >= vma.start || vma.start - fault_addr > (vma.start - vma.prev_end) / 2) {
            printf("FAIL %s: fault is not just below the stack VMA, with free space below\n", what);
            dump_maps(vma.prev_end, vma.end);
            return 1;
        }
        size_t size = vma.end - vma.start;
        if (size > STACK_LIMIT || size < STACK_LIMIT - 256 * 1024) {
            printf("FAIL %s: stack overflowed at %zu KiB, not at RLIMIT_STACK\n", what, size >> 10);
            return 1;
        }
        if (!vma.labelled || vma.labels != 1) {
            printf("FAIL %s: the stack VMA is not the only one labelled [stack]\n", what);
            return 1;
        }
    }
    return 0;
}

static void* thread_main(void* opaque)
{
    (void)opaque;
    alt_stack = thread_alt_stack;
    stack_t ss = {.ss_sp = thread_alt_stack, .ss_size = sizeof(thread_alt_stack)};
    if (sigaltstack(&ss, NULL)) { perror("sigaltstack"); return (void*)1; }
    /* A frame can skip libc's guard page: either code is right. */
    if (overflow("thread", 0)) return (void*)1;
    pthread_attr_t attr;
    void* base;
    size_t size, guard;
    if (pthread_getattr_np(pthread_self(), &attr)) { puts("FAIL pthread_getattr_np"); return (void*)1; }
    pthread_attr_getstack(&attr, &base, &size);
    pthread_attr_getguardsize(&attr, &guard);
    pthread_attr_destroy(&attr);
    if (fault_addr >= (uintptr_t)base || (uintptr_t)base - fault_addr > guard + 128 * 1024) {
        printf("FAIL thread: fault %#lx is not just below the stack at %p\n",
               (unsigned long)fault_addr, base);
        return (void*)1;
    }
    return NULL;
}

static int thread_stack(void)
{
    pthread_attr_t attr;
    pthread_t thread;
    void* result;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1 << 20);
    if (pthread_create(&thread, &attr, thread_main, NULL)) { puts("FAIL pthread_create"); return 1; }
    pthread_join(thread, &result);
    return result != NULL;
}

static __attribute__((noinline)) long grow(long depth)
{
    volatile char pad[4096];
    pad[0] = (char)depth;
    return depth ? grow(depth - 1) + pad[0] : pad[0];
}

/* A VFORK child runs on the parent's stack, below its frame, and must be
 * able to grow it as far as the parent could. */
static int vfork_stack(void)
{
    int status;
    pid_t pid = vfork();
    if (pid < 0) { perror("vfork"); return 1; }
    if (pid == 0) { grow(1024); _exit(42); }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 42) {
        printf("FAIL vfork child growing the shared stack: status %#x\n", status);
        return 1;
    }
    puts("vfork: child grew the shared stack by 4 MiB");
    return 0;
}

static int exec_stack(const char* self)
{
    int status;
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        execl(self, self, "exec", (char*)NULL);
        perror("execl");
        _exit(127);
    }
    fflush(stdout);
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
        printf("FAIL main stack after exec: status %#x\n", status);
        return 1;
    }
    return 0;
}

int main(int argc, char** argv)
{
    alarm(60);
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct rlimit limit = {STACK_LIMIT, STACK_LIMIT};
    if (setrlimit(RLIMIT_STACK, &limit)) { perror("setrlimit"); return 1; }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = on_segv;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGSEGV, &action, NULL);
    if (argc > 1) return main_stack();
    if (vfork_stack() || main_stack() || thread_stack() || exec_stack("/proc/self/exe")) return 1;
    puts("PASS stack overflows caught on the alternate stack with a coherent context");
    return 0;
}
