/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest execute permission must not depend on host EXEC, which the host may
 * refuse: prctl MDWE (systemd MemoryDenyWriteExecute) and SELinux execmem
 * with EACCES, a noexec mount with EPERM. Under RVVM, an anonymous RWX
 * mapping, RW made RX, an RX mapping moved by mremap and, given a directory
 * on a noexec mount, a READ|EXEC file mapping and a READ file mapping made
 * READ|EXEC all run code; RX made READ faults. Each round runs in the
 * process, in a shared-mm VFORK child (through the mapping helper), in a
 * private VFORK child and in a fork child. After a shared-mm round, the
 * parent runs the child's mappings too.
 *
 * Usage: test-exec-refused [noexec directory]
 * Run the emulator under tests/rocky/mdwe-exec to refuse EXEC gains, with
 * RVVM_NOJIT=1 until fork children stop sharing the JIT cache there (see
 * tests/rocky/README.md). RVVM deliberately accepts noexec files, as before
 * host EXEC was requested; natively, and on a RISC-V kernel, they fail with
 * EPERM and EACCES. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__riscv)
static const uint32_t instructions[] = {0x02a00513, 0x00008067};
#elif defined(__x86_64__)
static const unsigned char instructions[] = {0xb8, 42, 0, 0, 0, 0xc3};
#elif defined(__aarch64__)
static const uint32_t instructions[] = {0x52800540, 0xd65f03c0};
#else
#error Unsupported native test architecture
#endif

static char stack[128 * 1024];
static size_t page;
static int file = -1;
static void *rwx, *moved, *readonly, *file_rx, *file_protected;

static void flush(void* address)
{
#if defined(__riscv)
    assert(!syscall(SYS_riscv_flush_icache, address, (char*)address + sizeof(instructions), 0));
#endif
    __builtin___clear_cache(address, (char*)address + sizeof(instructions));
}

static void* code_map(int prot)
{
    void* address = mmap(NULL, page, PROT_READ | PROT_WRITE | (prot & PROT_EXEC),
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) return NULL;
    memcpy(address, instructions, sizeof(instructions));
    flush(address);
    return address;
}

static int run(void* address)
{
    return ((int (*)(void))address)();
}

/* Returns 0, or the number of the step that failed. */
static int exercise(void)
{
    rwx = code_map(PROT_EXEC);
    if (!rwx) return 1;
    if (run(rwx) != 42) return 2;
    void* rx = code_map(0);
    if (!rx || mprotect(rx, page, PROT_READ | PROT_EXEC)) return 3;
    if (run(rx) != 42) return 4;
    void* target = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) return 5;
    moved = mremap(rx, page, page, MREMAP_MAYMOVE | MREMAP_FIXED, target);
    if (moved != target) return 5;
    if (run(moved) != 42) return 6;
    readonly = code_map(0);
    if (!readonly || mprotect(readonly, page, PROT_READ | PROT_EXEC)) return 7;
    if (run(readonly) != 42) return 8;
    if (mprotect(readonly, page, PROT_READ)) return 9;
    if (file < 0) return 0;
    file_rx = mmap(NULL, page, PROT_READ | PROT_EXEC, MAP_PRIVATE, file, 0);
    file_protected = mmap(NULL, page, PROT_READ, MAP_PRIVATE, file, 0);
    if (file_protected == MAP_FAILED) return 10;
#if defined(__riscv)
    if (file_rx == MAP_FAILED) return 11;
    if (run(file_rx) != 42) return 12;
    if (mprotect(file_protected, page, PROT_READ | PROT_EXEC)) return 13;
    if (run(file_protected) != 42) return 14;
#else
    if (file_rx != MAP_FAILED || errno != EPERM) return 11;
    if (!mprotect(file_protected, page, PROT_READ | PROT_EXEC) || errno != EACCES) return 13;
#endif
    return 0;
}

static int child(void* unused)
{
    (void)unused;
    _exit(exercise());
}

/* Executing it in a fork child must fault. */
static void faults(void* address)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        signal(SIGSEGV, SIG_DFL);
        _exit(run(address) == 42 ? 1 : 2);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
}

/* The calling process's execute permission matches the round's mappings. */
static void check(void)
{
    assert(run(rwx) == 42 && run(moved) == 42);
    faults(readonly);
#if defined(__riscv)
    if (file >= 0) assert(run(file_rx) == 42 && run(file_protected) == 42);
#endif
}

static void release(void)
{
    void* mappings[] = {rwx, moved, readonly, file_rx, file_protected};
    for (unsigned i = 0; i < sizeof(mappings) / sizeof(*mappings); ++i)
        if (mappings[i] && mappings[i] != MAP_FAILED) assert(!munmap(mappings[i], page));
    rwx = moved = readonly = file_rx = file_protected = NULL;
}

int main(int argc, char** argv)
{
    assert(argc <= 2);
    alarm(60);
    page = sysconf(_SC_PAGESIZE);
    char path[4096];
    if (argc == 2) {
        struct statvfs info;
        assert(!statvfs(argv[1], &info));
        if (!(info.f_flag & ST_NOEXEC)) {
            fprintf(stderr, "%s is not on a noexec mount\n", argv[1]);
            return 2;
        }
        snprintf(path, sizeof(path), "%s/test-exec-refused.XXXXXX", argv[1]);
        file = mkstemp(path);
        assert(file >= 0 && !unlink(path));
        assert(write(file, instructions, sizeof(instructions)) == sizeof(instructions));
        assert(!ftruncate(file, page));
    }
    int step = exercise();
    if (step) fprintf(stderr, "process: step %d failed (errno %d)\n", step, errno);
    assert(!step);
    check();
    release();
    const int modes[] = {CLONE_VM | CLONE_VFORK, CLONE_VFORK, 0};
    for (unsigned i = 0; i < sizeof(modes) / sizeof(*modes); ++i) {
        pid_t pid = clone(child, stack + sizeof(stack), SIGCHLD | modes[i], NULL);
        int status;
        assert(pid > 0 && waitpid(pid, &status, 0) == pid);
        if (!WIFEXITED(status) || WEXITSTATUS(status))
            fprintf(stderr, "clone flags %#x: status %#x\n", modes[i], status);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
        if (modes[i] & CLONE_VM) {
            check();
            release();
        }
    }
    printf("PASS guest execute permission without host EXEC%s\n",
           file >= 0 ? ", including noexec files" : "; no noexec directory given");
    return 0;
}
