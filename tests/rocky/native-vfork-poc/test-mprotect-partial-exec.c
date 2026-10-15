/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static unsigned char* code;
static size_t page;
static int kernel_only;

static int kernel_exec(const void* address)
{
    FILE* maps = fopen("/proc/self/maps", "r");
    assert(maps);
    char line[4096], mode[5];
    unsigned long start, end;
    int executable = -1;
    while (fgets(line, sizeof(line), maps))
        if (sscanf(line, "%lx-%lx %4s", &start, &end, mode) == 3
            && start <= (uintptr_t)address && (uintptr_t)address < end)
            executable = mode[2] == 'x';
    fclose(maps);
    assert(executable >= 0);
    return executable;
}
static int child(void* unused)
{
    (void)unused;
    assert(mprotect(code, 3 * page, PROT_READ) == -1 && errno == ENOMEM);
    if (kernel_only) {
        assert(!kernel_exec(code) && kernel_exec(code + 2 * page));
        _exit(17);
    }
    /* Linux has already removed execute permission before finding the hole. */
    _exit(((int (*)(void))code)() == 42 ? 97 : 98);
}
int main(int argc, char** argv)
{
    assert(argc == 1 || (argc == 2 && !strcmp(argv[1], "--kernel-only")));
    kernel_only = argc == 2;
    alarm(10);
    page = sysconf(_SC_PAGESIZE);
#if defined(__riscv)
    const uint32_t instructions[] = {0x02a00513, 0x00008067};
#elif defined(__aarch64__)
    const uint32_t instructions[] = {0x52800540, 0xd65f03c0};
#elif defined(__x86_64__)
    const unsigned char instructions[] = {0xb8, 42, 0, 0, 0, 0xc3};
#else
#error "Need a native return-42 sequence"
#endif
    const int modes[] = {0, CLONE_VM | CLONE_VFORK, CLONE_VFORK};
    for (unsigned i = 0; i < sizeof(modes) / sizeof(*modes); ++i) {
        code = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(code != MAP_FAILED);
        memcpy(code, instructions, sizeof(instructions));
        __builtin___clear_cache((char*)code, (char*)code + sizeof(instructions));
        assert(!mprotect(code, 3 * page, PROT_READ | PROT_EXEC));
        assert(((int (*)(void))code)() == 42 && !munmap(code + page, page));
        pid_t pid = clone(child, stack + sizeof(stack), SIGCHLD | modes[i], NULL);
        int status;
        assert(pid > 0 && waitpid(pid, &status, 0) == pid);
        if (kernel_only) assert(WIFEXITED(status) && WEXITSTATUS(status) == 17);
        else assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
        assert(!munmap(code, 3 * page));
    }
    puts(kernel_only ? "PASS kernel maps retain partial execute changes"
                     : "PASS failed mprotect retains partial execute changes");
}
