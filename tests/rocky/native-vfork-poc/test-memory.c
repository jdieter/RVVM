/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned char* memory;
static int mode, fd;
static int child(void* unused)
{
    (void)unused;
    if (!mode) {
        if (mprotect((void*)(memory + 8192), 8192, PROT_READ | PROT_WRITE)) _exit(2);
        memory[8192] = 21;
        memory[12288] = 22;
        memory[16384] = 23;
        if (madvise((void*)memory, 4096, MADV_DONTNEED)) _exit(3);
    } else if (mode == 1) {
        memory[0] = 31;
        if (pwrite(fd, "Q", 1, 4096) != 1) _exit(4);
    } else {
        unsigned char value = memory[mode == 2 ? 4096 : 0];
        _exit(value);
    }
    _exit(0);
}
static void launch(void* stack, int expected_signal)
{
    int pid = clone(child, (char*)stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    assert(pid > 0);
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    if (expected_signal) assert(WIFSIGNALED(status) && WTERMSIG(status) == expected_signal);
    else assert(status == 0);
}
int main(void)
{
    alarm(10);
    void* stack = mmap(NULL, 65536, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    memory = mmap(NULL, 32768, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);
    memory[0] = 11;
    assert(!mprotect((void*)(memory + 8192), 4096, PROT_NONE));
    assert(!mprotect((void*)(memory + 12288), 4096, PROT_READ));
    assert(!mprotect((void*)(memory + 16384), 4096, PROT_WRITE));
    launch(stack, 0);
    assert(!mprotect((void*)memory, 32768, 3));
    assert(memory[0] == 0 && memory[8192] == 21 && memory[12288] == 22 && memory[16384] == 23);
    munmap((void*)memory, 32768);
    char name[] = "/tmp/native-vfork-file-XXXXXX";
    fd = mkstemp(name);
    assert(fd >= 0 && !unlink(name) && !ftruncate(fd, 8192));
    memory = mmap(NULL, 8192, 3, MAP_PRIVATE, fd, 0);
    assert(memory != MAP_FAILED);
    mode = 1;
    launch(stack, 0);
    unsigned char value;
    assert(pread(fd, &value, 1, 0) == 1 && value == 0);
    assert(memory[0] == 31 && memory[4096] == 'Q');
    assert(!ftruncate(fd, 4096));
    mode = 2;
    launch(stack, SIGBUS);
    munmap((void*)memory, 8192);
    close(fd);
    memory = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);
    mode = 3;
    launch(stack, SIGSEGV);
    munmap((void*)memory, 4096);
    munmap(stack, 65536);
    puts("PASS partial NONE/RO/W protections, discard, private file COW/cache, SIGBUS/SIGSEGV");
}
