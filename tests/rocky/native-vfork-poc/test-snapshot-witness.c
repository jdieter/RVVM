#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

/* The observer reads its owning mm, even when the child is nondumpable and
 * the guest cannot allocate an FD. A stopped COW child retains the witness. */
static unsigned shared_kb(int fd, uintptr_t marker)
{
    assert(lseek(fd, 0, SEEK_SET) == 0);
    char input[4096], line[4096];
    size_t used = 0;
    int selected = 0;
    unsigned shared = 0;
    ssize_t count;
    while ((count = read(fd, input, sizeof(input))) > 0) {
        for (ssize_t i = 0; i < count; ++i) {
            assert(used + 1 < sizeof(line));
            if (input[i] != '\n') { line[used++] = input[i]; continue; }
            line[used] = 0;
            uintptr_t start, end;
            unsigned value;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2)
                selected = start <= marker && marker < end;
            else if (selected && (sscanf(line, "Shared_Dirty: %u kB", &value) == 1
                                  || sscanf(line, "Shared_Clean: %u kB", &value) == 1))
                shared += value;
            used = 0;
        }
    }
    assert(count == 0);
    return shared;
}

int main(void)
{
    alarm(5);
    const size_t page = sysconf(_SC_PAGESIZE);
    char* region = mmap(NULL, 3 * page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(region != MAP_FAILED);
    char* marker = region + page;
    assert(mprotect(marker, page, PROT_READ | PROT_WRITE) == 0);
    assert(madvise(marker, page, MADV_NOHUGEPAGE) == 0);
    *marker = 1;
    assert(mprotect(marker, page, PROT_READ) == 0);
    int maps = open("/proc/self/smaps", O_RDONLY | O_CLOEXEC);
    assert(maps >= 0);
    assert(shared_kb(maps, (uintptr_t)marker) == 0);
    assert(prctl(PR_SET_DUMPABLE, 0) == 0);
    struct rlimit none = {0, 0};
    assert(setrlimit(RLIMIT_NOFILE, &none) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        raise(SIGSTOP);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    unsigned shared = shared_kb(maps, (uintptr_t)marker);
    assert(shared == page / 1024);
    assert(kill(child, SIGKILL) == 0);
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    assert(shared_kb(maps, (uintptr_t)marker) == 0);
    close(maps);
    munmap(region, 3 * page);
    puts("PASS: stopped COW snapshot visible through pinned own smaps with dumpability and NOFILE zero");
    return 0;
}
