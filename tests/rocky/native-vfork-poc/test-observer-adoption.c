#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

struct family { atomic_int descendant, release; };

static int stopped(void* unused)
{
    (void)unused;
    raise(SIGSTOP);
    return 0;
}

static int contains(pid_t pid, const struct stat* marker)
{
    char path[64], line[4096];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* maps = fopen(path, "r");
    assert(maps);
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end, offset, inode;
        unsigned device_major, device_minor;
        char mode[5];
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &start, &end, mode, &offset,
                   &device_major, &device_minor, &inode) == 7
            && inode == marker->st_ino && device_major == major(marker->st_dev)
            && device_minor == minor(marker->st_dev)) found = 1;
    }
    fclose(maps);
    return found;
}

int main(void)
{
    alarm(5);
    assert(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0);
    struct family* family = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(family != MAP_FAILED);
    pid_t intermediate = fork();
    assert(intermediate >= 0);
    if (!intermediate) {
        pid_t descendant = fork();
        assert(descendant >= 0);
        if (!descendant) { raise(SIGSTOP); _exit(0); }
        atomic_store(&family->descendant, descendant);
        while (!atomic_load(&family->release)) sched_yield();
        _exit(0);
    }
    while (!atomic_load(&family->descendant)) sched_yield();
    int marker = memfd_create("snapshot-cookie", MFD_CLOEXEC);
    assert(marker >= 0 && ftruncate(marker, 4096) == 0);
    struct stat identity;
    assert(fstat(marker, &identity) == 0);
    void* mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, marker, 0);
    assert(mapping != MAP_FAILED);
    atomic_store(&family->release, 1);
    int status;
    assert(waitpid(intermediate, &status, 0) == intermediate && WIFEXITED(status));
    pid_t adopted = atomic_load(&family->descendant);
    assert(waitpid(adopted, &status, WUNTRACED) == adopted && WIFSTOPPED(status));
    assert(!contains(adopted, &identity));
    char* stack = mmap(NULL, 128 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    pid_t actual = clone(stopped, stack + 128 * 1024, CLONE_VM | SIGCHLD, NULL);
    assert(actual > 0);
    assert(waitpid(actual, &status, WUNTRACED) == actual && WIFSTOPPED(status));
    assert(contains(actual, &identity));
    assert(!kill(actual, SIGKILL) && !kill(adopted, SIGKILL));
    assert(waitpid(actual, &status, 0) == actual && WIFSIGNALED(status));
    assert(waitpid(adopted, &status, 0) == adopted && WIFSIGNALED(status));
    puts("PASS: fresh marker rejects a newly adopted COW descendant and identifies the stopped same-mm child");
    return 0;
}
