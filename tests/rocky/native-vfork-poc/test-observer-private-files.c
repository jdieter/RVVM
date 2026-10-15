#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct request {
    atomic_int ready, command, result;
    pid_t caller, child;
    int parent_tid, child_tid;
    const char* proc;
    int drop_credentials;
};

static void wake(atomic_int* word, int value)
{
    atomic_store(word, value);
    syscall(SYS_futex, word, 1, INT_MAX, NULL, NULL, 0);
}

static void await(atomic_int* word)
{
    while (!atomic_load(word)) syscall(SYS_futex, word, 0, 0, NULL, NULL, 0);
}

static int observe(void* opaque)
{
    struct request* request = opaque;
    if (request->drop_credentials)
        assert(!setgroups(0, NULL) && !setgid(135) && !setuid(993));
    char path[96], buffer[4096];
    int proc = open(request->proc, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (proc < 0) { wake(&request->ready, -errno); return 1; }
    snprintf(path, sizeof(path), "%d/task/%d/children", request->caller, request->caller);
    int children = openat(proc, path, O_RDONLY | O_CLOEXEC);
    if (children < 0) { wake(&request->ready, -errno); return 1; }
    wake(&request->ready, 1);
    await(&request->command);
    ssize_t size = pread(children, buffer, sizeof(buffer) - 1, 0);
    int found = 0;
    if (size >= 0) {
        buffer[size] = 0;
        for (char* at = buffer; *at;) {
            char* end;
            long pid = strtol(at, &end, 10);
            if (at == end) break;
            if (pid == request->child) found = 1;
            at = end;
        }
    }
    snprintf(path, sizeof(path), "%d/maps", request->child);
    int maps = openat(proc, path, O_RDONLY | O_CLOEXEC);
    int result = maps < 0 ? -errno : !found ? -ESRCH : read(maps, buffer, sizeof(buffer)) > 0 ? 1 : -EIO;
    if (maps >= 0) close(maps);
    close(children);
    close(proc);
    wake(&request->result, result);
    return result == 1 ? 0 : 1;
}

static int stopped_child(void* unused)
{
    (void)unused;
    raise(SIGSTOP);
    return 0;
}

int main(int argc, char** argv)
{
    alarm(5);
    assert(argc == 1 || argc == 3);
    struct request request = {.caller = getpid(), .proc = argc == 3 ? argv[1] : "/proc",
                              .drop_credentials = argc == 3};
    size_t stack_size = 128 * 1024;
    char* observer_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char* child_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(observer_stack != MAP_FAILED && child_stack != MAP_FAILED);
    pid_t observer = clone(observe, observer_stack + stack_size, CLONE_VM | SIGCHLD, &request);
    assert(observer > 0);
    await(&request.ready);
    assert(atomic_load(&request.ready) == 1);
    if (argc == 3) {
        assert(!umount2(argv[1], MNT_DETACH));
        assert(!chroot(argv[2]) && !chdir("/"));
        assert(!setgroups(0, NULL) && !setgid(135) && !setuid(993));
    }
    assert(prctl(PR_SET_DUMPABLE, 0) == 0);
    struct rlimit none = {0, 0};
    assert(setrlimit(RLIMIT_NOFILE, &none) == 0);
    request.child = clone(stopped_child, child_stack + stack_size,
                          CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD,
                          NULL, &request.parent_tid, NULL, &request.child_tid);
    assert(request.child > 0 && request.parent_tid == request.child);
    int status;
    assert(waitpid(request.child, &status, WUNTRACED) == request.child && WIFSTOPPED(status));
    assert(request.child_tid == request.child);
    wake(&request.command, 1);
    await(&request.result);
    assert(atomic_load(&request.result) == 1);
    assert(waitpid(observer, &status, 0) == observer && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(kill(request.child, SIGKILL) == 0);
    assert(waitpid(request.child, &status, 0) == request.child && WIFSIGNALED(status));
    assert(!request.child_tid);
    puts("PASS: private observer reads caller children and same-mm child maps with dumpability and guest NOFILE zero; actual mixed TID stores preserved");
    return 0;
}
