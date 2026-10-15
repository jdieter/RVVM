#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static int child(void* unused)
{
    (void)unused;
    return 17;
}

int main(void)
{
    alarm(10);
    size_t length = 128 * 1024;
    char* stack = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    pid_t private = fork();
    assert(private >= 0);
    if (!private) {
        assert(prctl(PR_SET_DUMPABLE, 0) == 0);
        struct rlimit none = {0, 0};
        assert(setrlimit(RLIMIT_NOFILE, &none) == 0);
        int parent_tid = 0, child_tid = 0;
        pid_t pid = clone(child, stack + length, CLONE_VM | CLONE_VFORK | CLONE_PARENT_SETTID
                         | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD,
                         NULL, &parent_tid, NULL, &child_tid);
        if (pid < 0) {
            char message[96];
            int size = snprintf(message, sizeof(message), "nested clone failed: errno=%d\n", errno);
            write(STDERR_FILENO, message, size);
            _exit(1);
        }
        int status;
        assert(parent_tid == pid && !child_tid);
        assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 17);
        _exit(0);
    }
    int status;
    assert(waitpid(private, &status, 0) == private && WIFEXITED(status));
    if (WEXITSTATUS(status)) return WEXITSTATUS(status);
    puts("PASS: nested COW then mixed-TID shared-mm VFORK with dumpability and hard NOFILE zero");
    return 0;
}
