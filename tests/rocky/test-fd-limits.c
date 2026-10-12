/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Run unchanged on Linux and under RVVM. Each child owns its irreversible
 * hard-limit changes, so one case cannot make another pass accidentally. */
static void set_limit(rlim_t soft, rlim_t hard)
{
    struct rlimit limit = {soft, hard};
    assert(!setrlimit(RLIMIT_NOFILE, &limit));
}

static void exhausted_open(void)
{
    char path[] = "/tmp/rvvm-fd-limits.XXXXXX";
    int held = mkstemp(path);
    assert(held >= 0 && write(held, "keep", 4) == 4);
    struct rlimit limit;
    assert(!getrlimit(RLIMIT_NOFILE, &limit));
    assert(limit.rlim_max >= 16);
    set_limit(16, limit.rlim_max);
    int fd;
    while ((fd = open("/dev/null", O_RDONLY | O_CLOEXEC)) >= 0) {}
    assert(errno == EMFILE);
    errno = 0;
    assert(open(path, O_WRONLY | O_TRUNC) == -1 && errno == EMFILE);
    char bytes[4];
    assert(pread(held, bytes, sizeof(bytes), 0) == 4);
    assert(!memcmp(bytes, "keep", 4));
    assert(!unlink(path));
}

static void lowered_limit(void)
{
    int fd = open("/dev/null", O_RDONLY);
    assert(fd >= 0);
    struct rlimit limit;
    assert(!getrlimit(RLIMIT_NOFILE, &limit));
    set_limit(0, limit.rlim_max);
    /* Lowering a limit does not invalidate existing descriptors. */
    assert(fcntl(fd, F_GETFD) >= 0);
    errno = 0;
    assert(dup(fd) == -1 && errno == EMFILE);
    errno = 0;
    assert(fcntl(fd, F_DUPFD, 0) == -1 && errno == EINVAL);
    errno = 0;
    assert(dup3(fd, fd + 1, O_CLOEXEC) == -1 && errno == EBADF);
    int pair[2] = {-1, -1};
    errno = 0;
    assert(pipe2(pair, O_CLOEXEC) == -1 && errno == EMFILE);
    assert(pair[0] == -1 && pair[1] == -1);
    set_limit(16, limit.rlim_max);
    int copy = dup(fd);
    assert(copy >= 0 && copy < 16);
    close(copy);
    close(fd);
}

static void fork_inheritance(void)
{
    set_limit(16, 16);
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        struct rlimit limit;
        assert(!getrlimit(RLIMIT_NOFILE, &limit));
        assert(limit.rlim_cur == 16 && limit.rlim_max == 16);
        set_limit(8, 8);
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    struct rlimit limit;
    assert(!getrlimit(RLIMIT_NOFILE, &limit));
    assert(limit.rlim_cur == 16 && limit.rlim_max == 16);
}

static void failed_exec(void)
{
    set_limit(8, 8);
    char* argv[] = {"missing", NULL};
    char* env[] = {NULL};
    errno = 0;
    assert(execve("/rvvm-fd-limits-does-not-exist", argv, env) == -1 && errno == ENOENT);
    struct rlimit limit;
    assert(!getrlimit(RLIMIT_NOFILE, &limit));
    assert(limit.rlim_cur == 8 && limit.rlim_max == 8);
    int fd = open("/dev/null", O_RDONLY);
    assert(fd >= 0 && fd < 8);
    close(fd);
}

static void successful_exec(void)
{
    set_limit(16, 16);
    char* argv[] = {"test-fd-limits", "--after-exec", NULL};
    char* env[] = {NULL};
    execve("/proc/self/exe", argv, env);
    assert(!"execve failed");
}

static void rights_truncation(void)
{
    int sockets[2];
    assert(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets));
    int file = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(file >= 0);
    /* Make exactly two low slots available regardless of inherited fds. */
    struct rlimit saved;
    assert(!getrlimit(RLIMIT_NOFILE, &saved));
    assert(saved.rlim_max >= 16);
    set_limit(16, saved.rlim_max);
    int fd;
    while ((fd = open("/dev/null", O_RDONLY | O_CLOEXEC)) >= 0) {}
    assert(errno == EMFILE);
    assert(!close(14) && !close(15));
    char byte = 0;
    struct iovec io = {&byte, 1};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(3 * sizeof(int))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1,
                         .msg_control = control.bytes, .msg_controllen = sizeof(control)};
    struct cmsghdr* header = CMSG_FIRSTHDR(&msg);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(3 * sizeof(int));
    int files[] = {file, file, file};
    memcpy(CMSG_DATA(header), files, sizeof(files));
    assert(sendmsg(sockets[0], &msg, 0) == 1);
    memset(&control, 0, sizeof(control));
    msg.msg_controllen = sizeof(control);
    assert(recvmsg(sockets[1], &msg, MSG_CMSG_CLOEXEC) == 1);
    assert(msg.msg_flags & MSG_CTRUNC);
    header = CMSG_FIRSTHDR(&msg);
    assert(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS);
    assert(header->cmsg_len == CMSG_LEN(2 * sizeof(int)));
    memcpy(files, CMSG_DATA(header), 2 * sizeof(int));
    for (unsigned i = 0; i < 2; ++i) {
        assert(files[i] >= 0 && files[i] < 16);
        assert(fcntl(files[i], F_GETFD) & FD_CLOEXEC);
        close(files[i]);
    }
}

static void remote_limit(void)
{
    int gate[2];
    assert(!pipe2(gate, O_CLOEXEC));
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        close(gate[1]);
        char byte;
        assert(read(gate[0], &byte, 1) == 1);
        struct rlimit limit;
        assert(!getrlimit(RLIMIT_NOFILE, &limit));
        assert(limit.rlim_cur == 16);
        _exit(0);
    }
    close(gate[0]);
    struct rlimit before, next;
    assert(!prlimit(pid, RLIMIT_NOFILE, NULL, &before));
    next = before;
    next.rlim_cur = 16;
    assert(!prlimit(pid, RLIMIT_NOFILE, &next, NULL));
    assert(write(gate[1], "", 1) == 1);
    close(gate[1]);
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
}

static void open_preserves_locks(void)
{
    char path[] = "/tmp/rvvm-fd-locks.XXXXXX";
    int held = mkstemp(path);
    assert(held >= 0);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    assert(!fcntl(held, F_SETLK, &lock));
    int opened = open(path, O_RDWR | O_CLOEXEC);
    assert(opened >= 0);
    /* Closing any readable temporary duplicate during open would release
     * this process's existing POSIX locks, even though both guest fds live. */
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        lock.l_type = F_WRLCK;
        assert(!fcntl(held, F_GETLK, &lock));
        assert(lock.l_type == F_WRLCK && lock.l_pid == getppid());
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    close(opened);
    close(held);
    assert(!unlink(path));
}

struct blocked_open { const char* path; int gate; };

static void* fifo_reader(void* opaque)
{
    struct blocked_open* request = opaque;
    assert(write(request->gate, "", 1) == 1);
    int fd = open(request->path, O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    char byte;
    assert(read(fd, &byte, 1) == 1);
    close(fd);
    return NULL;
}

static void blocked_open_allows_close(void)
{
    char path[] = "/tmp/rvvm-fd-fifo.XXXXXX";
    int held = mkstemp(path);
    assert(held >= 0);
    assert(!unlink(path) && !mkfifo(path, 0600));
    int gate[2];
    assert(!pipe2(gate, O_CLOEXEC));
    struct blocked_open request = {path, gate[1]};
    pthread_t reader;
    assert(!pthread_create(&reader, NULL, fifo_reader, &request));
    char byte;
    assert(read(gate[0], &byte, 1) == 1);
    /* A table-wide guard around open must not prevent another thread from
     * closing a descriptor or opening the writer which releases the reader. */
    usleep(20000);
    assert(!close(held));
    int writer = open(path, O_WRONLY | O_CLOEXEC);
    assert(writer >= 0 && write(writer, "", 1) == 1);
    assert(!pthread_join(reader, NULL));
    close(writer);
    close(gate[0]);
    close(gate[1]);
    assert(!unlink(path));
}

struct exe_readers {
    struct stat expected;
    atomic_int ready, start;
};
static const char* executable_path;

static void* exe_reader(void* opaque)
{
    struct exe_readers* readers = opaque;
    atomic_fetch_add(&readers->ready, 1);
    while (!atomic_load(&readers->start)) sched_yield();
    for (unsigned i = 0; i < 300; ++i) {
        int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
        struct stat st;
        char magic[4];
        assert(fd >= 0 && !fstat(fd, &st));
        assert(st.st_dev == readers->expected.st_dev && st.st_ino == readers->expected.st_ino);
        assert(read(fd, magic, sizeof(magic)) == sizeof(magic) && !memcmp(magic, "\177ELF", 4));
        assert(!close(fd));
    }
    return NULL;
}

static void concurrent_exe_open(void)
{
    struct rlimit limit;
    assert(!getrlimit(RLIMIT_NOFILE, &limit) && limit.rlim_max > 1024);
    if (limit.rlim_cur <= 1024) set_limit(1025, limit.rlim_max);
    struct exe_readers readers = {0};
    assert(!stat(executable_path, &readers.expected));
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(source >= 0 && source < 64);
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, exe_reader, &readers));
    while (atomic_load(&readers.ready) != 4) sched_yield();
    atomic_store(&readers.start, 1);
    /* RVVM pins the ELF at 1024 or 64. Explicit replacement must relocate
     * that pin without giving a concurrent opener the /dev/null inode. */
    for (unsigned i = 0; i < 512; ++i) {
        assert(dup3(source, 1024, O_CLOEXEC) == 1024);
        assert(dup3(source, 64, O_CLOEXEC) == 64);
    }
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    assert(!close(1024) && !close(64) && !close(source));
}

int main(int argc, char** argv)
{
    executable_path = argv[0];
    if (argc == 2 && !strcmp(argv[1], "--after-exec")) {
        struct rlimit limit;
        assert(!getrlimit(RLIMIT_NOFILE, &limit));
        assert(limit.rlim_cur == 16 && limit.rlim_max == 16);
        return 0;
    }
    void (*cases[])(void) = {exhausted_open, lowered_limit, fork_inheritance,
                            failed_exec, successful_exec, rights_truncation, remote_limit,
                            open_preserves_locks, blocked_open_allows_close, concurrent_exe_open};
    for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) { cases[i](); _exit(0); }
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
    puts("PASS descriptor limits, inheritance, SCM_RIGHTS, locks and blocked open");
    return 0;
}
