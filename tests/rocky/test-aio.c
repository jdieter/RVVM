/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <linux/aio_abi.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct ring {
    uint32_t id, nr, head, tail, magic, compat, incompat, header_length;
};
struct aio_sigset { const uint64_t* mask; size_t size; };
static volatile sig_atomic_t caught;
static void handler(int signal) { (void)signal; caught++; }

static aio_context_t setup(void)
{
    aio_context_t context = 0;
    assert(!syscall(SYS_io_setup, 16, &context));
    struct ring* ring = (void*)(uintptr_t)context;
    assert(ring->magic == 0xa10a10a1 && ring->header_length == sizeof(*ring));
    assert(ring->nr >= 16 && ring->head == ring->tail);
    return context;
}

static void completion(aio_context_t context, struct iocb* request, long expected, int direct)
{
    struct io_event event;
    if (direct) {
        struct ring* ring = (void*)(uintptr_t)context;
        uint32_t head = ring->head;
        for (unsigned tries = 0; head == __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE); tries++) {
            assert(tries < 1000);
            usleep(1000);
        }
        memcpy(&event, (char*)ring + ring->header_length + head * sizeof(event), sizeof(event));
        __atomic_store_n(&ring->head, (head + 1) % ring->nr, __ATOMIC_RELEASE);
    } else {
        struct timespec timeout = {.tv_sec = 2};
        assert(syscall(SYS_io_getevents, context, 1, 1, &event, &timeout) == 1);
    }
    assert(event.data == request->aio_data && event.obj == (uintptr_t)request);
    assert(event.res == expected && !event.res2);
}

static void io_cases(aio_context_t context)
{
    char path[] = "/tmp/rvvm-aio.XXXXXX";
    int fd = mkstemp(path), event = eventfd(0, EFD_NONBLOCK);
    assert(fd >= 0 && event >= 0 && !unlink(path));
    char input[] = "AIO preserves request identity", output[sizeof(input)] = {0};
    struct iocb write = {
        .aio_data = 0x1122334455667788ULL, .aio_lio_opcode = IOCB_CMD_PWRITE,
        .aio_fildes = fd, .aio_buf = (uintptr_t)input, .aio_nbytes = sizeof(input),
        .aio_flags = IOCB_FLAG_RESFD, .aio_resfd = event,
    };
    struct iocb* requests[] = {&write};
    assert(syscall(SYS_io_submit, context, 1, requests) == 1);
    completion(context, &write, sizeof(input), 1);
    uint64_t count;
    assert(read(event, &count, sizeof(count)) == sizeof(count) && count == 1);
    struct iovec vectors[] = {{output, 7}, {output + 7, sizeof(output) - 7}};
    struct iocb read = {
        .aio_data = 33, .aio_lio_opcode = IOCB_CMD_PREADV, .aio_fildes = fd,
        .aio_buf = (uintptr_t)vectors, .aio_nbytes = 2,
    };
    struct iocb invalid = {.aio_lio_opcode = IOCB_CMD_PREAD, .aio_fildes = UINT32_MAX};
    struct iocb* partial[] = {&read, &invalid};
    assert(syscall(SYS_io_submit, context, 2, partial) == 1);
    completion(context, &read, sizeof(input), 0);
    assert(!memcmp(input, output, sizeof(input)));
    const char* private_fd = getenv("RVVM_TEST_PRIVATE_FD");
    if (private_fd) {
        struct iocb hidden = read;
        hidden.aio_fildes = atoi(private_fd);
        struct iocb* denied[] = {&hidden};
        errno = 0;
        assert(syscall(SYS_io_submit, context, 1, denied) == -1 && errno == EBADF);
        struct iocb* hidden_tail[] = {&read, &hidden};
        assert(syscall(SYS_io_submit, context, 2, hidden_tail) == 1);
        completion(context, &read, sizeof(input), 0);
        hidden = read;
        hidden.aio_flags = IOCB_FLAG_RESFD;
        hidden.aio_resfd = atoi(private_fd);
        errno = 0;
        assert(syscall(SYS_io_submit, context, 1, denied) == -1 && errno == EBADF);
    }
    read.aio_lio_opcode = IOCB_CMD_PWRITEV;
    requests[0] = &read;
    assert(syscall(SYS_io_submit, context, 1, requests) == 1);
    completion(context, &read, sizeof(input), 0);
    read.aio_lio_opcode = IOCB_CMD_PREAD;
    read.aio_buf = (uintptr_t)output;
    read.aio_nbytes = sizeof(output);
    assert(syscall(SYS_io_submit, context, 1, requests) == 1);
    completion(context, &read, sizeof(input), 0);
    struct iocb sync = {.aio_data = 44, .aio_lio_opcode = IOCB_CMD_FSYNC, .aio_fildes = fd};
    requests[0] = &sync;
    assert(syscall(SYS_io_submit, context, 1, requests) == 1);
    completion(context, &sync, 0, 0);
    struct iocb dsync = sync;
    dsync.aio_lio_opcode = IOCB_CMD_FDSYNC;
    dsync.aio_data = 45;
    struct iocb* batch[] = {&sync, &dsync};
    assert(syscall(SYS_io_submit, context, 2, batch) == 2);
    struct io_event events[2];
    struct timespec timeout = {.tv_sec = 2};
    assert(syscall(SYS_io_getevents, context, 2, 2, events, &timeout) == 2);
    assert(events[0].obj != events[1].obj);
    for (unsigned i = 0; i < 2; i++) {
        assert(events[i].obj == (uintptr_t)&sync || events[i].obj == (uintptr_t)&dsync);
        assert(!events[i].res && !events[i].res2);
    }
    struct iocb poll = {
        .aio_data = 55, .aio_lio_opcode = IOCB_CMD_POLL, .aio_fildes = event,
        .aio_buf = POLLIN,
    };
    requests[0] = &poll;
    assert(syscall(SYS_io_submit, context, 1, requests) == 1);
    struct io_event unused;
    errno = 0;
    assert(syscall(SYS_io_cancel, context, &poll, &unused) == -1 && errno == EINPROGRESS);
    completion(context, &poll, 0, 0);
    close(event);
    close(fd);
}

static void waits(aio_context_t context)
{
    caught = 0;
    struct io_event event;
    struct timespec zero = {0}, timeout = {.tv_sec = 2};
    assert(!syscall(SYS_io_getevents, context, 0, 1, &event, &zero));
    assert(!syscall(SYS_io_pgetevents, context, 0, 1, &event, &zero, NULL));
    errno = 0;
    assert(syscall(SYS_io_getevents, context, 2, 1, &event, &zero) == -1 && errno == EINVAL);
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_RESTART};
    assert(!sigaction(SIGUSR1, &action, NULL));
    pid_t parent = getpid(), child = fork();
    assert(child >= 0);
    if (!child) {
        assert(syscall(SYS_io_submit, context, 0, NULL) == -1 && errno == EINVAL);
        aio_context_t own = setup();
        assert(!syscall(SYS_io_destroy, own));
        usleep(20000);
        kill(parent, SIGUSR1);
        _exit(0);
    }
    errno = 0;
    assert(syscall(SYS_io_getevents, context, 1, 1, &event, &timeout) == -1 && errno == EINTR);
    assert(caught == 1);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    uint64_t blocked = UINT64_C(1) << (SIGUSR1 - 1), saved, empty = 0, current;
    assert(!syscall(SYS_rt_sigprocmask, SIG_BLOCK, &blocked, &saved, 8));
    assert(!kill(getpid(), SIGUSR1));
    struct aio_sigset mask = {&empty, 8};
    errno = 0;
    assert(syscall(SYS_io_pgetevents, context, 1, 1, &event, &timeout, &mask) == -1 && errno == EINTR);
    assert(caught == 2);
    assert(!syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &current, 8));
    assert(current & blocked);
    assert(!syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved, NULL, 8));
    mask.size = 4;
    errno = 0;
    assert(syscall(SYS_io_pgetevents, context, 0, 1, &event, &zero, &mask) == -1 && errno == EINVAL);
    errno = 0;
    assert(syscall(SYS_io_pgetevents, context, 0, 1, &event, (void*)1, &mask) == -1 && errno == EFAULT);
}

static int shared_child(void* pointer)
{
    aio_context_t parent = *(aio_context_t*)pointer;
    assert(!syscall(SYS_io_submit, parent, 0, NULL));
    aio_context_t own = setup();
    io_cases(own);
    assert(!syscall(SYS_io_destroy, own));
    return 0;
}

static void* threaded_io(void* pointer)
{
    io_cases(*(aio_context_t*)pointer);
    return NULL;
}

int main(void)
{
    aio_context_t context = 1;
    errno = 0;
    assert(syscall(SYS_io_setup, 16, &context) == -1 && errno == EINVAL);
    errno = 0;
    assert(syscall(SYS_io_setup, 16, (void*)1) == -1 && errno == EFAULT);
    context = setup();
    size_t page = sysconf(_SC_PAGESIZE);
    void* readonly = mmap(NULL, page, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(readonly != MAP_FAILED);
    errno = 0;
    assert(syscall(SYS_io_setup, 16, readonly) == -1 && errno == EFAULT);
    assert(!munmap(readonly, page));
    errno = 0;
    assert(syscall(SYS_io_submit, context, -1L, NULL) == -1 && errno == EINVAL);
    errno = 0;
    assert(syscall(SYS_io_submit, context, 1, (void*)1) == -1 && errno == EFAULT);
    errno = 0;
    assert(syscall(SYS_io_cancel, context, (void*)1, NULL) == -1 && errno == EFAULT);
    io_cases(context);
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, threaded_io, &context));
    assert(!pthread_join(thread, NULL));
    waits(context);
    void* stack = mmap(NULL, 128 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack != MAP_FAILED);
    pid_t child = clone(shared_child, (char*)stack + 128 * 1024, CLONE_VM | CLONE_VFORK | SIGCHLD, &context);
    int status;
    assert(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    assert(!munmap(stack, 128 * 1024));
    struct ring* ring = (void*)(uintptr_t)context;
    size_t size = (ring->header_length + ring->nr * sizeof(struct io_event) + page - 1) & ~(page - 1);
    void* next = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(next != MAP_FAILED);
    assert(mremap((void*)(uintptr_t)context, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, next) == next);
    context = (uintptr_t)next;
    io_cases(context);
    waits(context);
    assert(!syscall(SYS_io_destroy, context));
    errno = 0;
    assert(syscall(SYS_io_destroy, context) == -1 && errno == EINVAL);
    puts("PASS Linux AIO submission, ring access, cancellation, signals, fork, vfork and remap");
    return 0;
}
