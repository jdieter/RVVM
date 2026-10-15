/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int uffd;
static size_t page;
static void *source;
static atomic_int stop;
static unsigned faults, forks;
static void fail(const char *operation) { perror(operation); _exit(1); }
static void *handler(void *unused)
{
    (void)unused;
    struct pollfd fds[2] = {{.fd = uffd, .events = POLLIN}, {.fd = -1, .events = POLLIN}};
    while (!atomic_load(&stop)) {
        int result = poll(fds, 2, 20);
        if (result < 0) { if (errno == EINTR) continue; fail("poll"); }
        for (unsigned i = 0; i < 2; i++) {
            if (!(fds[i].revents & POLLIN)) continue;
            struct uffd_msg message;
            if (read(fds[i].fd, &message, sizeof(message)) != sizeof(message)) fail("uffd read");
            if (message.event == UFFD_EVENT_FORK) {
                fds[1].fd = message.arg.fork.ufd;
                forks++;
            } else if (message.event == UFFD_EVENT_PAGEFAULT) {
                struct uffdio_copy copy = {.dst = message.arg.pagefault.address & ~(page - 1),
                                          .src = (uintptr_t)source, .len = page};
                if (ioctl(fds[i].fd, UFFDIO_COPY, &copy)) fail("UFFDIO_COPY");
                faults++;
            } else { fprintf(stderr, "unexpected uffd event %u\n", message.event); _exit(1); }
        }
    }
    if (fds[1].fd >= 0) close(fds[1].fd);
    return NULL;
}
int main(void)
{
    page = sysconf(_SC_PAGESIZE);
    uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) fail("userfaultfd (kernel-fault capable)");
    uint64_t required = UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_EVENT_FORK;
    struct uffdio_api api = {.api = UFFD_API, .features = required};
    if (ioctl(uffd, UFFDIO_API, &api)) fail("UFFDIO_API");
    if ((api.features & required) != required) { fputs("required features absent\n", stderr); return 1; }
    int backing = syscall(SYS_memfd_create, "rvvm-uffd-capability-probe", MFD_CLOEXEC);
    if (backing < 0 || ftruncate(backing, page * 2)) fail("memfd");
    unsigned char *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_SHARED, backing, 0);
    if (memory == MAP_FAILED) fail("mmap");
    struct uffdio_register registration = {.range = {.start = (uintptr_t)memory, .len = page * 2},
                                           .mode = UFFDIO_REGISTER_MODE_MISSING};
    if (ioctl(uffd, UFFDIO_REGISTER, &registration)) fail("UFFDIO_REGISTER shared missing");
    if (!(registration.ioctls & (1ULL << _UFFDIO_COPY))
        || !(registration.ioctls & (1ULL << _UFFDIO_WAKE))) {
        fputs("registered COPY/WAKE unavailable\n", stderr); return 1;
    }
    if (posix_memalign(&source, page, page)) return 1;
    memset(source, 0xa5, page);
    pthread_t thread;
    if (pthread_create(&thread, NULL, handler, NULL)) return 1;
    int pipefd[2];
    if (pipe(pipefd)) fail("pipe");
    if (write(pipefd[1], "KK", 2) != 2) fail("write");
    /* Both faults originate from the kernel copying read() data to userspace. */
    if (read(pipefd[0], memory, 1) != 1 || memory[0] != 'K' || memory[1] != 0xa5) return 1;
    pid_t child = fork();
    if (child < 0) fail("fork");
    if (!child) {
        if (read(pipefd[0], memory + page, 1) != 1) _exit(1);
        _exit(memory[page] == 'K' && memory[page + 1] == 0xa5 ? 0 : 1);
    }
    int status;
    if (waitpid(child, &status, 0) != child || status) return 1;
    atomic_store(&stop, 1);
    pthread_join(thread, NULL);
    if (faults != 2 || forks != 1 || memory[page] != 'K') return 1;
    printf("PASS kernel-write shmem faults in parent and child; faults=%u forks=%u features=0x%llx register_ioctls=0x%llx\n",
           faults, forks, (unsigned long long)api.features, (unsigned long long)registration.ioctls);
    return 0;
}
