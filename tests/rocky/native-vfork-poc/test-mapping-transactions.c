/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];
static unsigned char *old, *created;
static unsigned char* file_map;
static char file_path[] = "/tmp/native-vfork-map-XXXXXX";
static size_t page;
static volatile int failure;

static int child(void* unused)
{
    (void)unused;
    created = mmap(NULL, page * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (created == MAP_FAILED) goto fail;
    created[0] = 37;
    void* moved = mremap(created, page * 4, page * 8, MREMAP_MAYMOVE);
    if (moved == MAP_FAILED) goto fail;
    created = moved;
    if (created[0] != 37 || mprotect(created + page, page, PROT_NONE)
        || mprotect(created + page, page, PROT_READ | PROT_WRITE)) goto fail;
    int fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, created + page, 1) != 1) goto fail;
    close(fd);
    created[page * 7] = 99;
    if (madvise(created + page * 7, page, MADV_DONTNEED) || created[page * 7]) goto fail;
    uintptr_t before = syscall(SYS_brk, 0);
    if (syscall(SYS_brk, before + page) != before + page) goto fail;
    *(unsigned char*)before = 61;
    if (syscall(SYS_brk, before) != before) goto fail;
    int file = open(file_path, O_RDWR | O_CLOEXEC);
    if (file < 0) goto fail;
    file_map = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
    if (file_map == MAP_FAILED) goto fail;
    file_map[0] = 77;
    unsigned char replacement = 22;
    if (pwrite(file, &replacement, 1, 0) != 1 || file_map[0] != 77) goto fail;
    close(file);
    if (munmap(old, page)) goto fail;
    _exit(0);
fail:
    failure = errno ? errno : EIO;
    _exit(117);
}

int main(void)
{
    page = sysconf(_SC_PAGESIZE);
    old = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (old == MAP_FAILED) return 2;
    int file = mkstemp(file_path);
    if (file < 0 || ftruncate(file, page)) return 2;
    close(file);
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || status || failure
        || !created || created == MAP_FAILED || created[0] != 37 || created[page * 7]
        || !file_map || file_map == MAP_FAILED || file_map[0] != 77) {
        fprintf(stderr, "FAIL mapping transaction status=%d errno=%d\n", status, failure);
        return 1;
    }
    void* reclaimed = mmap(old, page, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (reclaimed != old || munmap(reclaimed, page) || munmap(created, page * 8)) return 1;
    unsigned char value;
    file = open(file_path, O_RDONLY);
    if (file < 0 || read(file, &value, 1) != 1 || value != 22 || munmap(file_map, page)) return 1;
    close(file);
    unlink(file_path);
    puts("PASS child mmap/remap/protection/discard/unmap/brk and private-file COW shared with parent");
    return 0;
}
