/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_VM_BACKING_H
#define RVVM_USER_VM_BACKING_H

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Backings contain guest bytes only. Emulator allocations, locks and TLS stay
 * in the worker's ordinary host address space. A shared guest VM maps the same
 * backing; an ordinary fork needs a separate snapshot of private backings.
 * Descriptor ownership belongs to the caller, including hiding it from guests.
 */
static inline int user_vm_backing_create(size_t size)
{
    if (!size || size > INT64_MAX) { errno = EINVAL; return -1; }
    int fd = syscall(SYS_memfd_create, "rvvm-guest-memory", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)size)
        || fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static inline void* user_vm_backing_map(int fd, void* address, size_t size,
                                      int prot, int flags, off_t offset)
{
    if (flags & (MAP_TYPE | MAP_ANONYMOUS)) { errno = EINVAL; return MAP_FAILED; }
    return mmap(address, size, prot, MAP_SHARED | flags, fd, offset);
}

static inline int user_vm_backing_copy(int source, int target, off_t start, off_t end)
{
    unsigned char buffer[65536];
    while (start < end) {
        size_t count = end - start < (off_t)sizeof(buffer) ? (size_t)(end - start) : sizeof(buffer);
        ssize_t read_count;
        do { read_count = pread(source, buffer, count, start); } while (read_count < 0 && errno == EINTR);
        if (read_count <= 0) { if (!read_count) errno = EIO; return -1; }
        size_t written = 0;
        while (written < (size_t)read_count) {
            ssize_t n = pwrite(target, buffer + written, (size_t)read_count - written, start + written);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { if (!n) errno = EIO; return -1; }
            written += (size_t)n;
        }
        start += read_count;
    }
    return 0;
}

/* The caller must quiesce every writer, including outstanding kernel writes
 * to guest buffers, for the entire snapshot. Copy only allocated extents:
 * reserved heaps may span gigabytes while containing very little data.
 * SEEK_DATA includes shmem pages that have been swapped out, unlike mincore.
 */
static inline int user_vm_backing_snapshot(int source)
{
    struct stat info;
    if (fstat(source, &info)) return -1;
    int target = user_vm_backing_create((size_t)info.st_size);
    if (target < 0) return -1;
    off_t position = 0;
    while (position < info.st_size) {
        off_t start = lseek(source, position, SEEK_DATA);
        if (start < 0) {
            if (errno == ENXIO) break;
            goto fail;
        }
        off_t end = lseek(source, start, SEEK_HOLE);
        if (end < 0) goto fail;
        if (end > info.st_size) end = info.st_size;
        if (end <= start) { errno = EIO; goto fail; }
        if (user_vm_backing_copy(source, target, start, end)) goto fail;
        position = end;
    }
    return target;
fail: {
        int error = errno;
        close(target);
        errno = error;
        return -1;
    }
}

#endif
