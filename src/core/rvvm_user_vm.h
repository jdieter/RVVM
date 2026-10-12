/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_VM_H
#define RVVM_USER_VM_H

#include "rvvm_user_vma.h"
#include "rvvm_user_vm_backing.h"

struct user_vm_region {
    uintptr_t address;
    size_t size;
    int prot, backing, baseline;
    bool file;
    void* original;
    off_t offset;
};

struct user_vm {
    struct user_vm_region* regions;
    size_t count;
    int memory, pagemap;
    size_t page;
    unsigned char* scratch;
    uint64_t* pages;
    size_t buffer_size;
    uintptr_t child_cleartid;
};

static void user_vm_destroy_view(struct user_vm* vm, bool descriptors)
{
    for (size_t i = 0; i < vm->count; ++i) {
        struct user_vm_region* region = vm->regions + i;
        if (descriptors && region->backing >= 0) close(region->backing);
        if (descriptors && region->baseline >= 0) close(region->baseline);
        if (region->original) munmap(region->original, region->size);
    }
    if (descriptors && vm->memory >= 0) close(vm->memory);
    if (descriptors && vm->pagemap >= 0) close(vm->pagemap);
    free(vm->regions);
    free(vm->scratch);
    free(vm->pages);
    free(vm);
}

static void user_vm_destroy(struct user_vm* vm) { user_vm_destroy_view(vm, true); }

/* The service owns a private host descriptor table. None of its backing or
 * proc descriptors occupies a descriptor in the guest's kernel table. All
 * allocation and stdio must finish before pausing other native threads. */
static struct user_vm* user_vm_prepare(void)
{
    struct user_vm* vm = calloc(1, sizeof(*vm));
    if (!vm) return NULL;
    vm->memory = vm->pagemap = -1;
    vm->page = sysconf(_SC_PAGESIZE);
    vm->buffer_size = vm->page > 65536 ? vm->page : 65536;
    vm->scratch = malloc(vm->buffer_size * 2);
    vm->pages = malloc(65536 * sizeof(*vm->pages));
    if (!vm->scratch || !vm->pages) { user_vm_destroy(vm); return NULL; }
    FILE* maps = fopen("/proc/thread-self/maps", "re");
    if (!maps) { user_vm_destroy(vm); return NULL; }
    char line[4096];
    user_fd_mutex_lock(&user_vma_owned_lock);
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end, offset, inode;
        char mode[5];
        if (sscanf(line, "%lx-%lx %4s %lx %*s %lu", &start, &end, mode, &offset, &inode) != 5
            || mode[3] != 'p') continue;
        for (size_t i = 0; i < user_vma_owned_count; ++i) {
            uintptr_t first = start > user_vma_owned[i].start ? start : user_vma_owned[i].start;
            uintptr_t last = end < user_vma_owned[i].end ? end : user_vma_owned[i].end;
            if (first >= last) continue;
            void* grown = realloc(vm->regions, (vm->count + 1) * sizeof(*vm->regions));
            if (!grown) goto fail_maps;
            vm->regions = grown;
            vm->regions[vm->count++] = (struct user_vm_region) {
                .address = first, .size = last - first, .backing = -1, .baseline = -1, .file = inode != 0,
                .prot = (mode[0] == 'r' ? PROT_READ : 0) | (mode[1] == 'w' ? PROT_WRITE : 0)
                      | (mode[2] == 'x' ? PROT_EXEC : 0),
            };
        }
    }
    user_fd_mutex_unlock(&user_vma_owned_lock);
    fclose(maps);
    vm->memory = open("/proc/thread-self/mem", O_RDWR | O_CLOEXEC);
    vm->pagemap = open("/proc/thread-self/pagemap", O_RDONLY | O_CLOEXEC);
    if (vm->memory < 0 || vm->pagemap < 0) goto fail;
    for (size_t i = 0; i < vm->count; ++i) {
        struct user_vm_region* region = vm->regions + i;
        region->backing = syscall(SYS_memfd_create, "rvvm-vfork-memory", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (region->backing < 0 || ftruncate(region->backing, region->size)) goto fail;
        if (region->file) {
            region->baseline = syscall(SYS_memfd_create, "rvvm-vfork-baseline", MFD_CLOEXEC);
            if (region->baseline < 0) goto fail;
        }
        region->original = mmap(NULL, region->size, PROT_NONE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (region->original == MAP_FAILED) { region->original = NULL; goto fail; }
    }
    return vm;
fail_maps:
    user_fd_mutex_unlock(&user_vma_owned_lock);
    fclose(maps);
fail: {
        int error = errno;
        user_vm_destroy(vm);
        errno = error;
        return NULL;
    }
}

static int user_vm_read(int fd, void* buffer, size_t size, off_t offset)
{
    ssize_t n;
    do { n = pread(fd, buffer, size, offset); } while (n < 0 && errno == EINTR);
    if (n == (ssize_t)size) return 0;
    if (n >= 0) errno = EIO;
    return -1;
}

static int user_vm_write(int fd, const void* buffer, size_t size, off_t offset)
{
    while (size) {
        ssize_t n = pwrite(fd, buffer, size, offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; return -1; }
        buffer = (const char*)buffer + n;
        size -= n;
        offset += n;
    }
    return 0;
}

/* Native aliases retain the original anonymous/file-backed kernel mappings.
 * Only guest VMAs become shared; native TLS, malloc and locks remain private
 * when the worker forks. Writers must stay paused throughout this operation. */
static int user_vm_populate(struct user_vm* vm, struct user_vm_region* region, uintptr_t source)
{
    unsigned char* bytes = vm->scratch;
    uint64_t* entries = vm->pages;
        size_t valid = region->size;
        for (size_t offset = 0; offset < region->size;) {
            size_t count = (region->size - offset) / vm->page;
            if (count > 65536) count = 65536;
            if (!region->file && user_vm_read(vm->pagemap, entries, count * sizeof(*entries),
                    ((source + offset) / vm->page) * sizeof(*entries))) return -1;
            for (size_t p = 0; p < count;) {
                size_t position = offset + p * vm->page;
                /* Present and swapped anonymous pages both contain data.
                 * Untouched reserved heaps must remain sparse. */
                if (!region->file && !(entries[p] & (UINT64_C(3) << 62))) { ++p; continue; }
                size_t run = 1;
                while (run < vm->buffer_size / vm->page && p + run < count
                       && (region->file || (entries[p + run] & (UINT64_C(3) << 62)))) ++run;
                size_t length = run * vm->page;
                if (user_vm_read(vm->memory, bytes, length, source + position)) {
                    /* A file extent may end inside this batch. Retry a page
                     * at a time so its last valid page keeps the kernel's
                     * zero-filled tail and the following page still SIGBUSes. */
                    run = 1;
                    length = vm->page;
                    if (!user_vm_read(vm->memory, bytes, length, source + position)) goto write;
                    if (region->file && errno == EIO) { valid = position; goto copied; }
                    return -1;
                }
write:
                if (user_vm_write(region->backing, bytes, length, position)) return -1;
                p += run;
            }
            offset += count * vm->page;
        }
copied:
        /* Preserve SIGBUS beyond a file's last mapped page, including a
         * mapping whose starting offset is already beyond EOF. */
        return ftruncate(region->backing, valid);
}

static int user_vm_baseline(struct user_vm* vm, struct user_vm_region* region)
{
    if (region->baseline < 0) return 0;
    struct stat info;
    if (fstat(region->backing, &info) || ftruncate(region->baseline, info.st_size)) return -1;
    for (off_t offset = 0; offset < info.st_size;) {
        size_t length = info.st_size - offset > (off_t)vm->buffer_size
                      ? vm->buffer_size : (size_t)(info.st_size - offset);
        if (user_vm_read(region->backing, vm->scratch, length, offset)
            || user_vm_write(region->baseline, vm->scratch, length, offset)) return -1;
        offset += length;
    }
    return 0;
}

static int user_vm_share(struct user_vm* vm)
{
    size_t converted = 0;
    for (; converted < vm->count; ++converted) {
        struct user_vm_region* region = vm->regions + converted;
        if (user_vm_populate(vm, region, region->address) || user_vm_baseline(vm, region)) goto fail;
        if (mremap((void*)region->address, region->size, region->size,
                   MREMAP_MAYMOVE | MREMAP_FIXED, region->original) == MAP_FAILED) goto fail;
        if (user_vm_backing_map(region->backing, (void*)region->address, region->size,
                                region->prot, MAP_FIXED, 0) == MAP_FAILED) {
            int error = errno;
            if (mremap(region->original, region->size, region->size,
                       MREMAP_MAYMOVE | MREMAP_FIXED, (void*)region->address) == MAP_FAILED) abort();
            region->original = NULL;
            errno = error;
            goto fail;
        }
    }
    return 0;
fail: {
        int error = errno;
        while (converted) {
            struct user_vm_region* region = vm->regions + --converted;
            if (mremap(region->original, region->size, region->size,
                       MREMAP_MAYMOVE | MREMAP_FIXED, (void*)region->address) == MAP_FAILED) abort();
            region->original = NULL;
        }
        errno = error;
        return -1;
    }
}

/* Split metadata before pausing peers: realloc can require an allocator lock.
 * The original alias is still one kernel VMA; mremap can move its subranges
 * independently when the shared view is finally released. */
static int user_vm_split(struct user_vm* vm, uintptr_t address)
{
    for (size_t i = 0; i < vm->count; ++i) {
        struct user_vm_region region = vm->regions[i];
        if (address <= region.address || address >= region.address + region.size) continue;
        int fd = fcntl(region.backing, F_DUPFD_CLOEXEC, 0);
        if (fd < 0) return -1;
        int baseline = region.baseline >= 0 ? fcntl(region.baseline, F_DUPFD_CLOEXEC, 0) : -1;
        if (region.baseline >= 0 && baseline < 0) { close(fd); return -1; }
        void* grown = realloc(vm->regions, (vm->count + 1) * sizeof(region));
        if (!grown) { close(fd); if (baseline >= 0) close(baseline); return -1; }
        vm->regions = grown;
        memmove(vm->regions + i + 2, vm->regions + i + 1, (vm->count - i - 1) * sizeof(region));
        size_t left = address - region.address;
        vm->regions[i].size = left;
        region.address = address;
        region.size -= left;
        region.original = (char*)region.original + left;
        region.offset += left;
        region.backing = fd;
        region.baseline = baseline;
        vm->regions[i + 1] = region;
        ++vm->count;
        return 0;
    }
    return 0;
}

static void user_vm_remove(struct user_vm* vm, uintptr_t address, size_t size)
{
    for (size_t i = 0; i < vm->count;) {
        struct user_vm_region region = vm->regions[i];
        if (region.address < address || region.address >= address + size) { ++i; continue; }
        munmap(region.original, region.size);
        close(region.backing);
        if (region.baseline >= 0) close(region.baseline);
        memmove(vm->regions + i, vm->regions + i + 1, (--vm->count - i) * sizeof(region));
    }
}

/* Copy back only changed pages. In particular, unchanged private file pages
 * must retain their original connection to the file's page cache. The kernel
 * continues to own protection, residency, sparse allocation and ordinary
 * fork's COW once the original mapping is moved back into place. */
static int user_vm_sync_region(struct user_vm* vm, struct user_vm_region* region)
{
    unsigned char *shared = vm->scratch, *original = vm->scratch + vm->buffer_size;
        off_t position = region->offset;
        struct stat info;
        if (fstat(region->backing, &info)) return -1;
        off_t limit = region->offset + region->size;
        if (limit > info.st_size) limit = info.st_size;
        while (position < limit) {
            off_t start = lseek(region->backing, position, SEEK_DATA);
            if (start < 0) { if (errno == ENXIO) break; return -1; }
            off_t end = lseek(region->backing, start, SEEK_HOLE);
            if (end < 0) return -1;
            if (end > limit) end = limit;
            for (; start < end;) {
                size_t length = end - start > (off_t)vm->buffer_size ? vm->buffer_size : (size_t)(end - start);
                if (user_vm_read(region->backing, shared, length, start)
                    || (region->baseline >= 0
                        ? user_vm_read(region->baseline, original, length, start)
                        : user_vm_read(vm->memory, original, length,
                            (uintptr_t)region->original + start - region->offset)))
                    return -1;
                if (memcmp(shared, original, length)) {
                    for (size_t p = 0; p < length; p += vm->page) {
                        if (memcmp(shared + p, original + p, vm->page)
                            && user_vm_write(vm->memory, shared + p, vm->page,
                                (uintptr_t)region->original + start - region->offset + p)) return -1;
                    }
                }
                start += length;
            }
            position = end;
        }
    return 0;
}

static int user_vm_restore(struct user_vm* vm)
{
    for (size_t i = 0; i < vm->count; ++i)
        if (user_vm_sync_region(vm, vm->regions + i)) return -1;
    /* Restore only after all bytes are reconciled, so an I/O error leaves
     * every worker on the same shared view. */
    for (size_t i = 0; i < vm->count; ++i) {
        struct user_vm_region* region = vm->regions + i;
        if (mremap(region->original, region->size, region->size,
                   MREMAP_MAYMOVE | MREMAP_FIXED, (void*)region->address) == MAP_FAILED) return -1;
        region->original = NULL;
    }
    return 0;
}

#endif
