/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_AIO_H
#define RVVM_USER_AIO_H
#include <linux/aio_abi.h>

_Static_assert(sizeof(aio_context_t) == 8 && sizeof(struct iocb) == 64
               && sizeof(struct io_event) == 32, "RV64 Linux AIO ABI");
_Static_assert(offsetof(struct iocb, aio_fildes) == 20
               && offsetof(struct iocb, aio_buf) == 24
               && offsetof(struct iocb, aio_flags) == 56
               && offsetof(struct iocb, aio_resfd) == 60
               && offsetof(struct io_event, obj) == 8, "RV64 AIO fields");

struct user_aio_ring {
    uint32_t id, nr, head, tail, magic, compat, incompat, header_length;
};
struct user_aio_context {
    struct user_aio_context* next;
    uintptr_t address;
    size_t size;
    uint32_t capacity;
};
/* mmap_lock protects this ownership list, not the kernel's completion queue. */
static struct user_aio_context* user_aio_contexts;

static long user_aio_setup(unsigned events, aio_context_t* output)
{
    aio_context_t context;
    if (user_memory_copy(&context, output, sizeof(context))) return -EFAULT;
    if (context || !events) return -EINVAL;
    struct user_aio_context* entry = malloc(sizeof(*entry));
    if (!entry) return -ENOMEM;
    user_fd_lock();
    spin_lock(&mmap_lock);
    long result = -ENOMEM;
    if (!user_vma_reserve(1)) goto out;
    result = errno_ret(user_vma_execute(SYS_io_setup, events, (long)&context, 0, 0, 0, 0));
    if (result) goto out;
    /* Linux maps the ring outside the guest allocator. Move it with the
     * kernel's AIO mremap callback, which also updates its context handle.
     * libaio may read this ring directly instead of calling io_getevents. */
    struct user_aio_ring ring;
    memcpy(&ring, (void*)(uintptr_t)context, sizeof(ring));
    size_t page = user_vma_page();
    size_t size = (ring.header_length + (size_t)ring.nr * sizeof(struct io_event) + page - 1) & ~(page - 1);
    void* destination = user_vma_map_raw(NULL, size, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (destination == MAP_FAILED) result = -errno;
    else {
        void* moved = user_vma_kernel_remap((void*)(uintptr_t)context, size, size,
                                            MREMAP_MAYMOVE | MREMAP_FIXED, destination);
        if (moved == MAP_FAILED) {
            result = -errno;
            (void)user_vma_kernel_unmap(destination, size);
        } else {
            context = (uintptr_t)moved;
            result = user_memory_copy(output, &context, sizeof(context));
        }
    }
    if (result) {
        user_vma_execute(SYS_io_destroy, context, 0, 0, 0, 0, 0);
        goto out;
    }
    user_vma_remember(context, size);
    *entry = (struct user_aio_context){user_aio_contexts, context, size, ring.nr};
    user_aio_contexts = entry;
    entry = NULL;
out:
    spin_unlock(&mmap_lock);
    user_fd_unlock();
    free(entry);
    return result;
}

static long user_aio_destroy(aio_context_t context)
{
    user_fd_lock();
    spin_lock(&mmap_lock);
    struct user_aio_context** slot = &user_aio_contexts;
    while (*slot && (*slot)->address != context) slot = &(*slot)->next;
    struct user_aio_context* released = NULL;
    long result = -ENOMEM;
    if (user_vma_reserve(1) && user_exec_reserve(2)) {
        result = errno_ret(user_vma_execute(SYS_io_destroy, context, 0, 0, 0, 0, 0));
        if (!result && *slot) {
            released = *slot;
            *slot = released->next;
            user_vma_forget(released->address, released->size);
            user_exec_update(released->address, released->size, false);
        }
    }
    spin_unlock(&mmap_lock);
    user_fd_unlock();
    free(released);
    return result;
}

static void user_aio_remap(uintptr_t old, uintptr_t next)
{
    for (struct user_aio_context* entry = user_aio_contexts; entry; entry = entry->next)
        if (entry->address == old) { entry->address = next; break; }
}

static void user_aio_fork_child(void)
{
    /* Kernel AIO contexts and their DONTFORK rings do not survive fork.
     * Keep any guest replacement mappings, pruning only the actual holes. */
    while (user_aio_contexts) {
        struct user_aio_context* entry = user_aio_contexts;
        user_aio_contexts = entry->next;
        size_t page = user_vma_page();
        for (uintptr_t at = entry->address; at < entry->address + entry->size; at += page) {
            unsigned char resident;
            if (mincore((void*)at, page, &resident) && errno == ENOMEM) {
                if (!user_vma_reserve(1)) syscall(SYS_exit_group, 127);
                user_vma_forget(at, page);
                user_exec_update(at, page, false);
            }
        }
        free(entry);
    }
}

static long user_aio_submit(aio_context_t context, long count, struct iocb** requests)
{
    if (count <= 0) return errno_ret(USER_SYSCALL(SYS_io_submit, context, count, requests, 0, 0, 0));
    user_fd_lock();
    /* Validate the handle first, as Linux does, and bound the scan by the
     * kernel ring capacity even if the caller supplies LONG_MAX requests. */
    long result = errno_ret(USER_SYSCALL(SYS_io_submit, context, 0, NULL, 0, 0, 0));
    if (result) goto out;
    spin_lock(&mmap_lock);
    for (struct user_aio_context* entry = user_aio_contexts; entry; entry = entry->next) {
        if (entry->address != context) continue;
        if (count > entry->capacity) count = entry->capacity;
        break;
    }
    spin_unlock(&mmap_lock);
    bool private = false;
    long prefix;
    for (prefix = 0; prefix < count; prefix++) {
        struct iocb* request;
        struct iocb snapshot;
        if (user_memory_copy(&request, requests + prefix, sizeof(request))
            || user_memory_copy(&snapshot, request, sizeof(snapshot))) break;
        if (user_private_fd(snapshot.aio_fildes)
            || ((snapshot.aio_flags & IOCB_FLAG_RESFD) && user_private_fd(snapshot.aio_resfd))) {
            private = true;
            break;
        }
    }
    /* Keep original iocb pointers: Linux writes aio_key, reports the pointer
     * in io_event.obj and uses it to identify io_cancel requests. Retain bulk
     * submission and the kernel's partial-success/error ordering. */
    result = private && !prefix ? -EBADF
        : (long)errno_ret(USER_SYSCALL(SYS_io_submit, context, private ? prefix : count, requests, 0, 0, 0));
out:
    user_fd_unlock();
    return result;
}
#endif
