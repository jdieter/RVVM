/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_ALLOCATE_H
#define RVVM_USER_ALLOCATE_H

/* Shared-mm children delegate ownership to their trusted worker, so death
 * between allocation and publication cannot corrupt libc or leak storage. */
static THREAD_LOCAL struct {
    void* (*call)(void*, size_t, void*);
    void* opaque;
} user_runtime_allocator;

static void* user_runtime_allocate(size_t size)
{
    return user_runtime_allocator.call
        ? user_runtime_allocator.call(user_runtime_allocator.opaque, size, NULL) : malloc(size);
}

static void user_runtime_release(void* pointer)
{
    if (!pointer) return;
    if (user_runtime_allocator.call) user_runtime_allocator.call(user_runtime_allocator.opaque, 0, pointer);
    else free(pointer);
}
#endif
