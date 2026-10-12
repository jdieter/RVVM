/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_VM_RPC_H
#define RVVM_USER_VM_RPC_H

#include <linux/falloc.h>

struct user_vm_message {
    uint64_t nr, args[6], heap[4];
    int64_t result;
    uint64_t offset;
};
static THREAD_LOCAL bool user_vm_rpc_private_files;

static long user_vm_message(int socket, struct user_vm_message* message, int* fd, bool send_message)
{
    struct iovec io = {message, sizeof(*message)};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } ancillary;
    struct msghdr packet = {.msg_iov = &io, .msg_iovlen = 1};
    memset(&ancillary, 0, sizeof(ancillary));
    if (!send_message || *fd >= 0) {
        packet.msg_control = ancillary.bytes;
        packet.msg_controllen = sizeof(ancillary);
    }
    if (send_message && *fd >= 0) {
        struct cmsghdr* header = CMSG_FIRSTHDR(&packet);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), fd, sizeof(int));
    }
    long count;
    do {
        count = send_message ? sendmsg(socket, &packet, MSG_NOSIGNAL)
                             : recvmsg(socket, &packet, MSG_CMSG_CLOEXEC);
    } while (count < 0 && errno == EINTR);
    if (count <= 0) return count;
    if (!send_message) {
        *fd = -1;
        struct cmsghdr* header = CMSG_FIRSTHDR(&packet);
        if (header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS
            && header->cmsg_len == CMSG_LEN(sizeof(int))) memcpy(fd, CMSG_DATA(header), sizeof(int));
    }
    if (count != sizeof(*message) || (packet.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        if (!send_message && *fd >= 0) close(*fd);
        errno = EIO;
        return -1;
    }
    return count;
}

static int user_vm_region_prepare(struct user_vm* vm, struct user_vm_region* region,
                                  size_t size, int prot, int flags, int fd, off_t offset)
{
    *region = (struct user_vm_region){.size = size, .prot = prot, .backing = -1, .baseline = -1,
                                      .file = !(flags & MAP_ANONYMOUS)};
    region->original = mmap(NULL, size, prot,
        flags & ~(MAP_FIXED | MAP_FIXED_NOREPLACE), fd, offset);
    if (region->original == MAP_FAILED) { region->original = NULL; return -1; }
    region->backing = syscall(SYS_memfd_create, "rvvm-vfork-memory", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (region->backing < 0 || ftruncate(region->backing, size)
        || user_vm_populate(vm, region, (uintptr_t)region->original)) return -1;
    if (region->file) {
        region->baseline = syscall(SYS_memfd_create, "rvvm-vfork-baseline", MFD_CLOEXEC);
        if (region->baseline < 0 || user_vm_baseline(vm, region)) return -1;
    }
    return 0;
}

static void user_vm_region_discard(struct user_vm_region* region)
{
    if (region->original) munmap(region->original, region->size);
    if (region->backing >= 0) close(region->backing);
    if (region->baseline >= 0) close(region->baseline);
    region->original = NULL;
    region->backing = -1;
    region->baseline = -1;
}

static void user_vm_alias_protect(struct user_vm* vm, uintptr_t address, size_t size, int prot)
{
    for (size_t i = 0; i < vm->count; ++i) {
        struct user_vm_region* region = vm->regions + i;
        uintptr_t start = address > region->address ? address : region->address;
        uintptr_t end = address + size < region->address + region->size
                      ? address + size : region->address + region->size;
        if (start >= end) continue;
        if (mprotect((char*)region->original + start - region->address, end - start, prot))
            rvvm_fatal("Cannot mirror shared guest protection");
        region->prot = prot;
    }
}

static int user_vm_discard_pages(struct user_vm* vm, uintptr_t address, size_t size)
{
    for (size_t i = 0; i < vm->count; ++i) {
        struct user_vm_region* region = vm->regions + i;
        uintptr_t start = address > region->address ? address : region->address;
        uintptr_t end = address + size < region->address + region->size
                      ? address + size : region->address + region->size;
        if (start >= end) continue;
        void* alias = (char*)region->original + start - region->address;
        if (madvise(alias, end - start, MADV_DONTNEED)) return -1;
        off_t offset = region->offset + start - region->address;
        if (fallocate(region->backing, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, end - start)) return -1;
        if (region->file) {
            struct stat info;
            if (fstat(region->backing, &info)) return -1;
            for (uintptr_t at = start; at < end && offset < info.st_size; at += vm->page, offset += vm->page) {
                if (user_vm_read(vm->memory, vm->scratch, vm->page,
                                 (uintptr_t)region->original + at - region->address)
                    || user_vm_write(region->backing, vm->scratch, vm->page, offset)) return -1;
                if (region->baseline >= 0 && user_vm_write(region->baseline, vm->scratch, vm->page, offset)) return -1;
            }
        }
    }
    return 0;
}

/* One native service serializes VMA changes for the suspended parent and its
 * child. The kernel maps, protects, discards and faults each view; the service
 * coordinates addresses and owns the temporary private backings. */
static void user_vm_serve(struct user_vm* vm, int socket)
{
    struct user_vm_message request;
    int source = -1;
    while (user_vm_message(socket, &request, &source, false) > 0) {
        uint64_t *a = request.args;
        struct user_vm_region added = {.backing = -1, .baseline = -1};
        size_t remap_index = SIZE_MAX;
        bool appended = false;
        int response_fd = -1;
#ifdef USER_FAULT_META
        struct user_exec_move execution = ZERO_INIT;
#endif
        request.result = -ENOSYS;
        if (!vm) goto reply;
        if (request.nr == 96) {
            vm->child_cleartid = a[0];
            request.result = 0;
            goto reply;
        }
        size_t size = (a[1] + vm->page - 1) & ~(vm->page - 1);
        bool range = request.nr == 215 || request.nr == 222 || request.nr == 226 || request.nr == 233;
        if (range && (a[0] > UINTPTR_MAX - size
            || ((request.nr == 215 || request.nr == 222) && !size)
            || ((request.nr == 215 || request.nr == 226) && a[0] % vm->page))) {
            request.result = -EINVAL;
            goto reply;
        }
        if (request.nr == 214 && brk_heap.base && a[0] >= brk_heap.base
            && a[0] - brk_heap.base <= UAPI_BRK_WINDOW) {
            uintptr_t next = (a[0] + vm->page - 1) & ~(vm->page - 1);
            if (user_vm_split(vm, brk_heap.committed) || user_vm_split(vm, next)) {
                request.result = brk_heap.current;
                goto heap_reply;
            }
            if (next > brk_heap.committed) {
                if (user_vm_region_prepare(vm, &added, next - brk_heap.committed,
                                           PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) {
                    request.result = brk_heap.current;
                    goto heap_reply;
                }
                void* grown = realloc(vm->regions, (vm->count + 1) * sizeof(*vm->regions));
                if (!grown) { request.result = brk_heap.current; goto heap_reply; }
                vm->regions = grown;
            }
        }
        if ((request.nr == 215 || request.nr == 226)
            && (user_vm_split(vm, a[0]) || user_vm_split(vm, a[0] + size))) {
            request.result = -errno;
            goto reply;
        }
        if (request.nr == 222) {
            int flags = (a[3] & UAPI_MAP_SHARED ? MAP_SHARED : 0)
                      | (a[3] & UAPI_MAP_PRIVATE ? MAP_PRIVATE : 0)
                      | (a[3] & UAPI_MAP_ANON ? MAP_ANONYMOUS : 0)
                      | (a[3] & UAPI_MAP_FIXED ? MAP_FIXED : 0)
                      | (a[3] & UAPI_MAP_FIXED_NOREPLACE ? MAP_FIXED_NOREPLACE : 0)
                      | (a[3] & 0x4000 ? MAP_NORESERVE : 0);
            if (a[3] & UAPI_MAP_ILLEGAL) { request.result = -EINVAL; goto reply; }
            if (a[3] & 0x40000) flags |= MAP_HUGETLB | (a[3] & (63U << 26));
            size_t page = user_vma_map_page(flags);
            if (!page || page >= user_vma_layout.limit || a[1] > user_vma_layout.limit - page) {
                request.result = -ENOMEM;
                goto reply;
            }
            size = (a[1] + page - 1) & ~(page - 1);
            if ((flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) && a[0] % vm->page) {
                request.result = -EINVAL;
                goto reply;
            }
            if (!(flags & MAP_SHARED) || (flags & MAP_ANONYMOUS)) {
                if (user_vm_region_prepare(vm, &added, size, rvvm_sys_prot(a[2]), flags, source, a[5])) {
                    request.result = -errno;
                    goto reply;
                }
                void* grown = realloc(vm->regions, (vm->count + 1) * sizeof(*vm->regions));
                if (!grown) { request.result = -ENOMEM; goto reply; }
                vm->regions = grown;
            }
            if ((flags & MAP_FIXED) && (user_vm_split(vm, a[0]) || user_vm_split(vm, a[0] + size))) {
                request.result = -errno;
                goto reply;
            }
            if (added.original) {
                void* grown = realloc(vm->regions, (vm->count + 1) * sizeof(*vm->regions));
                if (!grown) { request.result = -ENOMEM; goto reply; }
                vm->regions = grown;
            }
        }
        if (request.nr == 216) {
            size_t oldsize = (a[1] + vm->page - 1) & ~(vm->page - 1);
            size_t newsize = (a[2] + vm->page - 1) & ~(vm->page - 1);
            if (!oldsize || !newsize || a[0] % vm->page || (a[3] & MREMAP_DONTUNMAP)
                || (a[3] & ~(MREMAP_MAYMOVE | MREMAP_FIXED))
                || ((a[3] & MREMAP_FIXED) && (!(a[3] & MREMAP_MAYMOVE)
                    || a[4] % vm->page || !user_vma_range(a[4], newsize)
                    || (a[0] < a[4] + newsize && a[4] < a[0] + oldsize)))) {
                request.result = -EINVAL;
                goto reply;
            }
            if (user_vm_split(vm, a[0]) || user_vm_split(vm, a[0] + oldsize)
                || ((a[3] & MREMAP_FIXED) && (user_vm_split(vm, a[4]) || user_vm_split(vm, a[4] + newsize)))) {
                request.result = -errno;
                goto reply;
            }
            for (size_t i = 0; i < vm->count; ++i)
                if (vm->regions[i].address == a[0] && vm->regions[i].size == oldsize) remap_index = i;
            if (remap_index == SIZE_MAX) { request.result = -ENOSYS; goto reply; }
            added = vm->regions[remap_index];
            added.size = newsize;
            added.original = NULL;
            added.offset = 0;
            added.baseline = -1;
            added.backing = syscall(SYS_memfd_create, "rvvm-vfork-memory", MFD_CLOEXEC | MFD_ALLOW_SEALING);
            if (added.backing < 0 || ftruncate(added.backing, newsize)) {
                request.result = -errno;
                goto reply;
            }
            if (added.file) {
                added.baseline = syscall(SYS_memfd_create, "rvvm-vfork-baseline", MFD_CLOEXEC);
                if (added.baseline < 0) { request.result = -errno; goto reply; }
            }
        }
        spin_lock(&brk_lock);
        spin_lock(&mmap_lock);
#ifdef USER_FAULT_META
        if (request.nr == 216) user_exec_move_prepare(&execution, a[0], a[1], a[2]);
#endif
        bool needs_metadata = request.nr == 222 || request.nr == 216
                           || (request.nr == 214 && added.original);
        if ((needs_metadata && !user_vma_reserve(2)) || user_vm_pause_begin()) {
            request.result = -errno;
            spin_unlock(&mmap_lock);
            spin_unlock(&brk_lock);
            goto reply;
        }
        switch (request.nr) {
            case 214: {
                uintptr_t old = brk_heap.committed;
                if (!brk_heap.base) break;
                if (added.original) {
                    void* address = user_vma_map_raw((void*)old, added.size, added.prot,
                                                    MAP_SHARED | MAP_FIXED_NOREPLACE,
                                                    added.backing, 0);
                    request.result = brk_heap.current;
                    if (address != MAP_FAILED) {
                        user_vma_remember(old, added.size);
                        added.address = old;
                        vm->regions[vm->count++] = added;
                        appended = true;
                        response_fd = added.backing;
                        brk_heap.committed = old + added.size;
                        brk_heap.current = a[0];
                        request.result = a[0];
                    }
                } else request.result = uapi_brk(&brk_heap, a[0]);
                if (old > brk_heap.committed)
                    user_vm_remove(vm, brk_heap.committed, old - brk_heap.committed);
                break;
            }
            case 215:
                request.result = (long)errno_ret(user_vma_unmap((void*)a[0], a[1]));
                if (!request.result) user_vm_remove(vm, a[0], size);
                break;
            case 222: {
                int fixed = (a[3] & UAPI_MAP_FIXED ? MAP_FIXED : 0)
                          | (a[3] & UAPI_MAP_FIXED_NOREPLACE ? MAP_FIXED_NOREPLACE : 0);
                void* address;
                if (added.original) {
                    address = user_vma_map_raw((void*)a[0], size, added.prot,
                        MAP_SHARED | MAP_NORESERVE | fixed, added.backing, 0);
                } else address = user_vma_map_raw((void*)a[0], size, rvvm_sys_prot(a[2]),
                                                  MAP_SHARED | fixed, source, a[5]);
                request.result = address == MAP_FAILED ? -errno : (intptr_t)address;
                if (address == MAP_FAILED) break;
                user_vm_remove(vm, (uintptr_t)address, size);
                user_vma_remember((uintptr_t)address, size);
                request.offset = added.original ? 0 : a[5];
                response_fd = added.original ? added.backing : source;
                if (added.original && (a[3] & UAPI_MAP_PRIVATE)) {
                    added.address = (uintptr_t)address;
                    vm->regions[vm->count++] = added;
                    appended = true;
                }
                break;
            }
            case 226:
                request.result = (long)errno_ret(mprotect((void*)a[0], a[1], rvvm_sys_prot(a[2])));
                if (!request.result) user_vm_alias_protect(vm, a[0], size, rvvm_sys_prot(a[2]));
                break;
            case 216: {
                struct user_vm_region* old = vm->regions + remap_index;
                if (user_vm_sync_region(vm, old)) rvvm_fatal("Cannot reconcile guest mremap");
                void* alias = mremap(old->original, old->size, added.size, MREMAP_MAYMOVE);
                if (alias == MAP_FAILED) { request.result = -errno; break; }
                old->original = alias;
                added.original = alias;
                if (user_vm_populate(vm, &added, (uintptr_t)alias) || user_vm_baseline(vm, &added))
                    rvvm_fatal("Cannot populate guest mremap");
                void* address = user_vma_remap_raw((void*)a[0], a[1], a[2], a[3], (void*)a[4]);
                if (address == MAP_FAILED) {
                    request.result = -errno;
                    alias = mremap(alias, added.size, old->size, MREMAP_MAYMOVE);
                    if (alias == MAP_FAILED) rvvm_fatal("Cannot roll back guest mremap");
                    old->original = alias;
                    added.original = NULL;
                    break;
                }
                if (user_vm_backing_map(added.backing, address, added.size, added.prot, MAP_FIXED, 0) == MAP_FAILED)
                    rvvm_fatal("Cannot replace shared guest mremap");
                close(old->backing);
                if (old->baseline >= 0) close(old->baseline);
                memmove(old, old + 1, (--vm->count - remap_index) * sizeof(*old));
                user_vm_remove(vm, (uintptr_t)address, added.size);
                added.address = (uintptr_t)address;
                vm->regions[vm->count++] = added;
                appended = true;
                response_fd = added.backing;
                request.result = (intptr_t)address;
                request.heap[0] = added.prot;
                user_vma_forget(a[0], a[1]);
                user_vma_remember((uintptr_t)address, a[2]);
                break;
            }
            case 233:
                request.result = (long)errno_ret(madvise((void*)a[0], a[1], a[2]));
                if (!request.result && a[2] == MADV_DONTNEED && user_vm_discard_pages(vm, a[0], size))
                    rvvm_fatal("Cannot discard shared guest pages");
                break;
        }
        user_vm_pause_end();
#ifdef USER_FAULT_META
        if (!request.result && request.nr == 226) user_exec_update(a[0], a[1], a[2] & UAPI_PROT_EXEC);
        if (!request.result && request.nr == 215) user_exec_update(a[0], a[1], false);
        if (request.result >= 0 && request.nr == 222)
            user_exec_update(request.result, a[1], a[2] & UAPI_PROT_EXEC);
        if (request.result >= 0 && request.nr == 216)
            user_exec_move_apply(&execution, a[0], a[1], a[2], a[3], request.result);
#endif
        spin_unlock(&mmap_lock);
        spin_unlock(&brk_lock);
heap_reply:
        if (request.nr == 214) {
            request.heap[0] = brk_heap.base;
            request.heap[1] = brk_heap.current;
            request.heap[2] = brk_heap.committed;
            request.heap[3] = brk_heap.page_size;
        }
reply:
#ifdef USER_FAULT_META
        vector_free(execution.ranges);
#endif
        if (user_vm_message(socket, &request, &response_fd, true) < 0) {
            if (!appended) user_vm_region_discard(&added);
            break;
        }
        if (source >= 0) close(source);
        source = -1;
        if (!appended) user_vm_region_discard(&added);
    }
    if (source >= 0) close(source);
}

static long user_vm_rpc_impl(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5)
{
    struct user_vm_message request = {.nr = nr, .args = {a0, a1, a2, a3, a4, a5}};
    user_fd_lock();
    int fd = nr == 222 && !(a3 & UAPI_MAP_ANON) ? (int)a4 : -1;
    if (nr == 222 && !(a3 & UAPI_MAP_ANON) && (fd < 0 || fcntl(fd, F_GETFD) < 0)) {
        user_fd_unlock();
        return -EBADF;
    }
    if (user_vm_message(user_vm_fd, &request, &fd, true) < 0) {
        int error = errno;
        user_fd_unlock();
        return -error;
    }
    /* The service retained a transmitted source. Release this helper's copy
     * before receiving the backing, including when fd0 fills a hard limit. */
    if (user_vm_rpc_private_files && fd >= 0) close(fd);
    fd = -1;
    if (user_vm_message(user_vm_fd, &request, &fd, false) <= 0) rvvm_fatal("Lost guest VM service");
    if (request.result >= 0) {
        long result = 0;
        switch (nr) {
            case 214: {
                uintptr_t old = brk_heap.committed, next = request.heap[2];
                if (old < next)
                    result = user_vma_map((void*)old, next - old, PROT_READ | PROT_WRITE,
                                         MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0) == MAP_FAILED ? -1 : 0;
                else if (old > next) result = user_vma_unmap((void*)next, old - next);
                brk_heap = (struct uapi_brk_heap){request.heap[0], request.heap[1], next, request.heap[3]};
                break;
            }
            case 215: result = user_vma_unmap((void*)a0, a1); break;
            case 222:
                result = user_vma_map((void*)request.result, a1, rvvm_sys_prot(a2),
                                     MAP_SHARED | MAP_FIXED, fd, request.offset) == MAP_FAILED ? -1 : 0;
                break;
            case 226: result = mprotect((void*)a0, a1, rvvm_sys_prot(a2)); break;
            case 216: {
                int flags = request.result == (int64_t)a0 ? (a3 & ~MREMAP_MAYMOVE)
                                                         : (a3 | MREMAP_MAYMOVE | MREMAP_FIXED);
#ifdef USER_FAULT_META
                long moved = user_mremap(a0, a1, a2, flags, request.result);
#else
                long moved = (long)errno_ret((uintptr_t)user_vma_remap((void*)a0, a1, a2, flags, (void*)request.result));
#endif
                if (moved < 0) result = -1;
                else result = mmap((void*)request.result, a2, request.heap[0],
                                   MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED ? -1 : 0;
                break;
            }
            case 233: result = madvise((void*)a0, a1, a2); break;
        }
        if (result) rvvm_fatal("Cannot mirror shared guest VMA");
#ifdef USER_FAULT_META
        if (nr == 226) user_exec_update(a0, a1, a2 & UAPI_PROT_EXEC);
        if (nr == 215) user_exec_update(a0, a1, false);
        if (nr == 222) user_exec_update(request.result, a1, a2 & UAPI_PROT_EXEC);
#endif
    }
    if (fd >= 0) close(fd);
    user_fd_unlock();
    return request.result;
}

#ifdef RVVM_STATIC_GLIBC_FORK
struct user_vm_rpc_call {
    uint64_t nr, args[6];
    pid_t parent;
    long result;
    bool complete;
};

static int user_vm_rpc_resource(void* opaque)
{
    struct user_vm_rpc_call* call = opaque;
    *user_fork_native_tid = syscall(SYS_gettid);
    syscall(SYS_set_robust_list, user_fork_native_robust, sizeof(*user_fork_native_robust));
    syscall(SYS_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    if (getppid() != call->parent) return 127;
    if (setsid() < 0) return 127;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit)) return 127;
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &limit)) return 127;
    /* This private files table needs one slot for a received backing fd,
     * even when the guest has filled its hard limit. Closing a copied guest
     * fd here cannot release a POSIX lock owned by the guest files table. */
    int source = call->nr == 222 && !(call->args[3] & UAPI_MAP_ANON) ? (int)call->args[4] : -1;
    for (int slot = 0; (rlim_t)slot < limit.rlim_max; ++slot) {
        if (slot != source && slot != user_vm_fd && slot != (int)user_fd_table()->exe_fd) {
            close(slot);
            break;
        }
    }
    user_vm_rpc_private_files = true;
    call->result = user_vm_rpc_impl(call->nr, call->args[0], call->args[1], call->args[2],
                                  call->args[3], call->args[4], call->args[5]);
    user_vm_rpc_private_files = false;
    call->complete = true;
    return 0;
}
#endif

static long user_vm_rpc(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5)
{
#ifdef RVVM_STATIC_GLIBC_FORK
    /* Backing descriptors received over SCM_RIGHTS belong to the emulator.
     * Receive and map them in a trusted process with private files and limits,
     * sharing only this already isolated child's native memory. Guest code
     * remains in its original process with its real kernel limits unchanged. */
    const size_t size = 256 * 1024;
    void* stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) return -errno;
    struct user_vm_rpc_call call = {.nr = nr, .args = {a0, a1, a2, a3, a4, a5}, .parent = getpid()};
    uint64_t held = UINT64_MAX, saved_mask;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, &saved_mask, 8);
    int self = *user_fork_native_tid;
    rvvm_hart_t* saved_cpu = user_sig.cpu;
    rvvm_hart_t* saved_hart = current_user_hart;
    user_sig.cpu = NULL;
    current_user_hart = NULL;
    pid_t pid = clone(user_vm_rpc_resource, (char*)stack + size, CLONE_VM | CLONE_FS, &call);
    if (pid < 0) call.result = -errno;
    else {
        int status;
        pid_t waited;
        do { waited = syscall(SYS_wait4, pid, &status, __WALL | WUNTRACED, NULL); }
        while (waited < 0 && errno == EINTR);
        /* The helper can hold native allocator locks. Unexpected termination
         * must not resume guest execution in a partially updated native heap. */
        if (waited != pid || !WIFEXITED(status) || WEXITSTATUS(status) || !call.complete)
            syscall(SYS_exit_group, 127);
    }
    *user_fork_native_tid = self;
    user_sig.cpu = saved_cpu;
    current_user_hart = saved_hart;
    munmap(stack, size);
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
    return call.result;
#else
    return user_vm_rpc_impl(nr, a0, a1, a2, a3, a4, a5);
#endif
}

#endif
