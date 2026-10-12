/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#include "user_fd_guard.h"
#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "locking.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <time.h>
#include "utils.h"

static user_fd_mutex_t shared_guard;
static user_fd_guard_t* default_guard;
static THREAD_LOCAL user_fd_guard_t* selected_guard;
#define guard (*(selected_guard ? &selected_guard->lock : default_guard ? &default_guard->lock : &shared_guard))
static THREAD_LOCAL unsigned depth;
static THREAD_LOCAL uint32_t owner_tid;
static THREAD_LOCAL uint32_t owner_marker;
static THREAD_LOCAL void (*resume_table)(void);
struct user_fd_registration {
    user_fd_mutex_t* lock;
    struct robust_list_head* head;
    struct robust_list* node;
    struct robust_list* next;
};
static THREAD_LOCAL struct user_fd_registration registrations[8];
static THREAD_LOCAL unsigned registration_count;
static bool user_fd_register(user_fd_mutex_t* lock);
static void user_fd_owner_init(void);

bool user_fd_mutex_share(user_fd_mutex_t* lock)
{
    if (__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)
        && __atomic_load_n(&lock->robust_marker, __ATOMIC_ACQUIRE)) return true;
    size_t page = sysconf(_SC_PAGESIZE);
    char* memory = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) return false;
    user_fd_owner_init();
    bool held = (atomic_load_uint32(&lock->owner) & 0x7FFFFFFFU) == owner_tid;
    if (!held) user_fd_mutex_lock(lock);
    if (lock->robust_marker) {
        munmap(memory, page);
        if (!held) user_fd_mutex_unlock(lock);
        return true;
    }
    __atomic_store_n(&lock->robust_marker, (void*)(memory + page / 2), __ATOMIC_RELEASE);
    if (!__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)) {
        uint64_t mine = ((uint64_t)owner_marker << 32) | owner_tid;
        atomic_store_uint64_relax(&lock->lease, mine);
        atomic_store_uint64_relax(&lock->marker_address, (uintptr_t)&owner_marker);
        atomic_store_uint32(&lock->registered, user_fd_register(lock));
        atomic_store_uint64(&lock->published, mine);
        __atomic_store_n(&lock->shared, true, __ATOMIC_RELEASE);
        /* Switch existing waiters to the shared sequence before fork: a
         * CLONE_FILES child cannot wake its parent's private futex keys. */
        atomic_store_uint32(&lock->owner, owner_tid);
        syscall(SYS_futex, &lock->owner, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
    }
    if (!held) user_fd_mutex_unlock(lock);
    return true;
}

void user_fd_mutex_destroy(user_fd_mutex_t* lock)
{
    if (lock->robust_marker) {
        size_t page = sysconf(_SC_PAGESIZE);
        munmap((char*)lock->robust_marker - page / 2, page);
    }
}

static long user_fd_copy_self(void* local, void* remote, size_t length, bool write)
{
    struct iovec from = {local, length}, to = {remote, length};
    return syscall(write ? SYS_process_vm_writev : SYS_process_vm_readv,
                   syscall(SYS_gettid), &from, 1, &to, 1, 0);
}

/* Add a marker to the calling thread's existing kernel robust list without
 * replacing the guest head, offset or pending operation. While the emulator
 * owns its descriptor guard, this thread cannot mutate its guest list. */
static bool user_fd_register(user_fd_mutex_t* lock)
{
    if (!lock->robust_marker) return false;
    struct robust_list_head* head, snapshot;
    size_t length;
    if (syscall(SYS_get_robust_list, 0, &head, &length) || length != sizeof(snapshot)
        || user_fd_copy_self(&snapshot, head, sizeof(snapshot), false) != sizeof(snapshot)) return false;
    long offset = snapshot.futex_offset;
    long bound = sysconf(_SC_PAGESIZE) / 2 - sizeof(struct robust_list);
    /* Malformed/nonstandard guest lists retain conservative owner probing. */
    if (offset > bound || offset < -bound || (offset > -8 && offset < 8)) return false;
    assert(registration_count < 8);
    struct robust_list* node = (void*)((char*)lock->robust_marker - offset);
    node->next = snapshot.list.next;
    atomic_store_uint32(lock->robust_marker, syscall(SYS_gettid));
    if (user_fd_copy_self(&node, &head->list.next, sizeof(node), true) != sizeof(node)) return false;
    registrations[registration_count++] = (struct user_fd_registration){lock, head, node, snapshot.list.next};
    return true;
}

static void user_fd_unregister(user_fd_mutex_t* lock)
{
    if (!registration_count || registrations[registration_count - 1].lock != lock) return;
    struct user_fd_registration* entry = &registrations[--registration_count];
    /* Clear ownership before removing the node, so death during removal
     * cannot leave a marker falsely identifying a live owner. */
    atomic_store_uint32(lock->robust_marker, 0);
    if (user_fd_copy_self(&entry->next, &entry->head->list.next, sizeof(entry->next), true) != sizeof(entry->next))
        rvvm_fatal("Cannot restore robust-list descriptor marker");
}

static bool user_fd_tid_dead(uint32_t tid)
{
    if (!tid) return false;
    /* TRYLOCK_PI asks the kernel whether this TID has finished futex exit
     * cleanup, even for an unreaped zombie or an inaccessible process. The
     * scratch word has no waiters and never becomes part of our locks. */
    uint32_t probe = tid;
    long ret = syscall(SYS_futex, &probe, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
    if (!ret) syscall(SYS_futex, &probe, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return ret < 0 && errno == ESRCH;
}

static void user_fd_owner_init(void)
{
    if (owner_tid) return;
    owner_tid = syscall(SYS_gettid);
    while (!owner_marker) {
        long ret = syscall(SYS_getrandom, &owner_marker, sizeof(owner_marker), 0);
        if (ret < 0 && errno == EINTR) continue;
        if (ret != sizeof(owner_marker))
            rvvm_fatal("Cannot initialize descriptor lock owner");
    }
}

/* A private TLS marker disappears on exec and changes when a TID is reused.
 * Reading through the owner task also distinguishes an unreaped zombie from
 * a live thread. Permission failures are not evidence of owner death. */
void user_fd_owner_marker(uint64_t* address, uint32_t* value)
{
    user_fd_owner_init();
    *address = (uintptr_t)&owner_marker;
    *value = owner_marker;
}

bool user_fd_owner_dead(uint32_t tid, uint64_t address, uint32_t value)
{
    if (!tid) return false;
    if (user_fd_tid_dead(tid)) return true;
    uint32_t marker;
    struct iovec local = {&marker, sizeof(marker)};
    struct iovec remote = {(void*)(uintptr_t)address, sizeof(marker)};
    long ret = syscall(SYS_process_vm_readv, tid, &local, 1, &remote, 1, 0);
    return ret == sizeof(marker) ? marker != value
                                : ret < 0 && (errno == ESRCH || errno == EFAULT);
}

static bool user_fd_owner_gone(user_fd_mutex_t* lock, uint64_t lease)
{
    if (atomic_load_uint64(&lock->published) != lease)
        return user_fd_tid_dead((uint32_t)lease);
    if (atomic_load_uint32(&lock->registered) && lock->robust_marker) {
        uint32_t owner = atomic_load_uint32(lock->robust_marker);
        return !(owner & FUTEX_TID_MASK) && atomic_load_uint64(&lock->published) == lease
            && atomic_load_uint32(&lock->registered);
    }
    bool gone = user_fd_owner_dead((uint32_t)lease, atomic_load_uint64(&lock->marker_address), lease >> 32);
    return gone && atomic_load_uint64(&lock->published) == lease;
}

void user_fd_mutex_lock(user_fd_mutex_t* lock)
{
    int saved = errno;
    user_fd_owner_init();
retry:
    if (__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)) {
        uint64_t mine = ((uint64_t)owner_marker << 32) | owner_tid;
        for (;;) {
            uint32_t sequence = atomic_load_uint32(&lock->sequence);
            uint64_t owner = 0;
            if (atomic_cas_uint64_ex(&lock->lease, &owner, mine, false, ATOMIC_ACQUIRE, ATOMIC_RELAXED)) {
                atomic_store_uint32_relax(&lock->owner, owner_tid);
                atomic_store_uint64_relax(&lock->marker_address, (uintptr_t)&owner_marker);
                atomic_store_uint32(&lock->registered, user_fd_register(lock));
                atomic_store_uint64(&lock->published, mine);
                break;
            }
            if (user_fd_owner_gone(lock, owner)) {
                atomic_cas_uint64(&lock->lease, owner, 0);
                continue;
            }
            struct timespec delay = {.tv_nsec = 100000000};
            atomic_add_uint32(&lock->waiters, 1);
            syscall(SYS_futex, &lock->sequence, FUTEX_WAIT, sequence, &delay, NULL, 0);
            atomic_sub_uint32(&lock->waiters, 1);
        }
        errno = saved;
        return;
    }
    for (;;) {
        uint32_t owner = 0;
        if (atomic_cas_uint32_ex(&lock->owner, &owner, owner_tid, false, ATOMIC_ACQUIRE, ATOMIC_RELAXED)) {
            if (!__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)) break;
            atomic_cas_uint32(&lock->owner, owner_tid, 0);
            goto retry;
        }
        if (__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)) goto retry;
        if (!(owner & 0x80000000U)) {
            uint32_t waiting = owner | 0x80000000U;
            if (!atomic_cas_uint32_ex(&lock->owner, &owner, waiting, false, ATOMIC_RELAXED, ATOMIC_RELAXED)) continue;
            owner = waiting;
        }
        if (__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)) goto retry;
        syscall(SYS_futex, &lock->owner, FUTEX_WAIT_PRIVATE, owner, NULL, NULL, 0);
    }
    errno = saved;
}

void user_fd_mutex_unlock(user_fd_mutex_t* lock)
{
    int saved = errno;
    if (__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)) {
        atomic_store_uint32(&lock->registered, 0);
        user_fd_unregister(lock);
        uint32_t private_owner = atomic_swap_uint32_ex(&lock->owner, 0, ATOMIC_RELEASE);
        atomic_store_uint64(&lock->published, 0);
        atomic_store_uint64_ex(&lock->lease, 0, ATOMIC_RELEASE);
        atomic_add_uint32(&lock->sequence, 1);
        if (atomic_load_uint32(&lock->waiters))
            syscall(SYS_futex, &lock->sequence, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        if (private_owner & 0x80000000U)
            syscall(SYS_futex, &lock->owner, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
        errno = saved;
        return;
    }
    uint32_t owner = atomic_swap_uint32_ex(&lock->owner, 0, ATOMIC_RELEASE);
    if (owner & 0x80000000U)
        syscall(SYS_futex, &lock->owner, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
    errno = saved;
}

void user_fd_mutex_recover(user_fd_mutex_t* lock, uint32_t tid)
{
    int saved = errno;
    if (__atomic_load_n(&lock->shared, __ATOMIC_ACQUIRE)) {
        uint64_t owner = atomic_load_uint64(&lock->lease);
        if (tid && (uint32_t)owner == tid) atomic_cas_uint64(&lock->lease, owner, 0);
        atomic_add_uint32(&lock->sequence, 1);
        syscall(SYS_futex, &lock->sequence, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        errno = saved;
        return;
    }
    uint32_t owner = atomic_load_uint32_relax(&lock->owner);
    while (tid && (owner & 0x7FFFFFFFU) == tid) {
        if (atomic_cas_uint32_ex(&lock->owner, &owner, 0, false, ATOMIC_RELEASE, ATOMIC_RELAXED)) {
            if (owner & 0x80000000U)
                syscall(SYS_futex, &lock->owner, FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0);
            break;
        }
    }
    errno = saved;
}

user_fd_guard_t* user_fd_guard_init(user_fd_guard_t* state)
{
    /* Native threads and trusted CLONE_VM helpers share private futex keys.
     * A guest CLONE_FILES process promotes the guard before its host fork. */
    state->refs = calloc(1, sizeof(*state->refs));
    if (!state->refs) return NULL;
    *state->refs = 1;
    return state;
}

user_fd_guard_t* user_fd_guard_create(void)
{
    user_fd_guard_t* state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) return NULL;
    if (!user_fd_guard_init(state)) { munmap(state, sizeof(*state)); return NULL; }
    return state;
}

user_fd_guard_t* user_fd_guard_retain(user_fd_guard_t* state)
{
    if (state) atomic_add_uint32(state->refs, 1);
    return state;
}

bool user_fd_guard_put(user_fd_guard_t* state)
{
    if (state && atomic_sub_uint32(state->refs, 1) == 1) {
        user_fd_mutex_destroy(&state->lock);
        free(state->refs);
        return true;
    }
    return false;
}

void user_fd_guard_release(user_fd_guard_t* state)
{
    if (user_fd_guard_put(state)) user_fd_guard_unmap(state);
}

void user_fd_guard_unmap(user_fd_guard_t* state)
{
    if (state) munmap(state, sizeof(*state));
}

unsigned user_fd_fork_select(user_fd_guard_t* state)
{
    unsigned inherited_depth = depth;
    depth = 0;
    /* The guest head is COW even when files are shared. Remove the inherited
     * nodes from that copy without clearing the parent's shared markers.
     * libc may already have reset its native head inside _Fork. */
    while (registration_count) {
        struct user_fd_registration* entry = &registrations[--registration_count];
        struct robust_list* next;
        if (user_fd_copy_self(&next, &entry->head->list.next, sizeof(next), false) == sizeof(next)
            && next == entry->node
            && user_fd_copy_self(&entry->next, &entry->head->list.next, sizeof(entry->next), true) != sizeof(entry->next))
            rvvm_fatal("Cannot detach inherited descriptor marker");
    }
    owner_tid = 0;
    user_fd_guard_select(state);
    return inherited_depth;
}

void user_fd_guard_select(user_fd_guard_t* state)
{
    assert(state == (selected_guard ? selected_guard : default_guard) || !depth);
    selected_guard = state;
    resume_table = NULL;
}

void user_fd_guard_set_resume(void (*resume)(void)) { resume_table = resume; }
void user_fd_guard_default(user_fd_guard_t* state) { default_guard = state; }

void user_fd_lock(void)
{
    int saved = errno;
    bool outer = !depth;
    if (outer) user_fd_mutex_lock(&guard);
    depth++;
    if (outer && resume_table) resume_table();
    errno = saved;
}

void user_fd_unlock(void)
{
    int saved = errno;
    assert(depth);
    if (!--depth) user_fd_mutex_unlock(&guard);
    errno = saved;
}

void user_fd_guard_child(void) { owner_tid = 0; user_fd_owner_init(); }

void user_fd_guard_recover(uint32_t tid)
{
    user_fd_mutex_recover(&guard, tid);
    depth = 0;
    owner_tid = syscall(SYS_gettid);
}
#endif
