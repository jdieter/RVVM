/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Shared-mm children keep allocations with trusted parent workers. */
#ifndef RVVM_USER_NATIVE_VFORK_H
#define RVVM_USER_NATIVE_VFORK_H
#include "cpu/softfloat/softfloat.h"

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
extern long user_native_clone3(const void*, size_t);
#if defined(__aarch64__)
__asm__(".text\n.balign 4\n.global user_native_clone3\n.hidden user_native_clone3\n"
        "user_native_clone3:\n bti c\n mov x8,435\n svc #0\n cbnz x0,1f\n"
        " ldp x9,x0,[sp],16\n blr x9\n mov x8,93\n svc #0\n brk 0\n1: ret\n");
#elif defined(__x86_64__)
__asm__(".text\n.global user_native_clone3\n.hidden user_native_clone3\n"
        "user_native_clone3:\n endbr64\n mov $435,%eax\n syscall\n test %rax,%rax\n jnz 1f\n"
        " pop %rax\n pop %rdi\n call *%rax\n mov %eax,%edi\n mov $60,%eax\n syscall\n ud2\n1: ret\n");
#endif

static bool user_native_vfork_preflight(uint32_t flags)
{
#ifndef RVVM_STATIC_GLIBC_FORK
    if (!(flags & UAPI_CLONE_VM)) return false;
#else
    if (!(flags & UAPI_CLONE_VM) && (!user_fork_native_tid || !user_fork_native_robust)) return false;
#endif
    if (syscall(SYS_clone3, NULL, 0) != -1 || errno != EINVAL) return false;
    struct stat active_pid, child_pid;
    /* A newly entered PID namespace makes this child its init. Its death
     * forcibly kills transaction helpers; this configuration remains a parity gap for that
     * configuration, including when namespace identity cannot be verified. */
    if (fstatat(AT_FDCWD, "/proc/thread-self/ns/pid", &active_pid, 0)
        || fstatat(AT_FDCWD, "/proc/thread-self/ns/pid_for_children", &child_pid, 0)
        || active_pid.st_dev != child_pid.st_dev || active_pid.st_ino != child_pid.st_ino) return false;
#if defined(__x86_64__)
    unsigned long features = 0;
    /* The owned jump primitive does not yet restore a CET shadow stack.
     * Reject before entering shared-mm execution until that platform gap is closed. */
    long ret = syscall(SYS_arch_prctl, 0x5005, &features); // ARCH_SHSTK_STATUS
    if (!ret) return !features;
    return errno == EINVAL || errno == ENOSYS;
#else
    return true;
#endif
}

struct user_native_allocation {
    struct user_native_allocation* next;
    void* pointer;
};

struct user_native_vfork {
    struct user_native_vfork* observer_next;
    struct user_observer* observer;
    pid_t caller;
    int clone_error;
    rvvm_hart_t* cpu;
    rvvm_user_thread_t* private_thread;
    struct user_exec_reader exec_reader;
    struct user_signal_process signals;
    struct user_signal_process* source_signals;
    struct user_sigstack signal_stack;
    struct user_native_jump fault_jump;
    struct user_ptrace_context ptrace_context;
    struct user_fake_credentials credentials;
    uint64_t mask;
    int executable_fd;
    user_fd_table_t* source_table;
    user_fd_table_t* child_table;
    user_fd_owner_t child_owner;
    user_fd_context_t child_guard;
    uint32_t clone_ready, clone_pid, child_ready, child_registered;
    uint32_t* clone_marker;
    uint32_t service_state, service_stop;
    uint32_t operation, helper_pid, helper_alive, helper_state, helper_ready;
    long mapping_nr, mapping_args[6], mapping_result;
    long kernel_nr, kernel_args[6], kernel_result;
    char helper_stack[65536] __attribute__((aligned(16)));
    size_t allocation_size;
    void* allocation_pointer;
    struct user_native_allocation* allocations;
    char path[4096], descriptor[64], marker[64];
};

#ifdef RVVM_STATIC_GLIBC_FORK
extern void __malloc_fork_lock_parent(void);
extern void __malloc_fork_unlock_parent(void);
extern void __malloc_fork_unlock_child(void);
extern void _IO_list_lock(void);
extern void _IO_list_unlock(void);
extern void _IO_list_resetlock(void);

static void user_native_cow_snapshot_lock(void)
{
    spin_lock(&brk_lock);
    spin_lock(&mmap_lock);
    user_fd_mutex_lock(&user_exe_lock);
    user_fd_mutex_lock(&user_reaper_lock);
    rvvm_user_fork_lock();
    _IO_list_lock();
    __malloc_fork_lock_parent();
}

static void user_native_cow_snapshot_unlock(void)
{
    __malloc_fork_unlock_parent();
    _IO_list_unlock();
    rvvm_user_fork_unlock();
    user_fd_mutex_unlock(&user_reaper_lock);
    user_fd_mutex_unlock(&user_exe_lock);
    spin_unlock(&mmap_lock);
    spin_unlock(&brk_lock);
}

static int user_native_cow_child(void* opaque)
{
    struct user_native_vfork* request = opaque;
    if (request->observer) {
        volatile sig_atomic_t pending = 0;
        atomic_store_uint32(request->clone_marker, user_safe_raw(&pending, SYS_gettid, 0, 0, 0, 0, 0, 0));
    }
    /* Snapshot locks belong to vanished parent threads in this private mm.
     * Unlock allocator state first, then let libc reset FILE/loader/NPTL
     * state through its ordinary child recovery. */
    __malloc_fork_unlock_child();
    _IO_list_resetlock();
    user_fork_recover_cow = true;
    if (fork() != 0) _exit(127);
    user_fake_default = request->credentials;
    user_fake_current = NULL;
    rvvm_user_thread_t* thread = request->private_thread;
    user_fd_fork_select(request->child_table->guard);
    user_fd_guard_default(request->child_table->guard);
    user_fd_current = request->child_table;
    user_fd_owner_override = NULL;
    user_fd_initial = request->child_table;
    user_fd_table_fork_child();
    user_reap_threads = NULL;
    user_reaper_running = false;
    user_thread_lifetime = 1;
    user_reaper_tid = 0;
    rvvm_user_fork_child(request->cpu);
    rvvm_user_fork_unlock();
    user_reaper_lock = (user_fd_mutex_t){0};
    user_exe_lock = (user_fd_mutex_t){0};
    user_exec_fork_child();
    user_observer_fork_child();
    user_exe_process_link_init(false);
    spin_unlock(&mmap_lock);
    spin_unlock(&brk_lock);
    spin_unlock(&request->source_signals->lock);
    user_native_child_active = false;
    user_native_fault_target = NULL;
    thread->signals = malloc(sizeof(*thread->signals));
    if (!thread->signals) _exit(127);
    *thread->signals = request->signals;
    thread->signals->refs = 1;
    thread->fd_table = request->child_table;
    user_ptrace_fork(request->cpu);
    user_ptrace_set_exe_fd_pointer(&request->child_table->exe_fd);
    user_ptrace_process_init(request->cpu, &thread->signal_mask, &user_sig.pending,
                             request->ptrace_context.bridge);
    rvvm_user_thread_wrap(thread);
    _exit(127);
}
#endif

static long user_native_raw(long nr, long a, long b, long c, long d, long e, long f)
{
    /* No errno mutation, libc cancellation points, or shared libc locks. */
    volatile sig_atomic_t pending = 0;
    long ret = user_safe_raw(user_native_child_active ? &user_sig.pending : &pending,
                            nr, a, b, c, d, e, f);
    if (ret == -512 && user_native_child_active) {
        user_sig.syscall_unstarted = true;
        return -EINTR;
    }
    return ret;
}

static __attribute__((no_stack_protector)) long user_native_internal(long nr, long a, long b, long c, long d, long e, long f)
{
    volatile sig_atomic_t pending = 0;
    long ret;
    do { ret = user_safe_raw(&pending, nr, a, b, c, d, e, f); } while (ret == -512);
    return ret;
}

#include "rvvm_user_observer.h"

static rvvm_addr_t rvvm_sys_mmap(void*, size_t, int, int, int, uint64_t);
static int rvvm_sys_munmap(void*, size_t);
static int rvvm_sys_prot(int);
static THREAD_LOCAL struct user_native_vfork* user_native_mapping_request;

/* This process has the guest child's current kernel credentials, limits and
 * shared files/mm. It never uses native TLS, libc allocation or shared locks.
 * Guest death therefore cannot interrupt trusted parent bookkeeping. */
static __attribute__((no_stack_protector)) int user_native_mapping_helper(void* opaque)
{
    struct user_native_vfork* request = opaque;
    uint64_t mask = UINT64_MAX;
    user_native_internal(SYS_rt_sigprocmask, SIG_SETMASK, (long)&mask, 0, 8, 0, 0);
    if (user_native_internal(SYS_setsid, 0, 0, 0, 0, 0, 0) < 0) return 127;
    atomic_store_uint32(&request->helper_ready, 1);
    user_native_internal(SYS_futex, (long)&request->helper_ready, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0);
    for (;;) {
        uint32_t state = atomic_load_uint32(&request->helper_state);
        if (state == 3) return 0;
        if (state != 1) {
            user_native_internal(SYS_futex, (long)&request->helper_state, FUTEX_WAIT_PRIVATE, state, 0, 0, 0);
            continue;
        }
        long* a = request->kernel_args;
        request->kernel_result = user_native_internal(request->kernel_nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        atomic_store_uint32(&request->helper_state, 2);
        user_native_internal(SYS_futex, (long)&request->helper_state, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    }
}

static long user_native_mapping_kernel(long nr, long a, long b, long c, long d, long e, long f)
{
    struct user_native_vfork* request = user_native_mapping_request;
    request->kernel_nr = nr;
    long args[] = {a, b, c, d, e, f};
    memcpy(request->kernel_args, args, sizeof(args));
    atomic_store_uint32(&request->helper_state, 1);
    rvvm_futex_wake(&request->helper_state, 1);
    while (atomic_load_uint32(&request->helper_state) != 2) {
        /* A killed helper may have committed the mutation before publication.
         * There is no safe replay of MAP_FIXED. Match the old fail-closed
         * transaction policy rather than continuing with unknown metadata. */
        if (!atomic_load_uint32(&request->helper_alive)) {
            syscall(SYS_kill, request->child_owner.tid, SIGKILL);
            syscall(SYS_exit_group, 127);
        }
        rvvm_futex_wait(&request->helper_state, 1, 10000000);
    }
    long ret = request->kernel_result;
    atomic_store_uint32(&request->helper_state, 0);
    return ret;
}

static void user_native_mapping_finish(struct user_native_vfork* request)
{
    if (!atomic_load_uint32(&request->helper_pid)) {
        atomic_store_uint32(&request->helper_alive, 0);
        return;
    }
    atomic_store_uint32(&request->helper_state, 3);
    rvvm_futex_wake(&request->helper_state, 1);
    syscall(SYS_kill, atomic_load_uint32(&request->helper_pid), SIGCONT);
    struct timespec timeout = {.tv_nsec = 10000000};
    while (atomic_load_uint32(&request->helper_alive))
        syscall(SYS_futex, &request->helper_alive, FUTEX_WAIT,
                atomic_load_uint32(&request->helper_alive), &timeout, NULL, 0);
}

static void user_native_mapping_service(struct user_native_vfork* request)
{
    user_fd_context_t guard;
    user_fd_context_save(&guard);
    user_fd_current = request->child_table;
    user_fd_guard_select(request->child_table->guard);
    user_native_mapping_request = request;
    user_vma_executor = user_native_mapping_kernel;
    long* a = request->mapping_args;
    switch (request->mapping_nr) {
        case 214: request->mapping_result = (long)rvvm_sys_brk((void*)a[0]); break;
        case 215: request->mapping_result = rvvm_sys_munmap((void*)a[0], a[1]); break;
        case 216: request->mapping_result = user_mremap(a[0], a[1], a[2], a[3], a[4]); break;
        case 222: request->mapping_result = rvvm_sys_mmap((void*)a[0], a[1], a[2], a[3], a[4], a[5]); break;
        case 226: {
            user_fd_lock();
            spin_lock(&mmap_lock);
            uintptr_t start = a[0]; size_t size = a[1];
            request->mapping_result = !user_exec_reserve(2) ? -ENOMEM
                : user_vma_protect_span(&start, &size, a[2]) ? -errno
                : user_native_mapping_kernel(SYS_mprotect, a[0], a[1], rvvm_sys_prot(a[2]), 0, 0, 0);
            if (!request->mapping_result) user_exec_update(start, size, a[2] & PROT_EXEC);
            spin_unlock(&mmap_lock);
            user_fd_unlock();
            break;
        }
        case 233: request->mapping_result = user_native_mapping_kernel(SYS_madvise, a[0], a[1], a[2], 0, 0, 0); break;
        default: request->mapping_result = -ENOSYS;
    }
    user_vma_executor = NULL;
    user_native_mapping_request = NULL;
    user_fd_current = request->source_table;
    user_fd_context_load(&guard);
    user_native_mapping_finish(request);
}

static void* user_native_service(void* opaque)
{
    struct user_native_vfork* request = opaque;
    if (request->observer) user_fd_mutex_lock(&request->observer->lock);
    user_signal_process = request->source_signals;
    /* This thread owns its TLS and the source guard. The kernel's private
     * files snapshot must agree with the private descriptor metadata, but
     * parent peers must resume as soon as that snapshot has been taken. */
    user_fd_table_enter(request->source_table);
    user_fd_lock();
    request->child_table = user_fd_table_copy_guard(request->source_table, true);
    if (request->child_table) {
        uint64_t address;
        user_fd_owner_marker(&address, &request->child_guard.marker);
        request->child_guard.selected = request->child_table->guard;
        request->ptrace_context.executable_fd = &request->child_table->exe_fd;
    }
    request->executable_fd = user_exe_fd;
    spin_lock(&user_action_lock);
    memcpy(request->signals.actions, user_actions, sizeof(request->signals.actions));
    memcpy(request->signals.private_installed, user_private_installed,
           sizeof(request->signals.private_installed));
#ifdef RVVM_STATIC_GLIBC_FORK
    if (request->private_thread) user_native_cow_snapshot_lock();
#endif
    if (!request->private_thread) spin_lock(&mmap_lock);
    request->observer_next = user_native_requests;
    user_native_requests = request;
    if (request->observer) {
        request->observer->request = request;
        request->observer->caller = request->caller;
        request->clone_error = user_observer_call(request->observer, 1);
    }
    atomic_store_uint32(&request->clone_ready, 1);
    rvvm_futex_wake(&request->clone_ready, 1);
    while (!atomic_load_uint32(request->clone_marker)
           && !atomic_load_uint32(&request->service_stop)) {
        if (request->observer && !request->clone_error) {
            long result = user_observer_call(request->observer, 2);
            if (result > 0) atomic_store_uint32(request->clone_marker, result);
            else if (result < 0) request->clone_error = result;
        }
        rvvm_futex_wait(&request->child_ready, 0, 1000000);
    }
    if (request->observer) {
        user_observer_call(request->observer, 3);
        request->observer->request = NULL;
        user_fd_mutex_unlock(&request->observer->lock);
    }
    if (!request->private_thread) spin_unlock(&mmap_lock);
#ifdef RVVM_STATIC_GLIBC_FORK
    if (request->private_thread) user_native_cow_snapshot_unlock();
#endif
    spin_unlock(&user_action_lock);
    user_fd_unlock();
    if (!request->private_thread && atomic_load_uint32(request->clone_marker)) {
        user_fd_mutex_lock(&user_fd_owners_lock);
        request->child_owner.tid = atomic_load_uint32(request->clone_marker);
        request->child_guard.tid = request->child_owner.tid;
        request->child_owner.table = request->child_table;
        request->child_owner.next = user_fd_owners;
        user_fd_owners = &request->child_owner;
        user_fd_mutex_unlock(&user_fd_owners_lock);
        atomic_store_uint32(&request->child_registered, 1);
        rvvm_futex_wake(&request->child_registered, 1);
    }
    for (;;) {
        uint32_t state = atomic_load_uint32(&request->service_state);
        if (atomic_load_uint32(&request->service_stop)) {
            if (request->operation == 2 || request->operation == 5) user_native_mapping_finish(request);
            break;
        }
        if (state != 1) {
            rvvm_futex_wait(&request->service_state, state, RVVM_FUTEX_INFINITE);
            continue;
        }
        if (request->operation == 2) {
            user_native_mapping_service(request);
            atomic_store_uint32(&request->service_state, 2);
            rvvm_futex_wake(&request->service_state, 1);
            continue;
        }
        if (request->operation == 5) {
            spin_lock(&mmap_lock);
            atomic_store_uint32(&request->service_state, 2);
            rvvm_futex_wake(&request->service_state, 1);
            while (!atomic_load_uint32(&request->helper_pid)
                   && atomic_load_uint32(&request->helper_alive)
                   && !atomic_load_uint32(&request->service_stop))
                rvvm_futex_wait(&request->helper_ready, 0, 1000000);
            spin_unlock(&mmap_lock);
            continue;
        }
        if (request->operation == 3) {
            rvvm_flush_icache(userland, request->mapping_args[0],
                              request->mapping_args[1] - request->mapping_args[0]);
            atomic_store_uint32(&request->service_state, 2);
            rvvm_futex_wake(&request->service_state, 1);
            continue;
        }
        void* result = NULL;
        if (request->allocation_size) {
            struct user_native_allocation* node = malloc(sizeof(*node));
            if (node) {
                result = malloc(request->allocation_size);
                if (result) {
                    *node = (struct user_native_allocation){request->allocations, result};
                    request->allocations = node;
                } else free(node);
            }
        } else {
            struct user_native_allocation** link = &request->allocations;
            while (*link) {
                struct user_native_allocation* node = *link;
                if (node->pointer != request->allocation_pointer) { link = &node->next; continue; }
                *link = node->next;
                free(node->pointer);
                free(node);
                break;
            }
        }
        request->allocation_pointer = result;
        atomic_store_uint32(&request->service_state, 2);
        rvvm_futex_wake(&request->service_state, 1);
    }
    while (request->allocations) {
        struct user_native_allocation* node = request->allocations;
        request->allocations = node->next;
        free(node->pointer);
        free(node);
    }
    if (atomic_load_uint32(&request->child_registered)) {
        user_fd_mutex_lock(&user_fd_owners_lock);
        user_fd_owner_t** link = &user_fd_owners;
        while (*link && *link != &request->child_owner) link = &(*link)->next;
        if (*link) *link = request->child_owner.next;
        user_fd_mutex_unlock(&user_fd_owners_lock);
    }
    spin_lock(&mmap_lock);
    struct user_native_vfork** link = &user_native_requests;
    while (*link && *link != request) link = &(*link)->observer_next;
    if (*link) *link = request->observer_next;
    spin_unlock(&mmap_lock);
    user_fd_table_leave();
    return NULL;
}

static void* user_native_allocate(struct user_native_vfork* request, size_t size, void* release)
{
    request->operation = 1;
    request->allocation_size = size;
    request->allocation_pointer = release;
    atomic_store_uint32(&request->service_state, 1);
    user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    while (atomic_load_uint32(&request->service_state) != 2)
        user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAIT_PRIVATE, 1, 0, 0, 0);
    void* pointer = request->allocation_pointer;
    atomic_store_uint32(&request->service_state, 0);
    return pointer;
}

static void* user_native_ptrace_allocate(void* opaque, size_t size, void* release)
{
    return user_native_allocate(opaque, size, release);
}

static long user_native_mapping(struct user_native_vfork* request, long nr, long args[6])
{
    request->mapping_nr = nr;
    memcpy(request->mapping_args, args, sizeof(request->mapping_args));
    atomic_store_uint32(&request->helper_pid, 0);
    atomic_store_uint32(&request->helper_alive, UINT32_MAX);
    atomic_store_uint32(&request->helper_state, 0);
    atomic_store_uint32(&request->helper_ready, 0);
    request->operation = 5;
    atomic_store_uint32(&request->service_state, 1);
    user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    while (atomic_load_uint32(&request->service_state) != 2)
        user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAIT_PRIVATE, 1, 0, 0, 0);
    uint64_t all = UINT64_MAX, saved_mask;
    user_native_internal(SYS_rt_sigprocmask, SIG_SETMASK, (long)&all, (long)&saved_mask, 8, 0, 0);
    int pid = clone(user_native_mapping_helper, request->helper_stack + sizeof(request->helper_stack),
                    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_PARENT_SETTID
                    | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID, request,
                    &request->helper_pid, NULL, &request->helper_alive);
    if (pid < 0) {
        int error = errno;
        atomic_store_uint32(&request->helper_alive, 0);
        atomic_store_uint32(&request->service_state, 0);
        user_native_internal(SYS_futex, (long)&request->helper_ready, FUTEX_WAKE_PRIVATE, INT_MAX, 0, 0, 0);
        user_native_internal(SYS_rt_sigprocmask, SIG_SETMASK, (long)&saved_mask, 0, 8, 0, 0);
        return -error;
    }
    while (!atomic_load_uint32(&request->helper_ready)) {
        if (!atomic_load_uint32(&request->helper_alive)) {
            user_native_internal(SYS_rt_sigprocmask, SIG_SETMASK, (long)&saved_mask, 0, 8, 0, 0);
            int status;
            user_native_internal(SYS_wait4, pid, (long)&status, __WALL, 0, 0, 0);
            return -EIO;
        }
        struct timespec timeout = {.tv_nsec = 10000000};
        user_native_internal(SYS_futex, (long)&request->helper_ready, FUTEX_WAIT_PRIVATE, 0, (long)&timeout, 0, 0);
    }
    user_native_internal(SYS_rt_sigprocmask, SIG_SETMASK, (long)&saved_mask, 0, 8, 0, 0);
    request->operation = 2;
    atomic_store_uint32(&request->service_state, 1);
    user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    while (atomic_load_uint32(&request->service_state) != 2)
        user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAIT_PRIVATE, 1, 0, 0, 0);
    long ret = request->mapping_result;
    atomic_store_uint32(&request->service_state, 0);
    int status;
    user_native_internal(SYS_wait4, pid, (long)&status, __WALL, 0, 0, 0);
    request->operation = 1;
    return ret;
}

static long user_native_environment(struct user_native_vfork* request, char** env, char*** result)
{
    size_t count = 0, limit = (size_t)sysconf(_SC_ARG_MAX) / sizeof(char*);
    char* entry;
    if (env) for (;;) {
        if (count >= limit) return -E2BIG;
        if (user_memory_copy(&entry, env + count, sizeof(entry))) return -EFAULT;
        if (!entry) break;
        ++count;
    }
    char** next = user_native_allocate(request, (count + 2) * sizeof(*next), NULL);
    if (!next) return -ENOMEM;
    if (count && user_memory_copy(next + 1, env, count * sizeof(*next))) {
        user_native_allocate(request, 0, next);
        return -EFAULT;
    }
    next[0] = request->marker;
    next[count + 1] = NULL;
    *result = next;
    return 0;
}

static void user_native_descriptor(struct user_native_vfork* request, int fd, bool pin)
{
    /* Formatting stays in a private bounded buffer; no stdio/libc locks. */
    const char* prefix = "/proc/thread-self/fd/";
    size_t n = 0;
    while (*prefix) request->descriptor[n++] = *prefix++;
    char digits[16]; size_t count = 0;
    unsigned value = fd;
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) request->descriptor[n++] = digits[--count];
    request->descriptor[n] = 0;
    prefix = pin ? "RVVM_USER_EXEPIN=" : "RVVM_USER_EXECFD=";
    n = 0;
    while (*prefix) request->marker[n++] = *prefix++;
    value = fd; count = 0;
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) request->marker[n++] = digits[--count];
    request->marker[n] = 0;
}

static long user_native_exec(struct user_native_vfork* request, long nr, long a[6])
{
    const char* path = (void*)(nr == 221 ? a[0] : a[1]);
    char** argv = (void*)(nr == 221 ? a[1] : a[2]);
    char** env = (void*)(nr == 221 ? a[2] : a[3]);
    if (nr == 221 && !user_binfmt_executable && !getenv("RVVM_USER_BINFMT"))
        return user_exec_interpreter(path, argv, env);
    long copied = user_path_copy(request->path, path, sizeof(request->path));
    if (copied < 0) return copied;
    bool self = nr == 221 && (!strcmp(request->path, "/proc/self/exe")
                              || !strcmp(request->path, "/proc/thread-self/exe"));
    if (!self) {
        long ret = user_native_raw(nr == 221 ? SYS_execve : SYS_execveat,
                                  a[0], a[1], a[2], a[3], a[4], a[5]);
        if (nr == 221 || ret != -ENOENT || (int)a[0] == AT_FDCWD
            || request->path[0] == '/' || a[4] & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)) return ret;
        long flags = user_native_raw(SYS_fcntl, a[0], F_GETFD, 0, 0, 0, 0);
        if (flags < 0 || !(flags & FD_CLOEXEC)) return ret;
        /* Preserve the intentional CLOEXEC-script ENOENT. */
        user_native_descriptor(request, a[0], false);
        long reader = user_native_raw(SYS_openat, AT_FDCWD, (long)request->descriptor,
                                      O_RDONLY | O_CLOEXEC, 0, 0, 0);
        if (reader < 0) return ret;
        unsigned char header[20];
        long n = user_native_raw(SYS_pread64, reader, (long)header, sizeof(header), 0, 0, 0);
        user_native_raw(SYS_close, reader, 0, 0, 0, 0, 0);
        if (n != sizeof(header) || memcmp(header, "\177ELF\2\1\1", 7)
            || header[18] != 243 || header[19]) return ret;
    }
    int fd = self ? request->executable_fd : a[0];
    user_native_descriptor(request, fd, self);
    char** next;
    long ret = user_native_environment(request, env, &next);
    if (ret) return ret;
    long saved = user_native_raw(SYS_fcntl, fd, F_GETFD, 0, 0, 0, 0);
    if (saved < 0) ret = saved;
    else if ((ret = user_native_raw(SYS_fcntl, fd, F_SETFD, saved & ~FD_CLOEXEC, 0, 0, 0)) == 0) {
        ret = self ? user_native_raw(SYS_execve, (long)request->descriptor, (long)argv, (long)next, 0, 0, 0)
                   : user_native_raw(SYS_execveat, fd, (long)request->path, (long)argv, (long)next, a[4], 0);
        user_native_raw(SYS_fcntl, fd, F_SETFD, saved, 0, 0, 0);
    }
    user_native_allocate(request, 0, next);
    return ret;
}

#define NATIVE_RAW(n) user_native_raw(SYS_##n, a[0], a[1], a[2], a[3], a[4], a[5])
static long user_native_dup3(struct user_native_vfork* request, int oldfd, int newfd, unsigned flags)
{
    if (oldfd == newfd || (flags & ~O_CLOEXEC)) return -EINVAL;
    if (oldfd >= 0 && oldfd == request->executable_fd) return -EBADF;
    if (newfd < 0 || newfd != request->executable_fd)
        return user_native_raw(SYS_dup3, oldfd, newfd, flags, 0, 0, 0);
    struct rlimit limit;
    if (user_native_raw(SYS_fcntl, oldfd, F_GETFD, 0, 0, 0, 0) < 0
        || user_native_raw(SYS_prlimit64, 0, RLIMIT_NOFILE, 0, (long)&limit, 0, 0) < 0
        || (unsigned)newfd >= limit.rlim_cur) return -EBADF;
    long moved = user_native_raw(SYS_fcntl, newfd, F_DUPFD_CLOEXEC, 0, 0, 0, 0);
    if (moved < 0) return moved;
    long ret = user_native_raw(SYS_dup3, oldfd, newfd, flags, 0, 0, 0);
    if (ret < 0) user_native_internal(SYS_close, moved, 0, 0, 0, 0, 0);
    else if (newfd == request->executable_fd) {
        request->executable_fd = moved;
        atomic_store_uint32_relax(&request->child_table->exe_fd, moved);
    }
    return ret;
}

static long user_native_close_range(struct user_native_vfork* request, unsigned first,
                                    unsigned last, unsigned flags)
{
    if (first > last || (flags & ~6U)) return -EINVAL;
    unsigned pin = request->executable_fd;
    if (pin >= first && pin <= last && pin != UINT32_MAX) {
        if (first < pin) {
            long ret = user_native_raw(SYS_close_range, first, pin - 1, flags, 0, 0, 0);
            if (ret) return ret;
            flags &= ~2U;
        }
        first = pin + 1;
    }
    return first <= last ? user_native_raw(SYS_close_range, first, last, flags, 0, 0, 0) : 0;
}

static long user_native_dispatch(struct user_native_vfork* request, long nr, long a[6])
{
    if (nr == 128) return user_ptrace_restart_syscall();
    if (nr == 259) {
        request->mapping_args[0] = a[0];
        request->mapping_args[1] = a[1];
        request->operation = 3;
        atomic_store_uint32(&request->service_state, 1);
        user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
        while (atomic_load_uint32(&request->service_state) != 2)
            user_native_internal(SYS_futex, (long)&request->service_state, FUTEX_WAIT_PRIVATE, 1, 0, 0, 0);
        atomic_store_uint32(&request->service_state, 0);
        return 0;
    }
    if (nr == 214 || nr == 215 || nr == 216 || nr == 222 || nr == 226 || nr == 233) {
        user_exe_filter_args(nr, a);
        return user_native_mapping(request, nr, a);
    }
    if (nr == 24) return user_native_dup3(request, a[0], a[1], uapi_open_flags_to_host(a[2]));
    user_exe_filter_args(nr, a);
    long result;
    if (user_kernel_dispatch(request->cpu, nr, a, &result)) return result;
    switch (nr) {
        case 23: return NATIVE_RAW(dup);
        case 25: {
            if ((int)a[1] == F_SETFL) a[2] = uapi_open_flags_to_host(a[2]);
            long ret = NATIVE_RAW(fcntl);
            return (int)a[1] == F_GETFL && ret >= 0 ? uapi_open_flags_to_guest(ret) : ret;
        }
        case 57: return NATIVE_RAW(close);
        case 61: return NATIVE_RAW(getdents64);
        case 93: case 94: user_ptrace_exit(request->cpu); return NATIVE_RAW(exit_group);
        case 96: return NATIVE_RAW(set_tid_address);
        case 139: user_rt_sigreturn(request->cpu); return 0;
        case 221: case 281: return user_native_exec(request, nr, a);
        case 436: return user_native_close_range(request, a[0], a[1], a[2]);
        default: return -ENOSYS;
    }
}
#undef NATIVE_RAW

static int user_native_child(void* opaque)
{
    struct user_native_vfork* request = opaque;
    if (request->observer)
        atomic_store_uint32(request->clone_marker, user_native_internal(SYS_gettid, 0, 0, 0, 0, 0, 0));
    user_fake_current = &request->credentials;
    atomic_store_uint32(&request->child_ready, 1);
    user_native_internal(SYS_futex, (long)&request->child_ready, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    while (!atomic_load_uint32(&request->child_registered))
        user_native_internal(SYS_futex, (long)&request->child_registered, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    user_fd_context_load(&request->child_guard);
    user_fd_current = request->child_table;
    user_fd_owner_override = &request->child_owner;
    rvvm_hart_t* cpu = request->cpu;
    current_user_hart = cpu;
    user_native_child_active = true;
    user_native_exec_reader = &request->exec_reader;
    user_signal_process = &request->signals;
    memset(&user_sig, 0, sizeof(user_sig));
    user_sig.cpu = cpu;
    user_sig.stack = request->signal_stack;
    user_native_fault_target = &request->fault_jump;
    user_sig.mask = request->mask;
    user_exe_process_link_init(true);
    user_runtime_allocator = (__typeof__(user_runtime_allocator)){
        user_native_ptrace_allocate, request,
    };
    user_ptrace_context_load(&request->ptrace_context);
    user_ptrace_process_init(cpu, &user_sig.mask, &user_sig.pending, request->ptrace_context.bridge);
    user_ptrace_restart = (__typeof__(user_ptrace_restart)){0};
    user_apply_mask();
    /* Do not let inherited native robust-list cleanup traverse parent locks. */
    user_native_raw(SYS_set_robust_list, 0, 24, 0, 0, 0, 0);
    for (;;) {
#ifdef USER_FAULT_POC
        if (user_native_jump_save(&request->fault_jump)) {
            user_fault_armed = 0;
            user_fault_restore_fenv();
            cpu->user_fault_interpreted = 0;
            cpu->lrsc = false;
            rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, cpu->user_fault_pc);
            user_fault_address(cpu);
        }
#endif
        user_ptrace_checkpoint(cpu);
        user_ptrace_pending_signal(cpu);
        user_signal_deliver(cpu);
#ifdef USER_FAULT_POC
        user_fault_armed = 1;
#endif
        rvvm_addr_t cause = user_ptrace_run(cpu);
#ifdef USER_FAULT_POC
        user_fault_armed = 0;
#endif
        if (cause == (rvvm_addr_t)-1 && !atomic_load_uint32(&cpu->user_signal_pending)) continue;
        if (cause == (rvvm_addr_t)-1) continue;
        if (cause != 8) {
            if (cause == 3 && user_ptrace_break(cpu)) continue;
            user_ptrace_guest_fault();
            user_sig.pending = cause == 2 ? SIGILL : SIGSEGV;
            user_sig.synchronous = true;
            continue;
        }
        user_ptrace_dispatch();
        if (user_sig.pending) continue;
        if (user_ptrace_syscall_begin(cpu)) { user_ptrace_syscall_end(cpu); continue; }
        user_ptrace_restart_prepare(cpu);
        long a[6];
        for (size_t i = 0; i < 6; ++i) a[i] = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10 + i);
        long nr = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 17);
        user_sig.syscall_unstarted = false;
        long result = user_native_dispatch(request, nr, a);
        if (nr == 139) { user_ptrace_syscall_end(cpu); continue; }
        if (result == -EINTR && user_ptrace_interrupted()) continue;
        if (user_ptrace_interrupt_syscall(cpu, nr, result)) continue;
        if (result == -EINTR && user_sig.pending
            && (user_sig.syscall_unstarted || (user_restart_syscall(cpu, nr)
                && (request->signals.actions[user_sig.pending].flags & SA_RESTART)))) continue;
        rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 10, result);
        rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, rvvm_read_cpu_reg(cpu, RVVM_REGID_PC) + 4);
        user_ptrace_syscall_end(cpu);
    }
    __builtin_unreachable();
}

static int user_native_vfork(rvvm_user_thread_t* current, uint32_t flags, size_t guest_stack,
                             uint32_t* parent_tid, size_t tls, uint32_t* child_tid)
{
    flags &= ~UAPI_CLONE_IGNORED_FLAGS;
    const uint32_t allowed = 0xff | UAPI_CLONE_OPTIONAL_FLAGS | UAPI_CLONE_VM | UAPI_CLONE_VFORK | UAPI_CLONE_PIDFD;
    if ((flags & ~allowed)
        || ((flags & UAPI_CLONE_PIDFD) && (flags & UAPI_CLONE_PARENT_SETTID))) return -EINVAL;
    if (!user_native_vfork_preflight(flags)) return -EOPNOTSUPP;
    struct user_native_vfork* request = calloc(1, sizeof(*request));
    if (!request) return -ENOMEM;
    request->caller = gettid();
    if ((flags & UAPI_CLONE_PARENT_SETTID)
        && (flags & (UAPI_CLONE_CHILD_SETTID | UAPI_CLONE_CHILD_CLEARTID))) {
        request->observer = user_observer_get();
        if (!request->observer) { int error = errno; free(request); return -error; }
    }
    request->clone_marker = &request->clone_pid;
    request->credentials = (struct user_fake_credentials){fake_uid, fake_gid};
    request->cpu = user_clone_cpu_mode(current->cpu, true);
    if (!request->cpu) { free(request); return -ENOMEM; }
    struct user_ptrace_context saved_ptrace;
    user_ptrace_context_save(&saved_ptrace);
    __typeof__(user_ptrace_restart) saved_restart = user_ptrace_restart;
    __typeof__(user_runtime_allocator) saved_allocator = user_runtime_allocator;
    struct stat saved_exe_link = user_fork_exe_link;
    bool saved_exe_link_ready = user_fork_exe_link_ready;
    request->ptrace_context.bridge = user_ptrace_prepare(request->cpu, user_cpu_auxv,
        user_cpu_auxv_size, user_sig.mask);
    if (!request->ptrace_context.bridge) {
        rvvm_free_user_thread(request->cpu); free(request); return -ENOMEM;
    }
    if (flags & UAPI_CLONE_VM) {
        request->ptrace_context.events = user_ptrace_events_context_new();
        if (!request->ptrace_context.events) {
            user_ptrace_cancel(request->ptrace_context.bridge);
            rvvm_free_user_thread(request->cpu); free(request); return -ENOMEM;
        }
        user_ptrace_events_context_allocator(request->ptrace_context.events, user_native_ptrace_allocate, request);
        request->ptrace_context.replay.allocate = user_native_ptrace_allocate;
        request->ptrace_context.replay.opaque = request;
        request->ptrace_context.replay.records = user_ptrace_replay_records_new(user_native_ptrace_allocate, request);
        if (!request->ptrace_context.replay.records) {
            user_ptrace_events_context_free(request->ptrace_context.events);
            user_ptrace_cancel(request->ptrace_context.bridge);
            rvvm_free_user_thread(request->cpu); free(request); return -ENOMEM;
        }
    }
    if (!(flags & UAPI_CLONE_VM)) {
        request->private_thread = calloc(1, sizeof(*request->private_thread));
        if (!request->private_thread) {
            user_ptrace_cancel(request->ptrace_context.bridge);
            rvvm_free_user_thread(request->cpu); free(request); return -ENOMEM;
        }
        *request->private_thread = (rvvm_user_thread_t){
            .cpu = request->cpu, .refs = 1, .process_thread = true,
            .signal_mask = user_sig.mask, .inherit_signal_stack = true,
            .signal_stack = user_sig.stack,
            .child_settid = flags & UAPI_CLONE_CHILD_SETTID ? child_tid : NULL,
            .child_cleartid = flags & UAPI_CLONE_CHILD_CLEARTID ? child_tid : NULL,
            .ptrace_state = request->ptrace_context.bridge,
        };
    }
    bool executable_ready = user_exec_native_enter(&request->exec_reader);
    const size_t stack_size = 1024 * 1024;
    void* native_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    size_t marker_size = user_vma_page();
    void* marker = flags & UAPI_CLONE_PARENT_SETTID
        ? mmap(NULL, marker_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0) : NULL;
    if (marker && marker != MAP_FAILED) request->clone_marker = marker;
    int result = -ENOMEM;
    if (native_stack != MAP_FAILED && marker != MAP_FAILED && executable_ready) {
        request->mask = user_sig.mask;
        request->signal_stack = user_sig.stack;
        request->source_table = user_fd_table_retain();
        request->source_signals = user_signal_process_current();
        if (guest_stack) rvvm_write_cpu_reg(request->cpu, RVVM_REGID_X0 + 2, guest_stack);
        if (flags & UAPI_CLONE_SETTLS) rvvm_write_cpu_reg(request->cpu, RVVM_REGID_X0 + 4, tls);
        /* The real calling thread cannot touch this TLS until kernel VFORK
         * release. Restore even after child SIGKILL; no child lock cleanup. */
        __typeof__(user_sig) saved_signal = user_sig;
        struct user_signal_process* saved_process = user_signal_process;
        rvvm_hart_t* saved_cpu = current_user_hart;
        struct user_native_jump* saved_target = user_native_fault_target;
        user_fd_context_t saved_guard;
        user_fd_context_save(&saved_guard);
        user_fd_table_t* saved_table = user_fd_current;
        user_fd_owner_t* saved_owner = user_fd_owner_override;
        struct user_fake_credentials* saved_credentials = user_fake_current;
        uint_fast8_t saved_rounding = softfloat_roundingMode;
        uint_fast8_t saved_tininess = softfloat_detectTininess;
        uint_fast8_t saved_exceptions = softfloat_exceptionFlags;
#ifdef USER_FAULT_POC
        sigjmp_buf saved_fault;
        memcpy(saved_fault, user_fault_resume, sizeof(saved_fault));
        sig_atomic_t saved_armed = user_fault_armed;
        uint32_t saved_control = user_fault_fp_control;
#if defined(__aarch64__)
        uint32_t saved_status = user_fault_fp_status;
#endif
#endif
        uint64_t all = UINT64_MAX, saved_mask;
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &all, &saved_mask, 8);
        int saved_errno = errno;
        rvvm_thread_t* worker = rvvm_thread_create(user_native_service, request);
        if (worker) while (!atomic_load_uint32(&request->clone_ready))
            rvvm_futex_wait(&request->clone_ready, 0, RVVM_FUTEX_INFINITE);
        if (worker && request->child_table && !request->clone_error) {
            uintptr_t* packet = (void*)((char*)native_stack + stack_size - 2 * sizeof(uintptr_t));
            packet[0] = (uintptr_t)user_native_child;
#ifdef RVVM_STATIC_GLIBC_FORK
            if (request->private_thread) packet[0] = (uintptr_t)user_native_cow_child;
#endif
            packet[1] = (uintptr_t)request;
            struct {
                uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
            } args = {
                .flags = (flags & ~(UINT64_C(0xff) | UAPI_CLONE_SETTLS)) | UAPI_CLONE_PARENT_SETTID
                    | (flags & UAPI_CLONE_PARENT_SETTID ? UAPI_CLONE_CHILD_SETTID : 0),
                .pidfd = flags & UAPI_CLONE_PIDFD ? (uintptr_t)parent_tid : 0,
                /* schedule_tail stores the marker before pending STOP. The
                 * shared VMA keeps it visible even without CLONE_VM. */
                .child_tid = (uintptr_t)(flags & UAPI_CLONE_PARENT_SETTID ? request->clone_marker : child_tid),
                .parent_tid = (uintptr_t)(flags & UAPI_CLONE_PARENT_SETTID ? parent_tid : request->clone_marker),
                .exit_signal = flags & 0xff,
                .stack = (uintptr_t)native_stack,
                .stack_size = stack_size - 2 * sizeof(uintptr_t),
            };
            if (request->observer) {
                args.flags = flags & ~(UINT64_C(0xff) | UAPI_CLONE_SETTLS);
                args.child_tid = (uintptr_t)child_tid;
                args.parent_tid = (uintptr_t)parent_tid;
            }
            result = user_native_clone3(&args, sizeof(args));
        } else result = request->clone_error ? request->clone_error : -ENOMEM;
        user_sig = saved_signal;
        user_signal_process = saved_process;
        current_user_hart = saved_cpu;
        user_native_child_active = false;
        user_native_fault_target = saved_target;
        user_fd_context_load(&saved_guard);
        user_fd_current = saved_table;
        user_fd_owner_override = saved_owner;
        user_fake_current = saved_credentials;
        user_ptrace_context_load(&saved_ptrace);
        user_ptrace_restart = saved_restart;
        user_runtime_allocator = saved_allocator;
        user_fork_exe_link = saved_exe_link;
        user_fork_exe_link_ready = saved_exe_link_ready;
        softfloat_roundingMode = saved_rounding;
        softfloat_detectTininess = saved_tininess;
        softfloat_exceptionFlags = saved_exceptions;
#ifdef USER_FAULT_POC
        memcpy(user_fault_resume, saved_fault, sizeof(saved_fault));
        user_fault_armed = saved_armed;
        user_fault_fp_control = saved_control;
#if defined(__aarch64__)
        user_fault_fp_status = saved_status;
#endif
#endif
        user_native_exec_reader = NULL;
        errno = saved_errno;
        if (worker) {
            atomic_store_uint32(&request->service_stop, 1);
            atomic_store_uint32(&request->service_state, 3);
            rvvm_futex_wake(&request->service_state, 1);
            rvvm_futex_wake(&request->child_ready, 1);
            thread_join(worker);
        } else user_fd_table_release(request->source_table);
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
    }
    if (native_stack != MAP_FAILED) munmap(native_stack, stack_size);
    if (marker && marker != MAP_FAILED) munmap(marker, marker_size);
    if (executable_ready) user_exec_native_leave(&request->exec_reader);
    if (request->child_table) user_fd_table_release(request->child_table);
    user_ptrace_cancel(request->ptrace_context.bridge);
    user_ptrace_events_context_free(request->ptrace_context.events);
    user_ptrace_replay_records_free(request->ptrace_context.replay.records);
    rvvm_free_user_thread(request->cpu);
    free(request->private_thread);
    free(request);
    return result;
}
#endif
