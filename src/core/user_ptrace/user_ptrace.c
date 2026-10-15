/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Linux owns tracing permissions, relationships, wait events and signal routing.
 * This bridge translates the tracee's published guest state at safe boundaries.
 * Its mapping is not an authorization token: every remote access uses ptrace. */
#include "feature_test.h"
#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "user_ptrace.h"
#include "user_ptrace_events.h"
#include "user_ptrace_syscall.h"
#include "user_ptrace_replay.h"
#include "cpu/riscv_cpu.h"
#include "cpu/riscv_hart.h"
#include "cpu/riscv_csr.h"
#include "cpu/riscv_mmu.h"
#include "util/atomics.h"
#include "util/spinlock.h"
#include "util/user_fd_guard.h"
#include "util/user_proc_read.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define BRIDGE_MAGIC UINT64_C(0x5256564d50545203)
#define BRIDGE_SYNC 1
#define BRIDGE_STEP 2
#define BRIDGE_STEP_CALL 3
#define BRIDGE_TRANSFER 4
#define PHASE_RUNNING 0
#define PHASE_DISPATCH 1
#define PHASE_EXIT 2
#define PHASE_NEW 3
#define STOP_ENTRY 1
#define STOP_EXIT 2
#define STOP_SIGNAL 3
struct bridge {
    uint64_t magic, hart;
    uint64_t clone_hart;
    uint64_t clone_bridge;
    uint32_t phase, reserved;
    uint32_t tid, tgid, command, stopped, dirty, tracer, trap_code, fcsr, fp_dirty, saved_info_valid;
    uint64_t exe_fd_pointer;
    uint64_t signal_mask_pointer;
    uint64_t signal_pending_pointer;
    uint64_t signal_mask_value;
    siginfo_t saved_info;
    uint64_t auxv[64], auxv_size;
    uint64_t exit_regs[32], exit_fp[33];
    uint32_t options, syscall_mode, stop_type, inject_fault;
    uint32_t resume_signal, signal_deferred;
    struct user_ptrace_syscall_state syscall;
    uint64_t replay_requested, replay_area;
    int32_t replay_error;
};
static _Thread_local struct bridge* self;
static _Thread_local bool stepped;
static __thread uint32_t* executable_fd;
static spinlock_t bridge_pool_lock = SPINLOCK_INIT;
static struct bridge* bridge_pool;
static unsigned bridge_pool_count;
static void* bridge_marker;

void user_ptrace_context_save(struct user_ptrace_context* context)
{
    context->bridge = self;
    context->executable_fd = executable_fd;
    context->stepped = stepped;
    context->events = user_ptrace_events_context_current();
    user_ptrace_replay_context_save(&context->replay);
}

void user_ptrace_context_load(const struct user_ptrace_context* context)
{
    self = context->bridge;
    executable_fd = context->executable_fd;
    stepped = context->stepped;
    user_ptrace_events_context_select(context->events);
    user_ptrace_replay_context_load(&context->replay);
}
static bool debug_enabled(void)
{
    const char* value = getenv("RVVM_PTRACE_DEBUG");
    return value && *value && strcmp(value, "0");
}
static void trace_message(const char* format, ...)
{
    if (!debug_enabled()) return;
    /* A shared-mm child can die here; don't leave a parent's FILE lock held. */
    char line[512];
    int prefix = snprintf(line, sizeof(line), "rvvm-ptrace[%ld]: ", syscall(SYS_gettid));
    if (prefix < 0 || (size_t)prefix >= sizeof(line) - 1) return;
    va_list arguments;
    va_start(arguments, format);
    int suffix = vsnprintf(line + prefix, sizeof(line) - prefix, format, arguments);
    va_end(arguments);
    if (suffix < 0) return;
    size_t length = prefix + (size_t)suffix;
    if (length >= sizeof(line) - 1) length = sizeof(line) - 2;
    line[length++] = '\n';
    syscall(SYS_write, STDERR_FILENO, line, length);
}
#define TRACE(...) trace_message(__VA_ARGS__)

static long host_ptrace(unsigned long request, pid_t pid, uintptr_t addr, uintptr_t data)
{
    long ret = syscall(SYS_ptrace, request, pid, addr, data);
    return ret == -1 ? -errno : ret;
}

static int copy_guest(void* local, uintptr_t guest, size_t size, bool write)
{
    struct iovec l = {local, size}, r = {(void*)guest, size};
    long ret = syscall(write ? SYS_process_vm_writev : SYS_process_vm_readv,
                       syscall(SYS_gettid), &l, 1, &r, 1, 0);
    return ret == (long)size ? 0 : -EFAULT;
}

static int copy_wait_status(void* local, uintptr_t guest, size_t size)
{
#if defined(__aarch64__) || defined(__x86_64__)
    extern long user_memory_copy(void*, const void*, size_t);
    return user_memory_copy(local, (const void*)guest, size);
#else
    return copy_guest(local, guest, size, false);
#endif
}

static int remote(pid_t pid, uintptr_t addr, void* buffer, size_t size, bool write)
{
    if (!size) return 0;
    long probe;
    long allowed = host_ptrace(PTRACE_PEEKDATA, pid, addr & ~(sizeof(long) - 1), (uintptr_t)&probe);
    if (allowed < 0) return allowed;
    struct iovec local = {buffer, size}, other = {(void*)addr, size};
    long copied = syscall(write ? SYS_process_vm_writev : SYS_process_vm_readv,
                          pid, &local, 1, &other, 1, 0);
    if (copied == (long)size) return 0;
    unsigned char* bytes = buffer;
    while (size) {
        uintptr_t base = addr & ~(sizeof(long) - 1);
        size_t off = addr - base, n = sizeof(long) - off;
        if (n > size) n = size;
        long word;
        long ret = host_ptrace(PTRACE_PEEKDATA, pid, base, (uintptr_t)&word);
        if (ret < 0) return ret;
        if (write) {
            memcpy((char*)&word + off, bytes, n);
            ret = host_ptrace(PTRACE_POKEDATA, pid, base, word);
            if (ret < 0) return ret;
        } else memcpy(bytes, (char*)&word + off, n);
        addr += n; bytes += n; size -= n;
    }
    return 0;
}

static uintptr_t bridge_mapping_address(const char* line)
{
    if (!strstr(line, "/memfd:rvvm-ptrace-")) return 0;
    uintptr_t start = 0;
    const char* digit = line;
    for (;;) {
        unsigned value = *digit >= '0' && *digit <= '9' ? *digit - '0'
            : *digit >= 'a' && *digit <= 'f' ? *digit - 'a' + 10 : 16;
        if (value == 16) break;
        if (start > (UINTPTR_MAX - value) / 16) return 0;
        start = start * 16 + value;
        ++digit;
    }
    if (digit == line || *digit != '-') return 0;
    /* A zero-length file labels a guard page; the state itself is anonymous.
     * Continue recognizing the older file-backed bridge layout as well. */
    if (strstr(line, "/memfd:rvvm-ptrace-marker")) start += (unsigned long)sysconf(_SC_PAGESIZE);
    return start;
}

/* Proc readers need no debugger attachment. The kernel still enforces read
 * access to process memory; an attached debugger can use its ptrace fallback. */
static int remote_read(pid_t pid, uintptr_t addr, void* buffer, size_t size)
{
    struct iovec local = {buffer, size}, other = {(void*)addr, size};
    if (syscall(SYS_process_vm_readv, pid, &local, 1, &other, 1, 0) == (long)size) return 0;
    return remote(pid, addr, buffer, size, false);
}

static uintptr_t locate_inner(pid_t pid, struct bridge* state, bool proc)
{
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    user_fd_lock();
    struct user_proc_reader maps;
    if (!user_proc_open(&maps, path)) { user_fd_unlock(); return 0; }
    uintptr_t addr = 0;
    while (user_proc_line(&maps, line, sizeof(line))) {
        uintptr_t start = bridge_mapping_address(line);
        if (start
            && !(proc ? remote_read(pid, start, state, sizeof(*state))
                      : remote(pid, start, state, sizeof(*state), false))
            && state->magic == BRIDGE_MAGIC && state->tid == (uint32_t)pid) {
            addr = start;
            break;
        }
    }
    user_proc_close(&maps);
    user_fd_unlock();
    if (!addr) {
        struct user_ptrace_stop stop;
        if (user_ptrace_events_get(pid, &stop) && stop.bridge_hint
            && !(proc ? remote_read(pid, stop.bridge_hint, state, sizeof(*state))
                      : remote(pid, stop.bridge_hint, state, sizeof(*state), false))
            && state->magic == BRIDGE_MAGIC) {
            addr = stop.bridge_hint;
            if (stop.hart_hint) state->hart = stop.hart_hint;
        }
    }
    return addr;
}

static uintptr_t locate(pid_t pid, struct bridge* state)
{
    return locate_inner(pid, state, false);
}

/* Proc enumeration precedes debugger attachment. process_vm_readv leaves
 * access control with Linux, unlike the attached-only remote() helper. */
bool user_ptrace_guest_task(pid_t pid, pid_t tid, bool* recognized)
{
    *recognized = false;
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    struct user_proc_reader maps;
    user_fd_lock();
    if (!user_proc_open(&maps, path)) { user_fd_unlock(); return true; }
    bool found = false;
    while (user_proc_line(&maps, line, sizeof(line))) {
        uintptr_t address = bridge_mapping_address(line);
        if (!address) continue;
        struct bridge state;
        struct iovec local = {&state, sizeof(state)}, other = {(void*)address, sizeof(state)};
        if (syscall(SYS_process_vm_readv, pid, &local, 1, &other, 1, 0) != sizeof(state)) {
            *recognized = false;
            found = true;
            break;
        }
        if (state.magic != BRIDGE_MAGIC) continue;
        *recognized = true;
        if (state.tid == (uint32_t)tid) { found = true; break; }
    }
    user_proc_close(&maps);
    user_fd_unlock();
    return found;
}

static bool traced(void)
{
    struct user_proc_reader status;
    char line[256];
    user_fd_lock();
    if (!user_proc_open(&status, "/proc/thread-self/status")) { user_fd_unlock(); return false; }
    int32_t tracer = 0;
    while (user_proc_line(&status, line, sizeof(line))) {
        if (user_proc_integer(line, "TracerPid:", &tracer)) break;
    }
    user_proc_close(&status);
    user_fd_unlock();
    return tracer != 0;
}

static void stop_guest(rvvm_hart_t* cpu, int signo)
{
    riscv_jit_discard(cpu);
    rvvm_uxlen_t fcsr = 0;
    riscv_csr_op(cpu, CSR_FCSR, &fcsr, CSR_SETBITS);
    self->fcsr = fcsr;
    atomic_store_uint32(&self->stopped, 1);
    uint64_t bit = UINT64_C(1) << (signo - 1), saved;
    syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &bit, &saved, 8);
    for (;;) {
        syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), signo);
        if (atomic_load_uint32(&self->command) != BRIDGE_TRANSFER) break;
        void* area = user_ptrace_replay_allocate(self->replay_requested);
        self->replay_area = (uintptr_t)area;
        self->replay_error = area ? 0 : errno;
        atomic_store_uint32(&self->command, 0);
        signo = SIGSTOP;
    }
    if (self->signal_pending_pointer && *(volatile sig_atomic_t*)(uintptr_t)self->signal_pending_pointer) {
        saved = UINT64_MAX & ~(UINT64_C(1) << (SIGSEGV - 1)) & ~(UINT64_C(1) << (SIGBUS - 1));
    }
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved, NULL, 8);
    atomic_store_uint32(&self->stopped, 0);
}

bool user_ptrace_syscall_begin(rvvm_hart_t* cpu)
{
    if (!self || !atomic_load_uint32(&self->syscall_mode)) return false;
    cpu->registers[RISCV_REG_PC] += 4;
    user_ptrace_syscall_entry(cpu, &self->syscall);
    cpu->registers[10] = (rvvm_uxlen_t)-ENOSYS;
    self->saved_info_valid = 0;
    self->trap_code = SIGTRAP | (self->options & PTRACE_O_TRACESYSGOOD ? 0x80 : 0);
    self->stop_type = STOP_ENTRY;
    stop_guest(cpu, SIGTRAP);
    self->stop_type = 0;
    if ((int32_t)cpu->registers[17] == -1) return true;
    cpu->registers[10] = self->syscall.args[0];
    cpu->registers[RISCV_REG_PC] -= 4;
    return false;
}

static no_inline void syscall_end_slow(rvvm_hart_t* cpu)
{
    if (self && atomic_load_uint32(&self->phase) == PHASE_EXIT) return;
    if (self && atomic_load_uint32(&self->command) == BRIDGE_STEP_CALL) {
        atomic_store_uint32(&self->command, 0);
        self->saved_info_valid = 0;
        self->stop_type = 0;
        self->trap_code = TRAP_TRACE;
        stop_guest(cpu, SIGTRAP);
        return;
    }
    if (!self || !atomic_load_uint32(&self->syscall_mode) || self->syscall.phase != 1) return;
    user_ptrace_syscall_exit(cpu, &self->syscall);
    self->saved_info_valid = 0;
    self->trap_code = SIGTRAP | (self->options & PTRACE_O_TRACESYSGOOD ? 0x80 : 0);
    self->stop_type = STOP_EXIT;
    stop_guest(cpu, SIGTRAP);
    self->stop_type = 0;
}

void user_ptrace_syscall_end(rvvm_hart_t* cpu)
{
    /* These are only hints to enter the slow path, which performs acquire
     * reads before consuming debugger state. */
    if (self && (atomic_load_uint32_relax(&self->command) == BRIDGE_STEP_CALL
                 || atomic_load_uint32_relax(&self->syscall_mode))) syscall_end_slow(cpu);
}

bool user_ptrace_tracing(void)
{
    return self && atomic_load_uint32(&self->syscall_mode);
}

void user_ptrace_guest_fault(void)
{
    /* Interpreter permission/illegal-instruction faults have no host delivery
     * stop. Publish them before a guest default action can reset the host
     * handler; debuggers also use this stop for non-executable call dummies. */
    if (self && traced()) atomic_store_uint32(&self->signal_deferred, 1);
}

void user_ptrace_deliver_signal(rvvm_hart_t* cpu, volatile sig_atomic_t* signo, siginfo_t* info)
{
    if (!*signo || !self || !atomic_swap_uint32(&self->signal_deferred, 0)) return;
    self->saved_info = *info;
    self->saved_info_valid = 1;
    self->resume_signal = *signo;
    self->stop_type = STOP_SIGNAL;
    stop_guest(cpu, SIGTRAP);
    self->stop_type = 0;
    *signo = self->resume_signal;
    *info = self->saved_info;
    info->si_signo = *signo;
}

static struct bridge* allocate_bridge(void)
{
    spin_lock(&bridge_pool_lock);
    struct bridge* cached = bridge_pool;
    if (cached) {
        bridge_pool = (void*)(uintptr_t)cached->magic;
        bridge_pool_count--;
    }
    spin_unlock(&bridge_pool_lock);
    if (cached) {
        memset(cached, 0, sizeof(*cached));
        return cached;
    }
    /* Keep bridge state private and its empty file marker inaccessible.
     * Clone the shared marker VMA, rather than opening another descriptor:
     * guest NOFILE/FSIZE limits must not prevent tracing state allocation. */
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t length = page + sizeof(struct bridge);
    user_fd_lock();
    spin_lock(&bridge_pool_lock);
    if (!bridge_marker) {
        int fd = syscall(SYS_memfd_create, "rvvm-ptrace-marker", 1);
        if (fd >= 0) {
            void* marker = mmap(NULL, page, PROT_NONE, MAP_SHARED, fd, 0);
            if (marker != MAP_FAILED) bridge_marker = marker;
            close(fd);
        }
    }
    void* marker = bridge_marker;
    spin_unlock(&bridge_pool_lock);
    user_fd_unlock();
    if (!marker) return NULL;
    void* region = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct bridge* result = NULL;
    if (region != MAP_FAILED) {
        if (mremap(marker, 0, page, MREMAP_MAYMOVE | MREMAP_FIXED, region) != MAP_FAILED)
            result = (void*)((char*)region + page);
        else munmap(region, length);
    }
    return result;
}

static void recycle_bridge(struct bridge* state)
{
    if (!state) return;
    /* Retired mappings must no longer identify a live tracee. Keep a bounded
     * cache so ordinary pthread churn does not require four setup syscalls. */
    state->magic = 0;
    spin_lock(&bridge_pool_lock);
    bool retained = bridge_pool_count < 64;
    if (retained) {
        state->magic = (uintptr_t)bridge_pool;
        bridge_pool = state;
        bridge_pool_count++;
    }
    spin_unlock(&bridge_pool_lock);
    if (!retained) {
        size_t page = (size_t)sysconf(_SC_PAGESIZE);
        munmap((char*)state - page, page + sizeof(*state));
    }
}

void* user_ptrace_prepare(rvvm_hart_t* cpu, const uint64_t* auxv, size_t size, uint64_t mask)
{
    struct bridge* next = allocate_bridge();
    if (!next) return NULL;
    next->magic = BRIDGE_MAGIC;
    next->hart = (uintptr_t)cpu;
    next->tgid = self ? self->tgid : (uint32_t)getpid();
    next->exe_fd_pointer = (uintptr_t)executable_fd;
    next->signal_mask_value = mask;
    next->phase = PHASE_NEW;
    if (size <= sizeof(next->auxv)) { memcpy(next->auxv, auxv, size); next->auxv_size = size; }
    if (self) {
        next->options = self->options;
        next->syscall_mode = self->syscall_mode;
        next->syscall = self->syscall;
        next->syscall.phase = 0;
        self->clone_hart = (uintptr_t)cpu;
        self->clone_bridge = (uintptr_t)next;
    }
    return next;
}

void user_ptrace_cancel(void* state)
{
    if (self && self->clone_bridge == (uintptr_t)state) {
        self->clone_bridge = 0;
        self->clone_hart = 0;
    }
    recycle_bridge(state);
}

void user_ptrace_init(rvvm_hart_t* cpu, const uint64_t* auxv, size_t size, uint64_t* mask,
                     volatile sig_atomic_t* pending, void* prepared)
{
    self = prepared ? prepared : user_ptrace_prepare(cpu, auxv, size, *mask);
    if (!self) return;
    self->exe_fd_pointer = (uintptr_t)executable_fd;
    self->tid = syscall(SYS_gettid);
    *mask = self->signal_mask_value;
    self->signal_mask_pointer = (uintptr_t)mask;
    self->signal_pending_pointer = (uintptr_t)pending;
    if (!prepared) {
        bool tracing = traced();
        TRACE("initialized mapping=%p traced=%d", (void*)self, tracing);
        if (tracing) {
            self->trap_code = SI_KERNEL;
            stop_guest(cpu, SIGSTOP);
            if (self->syscall_mode) self->syscall.phase = 1;
        }
    }
    user_ptrace_syscall_end(cpu);
}

void user_ptrace_fork(rvvm_hart_t* cpu)
{
    /* Other threads and their lock ownership do not survive fork. */
    bridge_pool_lock = (spinlock_t)SPINLOCK_INIT;
    user_ptrace_events_fork_reset();
    user_ptrace_replay_fork_reset();
    if (!self) return;
    /* The private mapping is already COW after fork. Discovery validates its
     * published TID, not the memfd's historical name. */
    self->tid = syscall(SYS_gettid);
    self->tgid = getpid();
    self->hart = (uintptr_t)cpu;
    self->command = self->stopped = self->dirty = 0;
    self->syscall.phase = 0;
}

void user_ptrace_process_init(rvvm_hart_t* cpu, uint64_t* mask,
                             volatile sig_atomic_t* pending, void* prepared)
{
    /* Shared-mm callers already selected this prepared bridge. A recovered
     * COW child can safely retire its copied parent bridge first. */
    struct bridge* state = prepared;
    if (!state) return;
    if (self && self != state) recycle_bridge(self);
    state->tgid = syscall(SYS_getpid);
    state->clone_hart = state->clone_bridge = 0;
    user_ptrace_init(cpu, NULL, 0, mask, pending, state);
}

void user_ptrace_destroy(void)
{
    user_ptrace_replay_thread_destroy();
    if (self && (self->options & PTRACE_O_TRACEEXIT) && self->exe_fd_pointer) {
        // A private fd-table's metadata may be freed before the native exit stop.
        self->reserved = atomic_load_uint32((uint32_t*)(uintptr_t)self->exe_fd_pointer);
        self->exe_fd_pointer = (uintptr_t)&self->reserved;
    }
    if (self && !(self->options & PTRACE_O_TRACEEXIT)) recycle_bridge(self);
    self = NULL;
}

void user_ptrace_dispatch(void)
{
    if (self) atomic_store_uint32(&self->phase, PHASE_DISPATCH);
}

void user_ptrace_clone(rvvm_hart_t* child)
{
    if (self) { self->clone_hart = (uintptr_t)child; self->clone_bridge = (uintptr_t)self; }
}

void user_ptrace_exit(rvvm_hart_t* cpu)
{
    if (!self) return;
    for (unsigned i = 1; i < 32; i++) self->exit_regs[i] = cpu->registers[i];
    self->exit_regs[0] = cpu->registers[RISCV_REG_PC] + 4;
    memcpy(self->exit_fp, cpu->fpu_registers, 256);
    rvvm_uxlen_t fcsr = 0;
    riscv_csr_op(cpu, CSR_FCSR, &fcsr, CSR_SETBITS);
    self->exit_fp[32] = fcsr;
    atomic_store_uint32(&self->phase, PHASE_EXIT);
}

bool user_ptrace_signal(rvvm_hart_t* cpu, int signo, const siginfo_t* info)
{
    if (!self || signo != SIGSEGV || info->si_code != SI_QUEUE
        || info->si_value.sival_ptr != self || info->si_pid != (pid_t)self->tracer
        || atomic_load_uint32(&self->command) != BRIDGE_SYNC) return false;
    /* Hart entry resets running. Preserve the wake across that tiny window in
     * the same pending latch used by ordinary guest signal delivery. */
    atomic_store_uint32(&cpu->user_signal_pending, 1);
    atomic_store_uint32(&cpu->running, 0);
    return true;
}

bool user_ptrace_interrupted(void)
{
    return self && atomic_load_uint32(&self->command) == BRIDGE_SYNC;
}

bool user_ptrace_injected(int signo, siginfo_t* info)
{
    if (!self || atomic_load_uint32(&self->inject_fault) != (uint32_t)signo) return false;
    atomic_store_uint32(&self->inject_fault, 0);
    *info = self->saved_info;
    return true;
}

bool user_ptrace_restore_signal(siginfo_t* info)
{
    return user_ptrace_replay_restore(info);
}

static no_inline void checkpoint_slow(rvvm_hart_t* cpu)
{
    if (!self) return;
    if (atomic_load_uint32(&self->command) == BRIDGE_SYNC) {
        atomic_store_uint32(&self->command, 0);
        stop_guest(cpu, SIGSTOP);
        atomic_store_uint32(&cpu->user_signal_pending, 0);
    } else if (stepped) {
        stepped = false;
        self->saved_info_valid = 0;
        self->trap_code = TRAP_TRACE;
        stop_guest(cpu, SIGTRAP);
    }
    /* Debugger writes happen while this thread is stopped. Avoid exclusive
     * writes on every guest trap when there is no modified state to consume. */
    if (atomic_load_uint32(&self->fp_dirty) && atomic_swap_uint32(&self->fp_dirty, 0)) {
        rvvm_uxlen_t fcsr = self->fcsr;
        riscv_csr_op(cpu, CSR_FCSR, &fcsr, CSR_SWAP);
    }
    if (atomic_load_uint32(&self->dirty) && atomic_swap_uint32(&self->dirty, 0)) {
        riscv_jit_flush_cache(cpu);
        riscv_tlb_flush(cpu);
    }
}

void user_ptrace_checkpoint(rvvm_hart_t* cpu)
{
    if (self && (atomic_load_uint32_relax(&self->command) == BRIDGE_SYNC || stepped
                 || atomic_load_uint32_relax(&self->fp_dirty)
                 || atomic_load_uint32_relax(&self->dirty))) checkpoint_slow(cpu);
}

bool user_ptrace_break(rvvm_hart_t* cpu)
{
    if (!self || !traced()) return false;
    stepped = false;
    self->saved_info_valid = 0;
    self->trap_code = TRAP_BRKPT;
    stop_guest(cpu, SIGTRAP);
    return true;
}

rvvm_addr_t user_ptrace_run(rvvm_hart_t* cpu)
{
    if (self && atomic_load_uint32(&self->command) == BRIDGE_SYNC) return (rvvm_addr_t)-1;
    if (self) atomic_store_uint32(&self->phase, PHASE_RUNNING);
    if (!self || atomic_load_uint32(&self->command) != BRIDGE_STEP)
        return riscv_hart_run_userland(cpu);
    atomic_store_uint32(&self->command, 0);
    stepped = true;
    riscv_jit_discard(cpu);
#ifdef USE_JIT
    bool jit = cpu->jit_enabled;
    cpu->jit_enabled = false;
#endif
    atomic_store_uint32(&cpu->running, 0);
    riscv_run_till_event(cpu);
#ifdef USE_JIT
    cpu->jit_enabled = jit;
#endif
    if (cpu->trap) {
        cpu->registers[RISCV_REG_PC] = cpu->trap_pc;
        cpu->trap = false;
        return cpu->csr.cause[RISCV_PRIV_USER];
    }
    return (rvvm_addr_t)-1;
}

static void capture_event(pid_t, int, struct user_ptrace_event*);

static int synchronize(pid_t pid, uintptr_t addr, struct bridge* state)
{
    if (state->stopped || state->phase != PHASE_RUNNING) return 0;
    siginfo_t info;
    long info_ret = host_ptrace(PTRACE_GETSIGINFO, pid, 0, (uintptr_t)&info);
    uint32_t info_valid = info_ret < 0 ? 2 : 1;
    int ret;
    if (!info_ret) {
        ret = remote(pid, addr + offsetof(struct bridge, saved_info), &info, sizeof(info), true);
        if (ret) return ret;
    }
    ret = remote(pid, addr + offsetof(struct bridge, saved_info_valid), &info_valid, 4, true);
    if (ret) return ret;
    uint32_t command = BRIDGE_SYNC;
    uint32_t tracer = getpid();
    ret = remote(pid, addr + offsetof(struct bridge, tracer), &tracer, sizeof(tracer), true);
    if (ret) return ret;
    ret = remote(pid, addr + offsetof(struct bridge, command), &command, sizeof(command), true);
    if (ret) return ret;
    bool fault = !info_ret && info.si_code > 0
        && (info.si_signo == SIGSEGV || info.si_signo == SIGBUS);
    TRACE("sync start pid=%d phase=%u signal=%d code=%d fault=%d", pid, state->phase,
          info_ret ? 0 : info.si_signo, info_ret ? 0 : info.si_code, fault);
    if (!fault) {
        /* Kernel event stops ignore resume's signal argument. Obtain a native
         * delivery stop first; unlike queued signals this needs no free slot
         * under RLIMIT_SIGPENDING and cannot lose its identifying metadata. */
        struct user_ptrace_stop logical;
        bool event_stop = info_ret || (user_ptrace_events_get(pid, &logical)
            && ((unsigned)logical.event.status >> 16));
        if (event_stop) {
            for (;;) {
                ret = host_ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
                if (ret < 0) return ret;
                int status;
                do { ret = waitpid(pid, &status, __WALL); } while (ret < 0 && errno == EINTR);
                if (ret < 0) return -errno;
                struct user_ptrace_event step;
                capture_event(pid, status, &step);
                if (WIFSTOPPED(status) && !((unsigned)status >> 16) && step.info_valid
                    && WSTOPSIG(status) == SIGTRAP && step.info.si_code == TRAP_TRACE) break;
                step.deferred = true;
                if (!user_ptrace_events_push(&step)) return -ENOMEM;
                if (!WIFSTOPPED(status) || ((unsigned)status >> 16)) return -EAGAIN;
            }
        }
        siginfo_t wake = {0};
        wake.si_signo = SIGSEGV; wake.si_code = SI_QUEUE;
        wake.si_pid = getpid(); wake.si_uid = geteuid(); wake.si_value.sival_ptr = (void*)addr;
        ret = host_ptrace(PTRACE_SETSIGINFO, pid, 0, (uintptr_t)&wake);
        if (ret < 0) return ret;
    }
    ret = host_ptrace(PTRACE_CONT, pid, 0, fault ? info.si_signo : SIGSEGV);
    if (ret < 0) return ret;
    int status;
again:
    do { ret = waitpid(pid, &status, __WALL); } while (ret < 0 && errno == EINTR);
    if (ret < 0) return -errno;
    TRACE("sync wait pid=%d status=%x", pid, status);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV) {
        siginfo_t wake;
        if (!host_ptrace(PTRACE_GETSIGINFO, pid, 0, (uintptr_t)&wake)
            && wake.si_code == SI_QUEUE && wake.si_pid == getpid() && wake.si_value.sival_ptr == (void*)addr) {
            ret = host_ptrace(PTRACE_CONT, pid, 0, SIGSEGV);
            if (ret < 0) return ret;
            goto again;
        }
    }
    int copied = remote(pid, addr, state, sizeof(*state), false);
    TRACE("sync state copied=%d phase=%u stopped=%u command=%u", copied, state->phase,
          state->stopped, state->command);
    if (copied || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP || !state->stopped) {
        struct user_ptrace_event competing;
        capture_event(pid, status, &competing);
        competing.deferred = true;
        if (!user_ptrace_events_push(&competing)) return -ENOMEM;
        /* A kernel fork/exit event already is a coherent dispatcher boundary.
         * Keep it stopped; the next guest resume exposes the queued event. */
        if (!copied && state->phase != PHASE_RUNNING) return 0;
        if (!copied && WIFSTOPPED(status) && !((unsigned)status >> 16)) {
            /* Preserve competing delivery stops while the tagged wake brings
             * the hart to a stable boundary. They remain hidden until resume. */
            ret = host_ptrace(PTRACE_CONT, pid, 0, 0);
            if (ret < 0) return ret;
            goto again;
        }
        return copied ? copied : -EAGAIN;
    }
    return 0;
}

static void capture_event(pid_t pid, int status, struct user_ptrace_event* event)
{
    memset(event, 0, sizeof(*event));
    event->pid = pid;
    user_ptrace_events_identify(event);
    event->pgid = getpgid(pid);
    event->status = status;
    event->info_valid = !host_ptrace(PTRACE_GETSIGINFO, pid, 0, (uintptr_t)&event->info);
    event->traced = event->info_valid || ((unsigned)status >> 16);
    if ((unsigned)status >> 16)
        event->eventmsg_valid = !host_ptrace(PTRACE_GETEVENTMSG, pid, 0, (uintptr_t)&event->eventmsg);
}

static void remember_event(const struct user_ptrace_event* event)
{
    struct user_ptrace_stop stop = {.pid = event->pid};
    bool known = user_ptrace_events_get(event->pid, &stop);
    if (!known && !event->traced) return;
    stop.stopped = WIFSTOPPED(event->status);
    if (!stop.owner_tid) stop.owner_tid = event->owner_tid;
    stop.event = *event;
    user_ptrace_events_set(&stop);
    unsigned kind = (unsigned)event->status >> 16;
    if (event->eventmsg_valid && (kind == PTRACE_EVENT_FORK || kind == PTRACE_EVENT_VFORK
                                  || kind == PTRACE_EVENT_CLONE)) {
        struct bridge state;
        uintptr_t addr = locate(event->pid, &state);
        user_ptrace_events_inherit(event->pid, event->eventmsg);
        struct user_ptrace_stop child;
        if (addr && user_ptrace_events_get(event->eventmsg, &child)) {
            child.bridge_hint = state.clone_bridge ? state.clone_bridge : addr;
            child.hart_hint = state.clone_hart ? state.clone_hart : state.hart;
            user_ptrace_events_set(&child);
        }
    }
}

bool user_ptrace_wait_ready(pid_t selector, int* status, int options, void* usage, long* result)
{
    if (!user_ptrace_events_pending()) return false;
    struct user_ptrace_event event;
    if (!user_ptrace_events_wait4(selector, getpgrp(), options, &event)) return false;
    remember_event(&event);
    *result = event.pid;
    if ((status && copy_guest(&event.status, (uintptr_t)status, sizeof(event.status), true))
        || (usage && copy_guest(&event.usage, (uintptr_t)usage, sizeof(event.usage), true))) *result = -EFAULT;
    return true;
}

bool user_ptrace_waitid_ready(int type, unsigned id, siginfo_t* info, int options, void* usage, long* result)
{
    if (!user_ptrace_events_pending()) return false;
    struct user_ptrace_event event;
    if (!user_ptrace_events_waitid(type, id, getpgrp(), options, &event)) return false;
    remember_event(&event);
    siginfo_t value = {0};
    value.si_signo = SIGCHLD;
    value.si_pid = event.pid;
    if (WIFSTOPPED(event.status)) { value.si_code = CLD_TRAPPED; value.si_status = event.status >> 8; }
    else if (WIFEXITED(event.status)) { value.si_code = CLD_EXITED; value.si_status = WEXITSTATUS(event.status); }
    else { value.si_code = CLD_KILLED; value.si_status = WTERMSIG(event.status); }
    *result = 0;
    if ((info && copy_guest(&value, (uintptr_t)info, sizeof(value), true))
        || (usage && copy_guest(&event.usage, (uintptr_t)usage, sizeof(event.usage), true))) *result = -EFAULT;
    return true;
}

long user_ptrace_wait(long pid, int* status)
{
    if (pid <= 0 || !status) return pid;
    int value;
    if (copy_wait_status(&value, (uintptr_t)status, sizeof(value))) return pid;
    if (WIFEXITED(value) || WIFSIGNALED(value)) {
        user_ptrace_events_remove(pid);
        user_ptrace_replay_remove(pid);
        return pid;
    }
    if (!WIFSTOPPED(value)) return pid;
    struct user_ptrace_event event;
    capture_event(pid, value, &event);
    siginfo_t replay;
    if (event.info_valid && user_ptrace_replay_take(pid, &event.info, &replay)) {
        long ret = host_ptrace(PTRACE_SETSIGINFO, pid, 0, (uintptr_t)&replay);
        if (!ret) ret = host_ptrace(PTRACE_CONT, pid, 0, replay.si_signo);
        return ret < 0 ? ret : USER_PTRACE_WAIT_AGAIN;
    }
    remember_event(&event);
    TRACE("wait pid=%ld status=%x", pid, value);
    struct bridge state;
    uintptr_t bridge = locate(pid, &state);
    if (bridge) {
        struct user_ptrace_stop known;
        if (user_ptrace_events_get(pid, &known)) {
            state.options = known.options;
            remote(pid, bridge + offsetof(struct bridge, options), &state.options, sizeof(state.options), true);
        }
        unsigned kind = (unsigned)value >> 16;
        if (!kind && !state.stopped && state.phase == PHASE_DISPATCH
            && state.syscall_mode && state.syscall.phase == 1
            && WSTOPSIG(value) != SIGSTOP && WSTOPSIG(value) != SIGTRAP) {
            /* Finish the interrupted guest syscall before reporting its
             * delivery stop. The dispatcher republishes the captured signal. */
            uint32_t deferred = 1;
            int copied = remote(pid, bridge + offsetof(struct bridge, signal_deferred), &deferred, sizeof(deferred), true);
            if (copied) return copied;
            long ret = host_ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(value));
            if (ret < 0) return ret;
            do { ret = waitpid(pid, &value, __WALL); } while (ret < 0 && errno == EINTR);
            if (ret < 0) return -errno;
            if (copy_guest(&value, (uintptr_t)status, sizeof(value), true)) return -EFAULT;
            return user_ptrace_wait(pid, status);
        }
        if ((!kind || (kind == PTRACE_EVENT_STOP && WSTOPSIG(value) == SIGTRAP))
            && state.phase == PHASE_RUNNING && !state.stopped) {
            int ret = synchronize(pid, bridge, &state);
            if (ret) return ret;
        }
        if (state.stopped && state.stop_type == STOP_SIGNAL) {
            value = (state.saved_info.si_signo << 8) | 0x7f;
            event.status = value;
            event.info = state.saved_info;
            event.info_valid = true;
            remember_event(&event);
            copy_guest(&value, (uintptr_t)status, sizeof(value), true);
        } else if (state.stopped && state.stop_type && (state.options & PTRACE_O_TRACESYSGOOD)) {
            value = (value & ~0xff00) | ((SIGTRAP | 0x80) << 8);
            event.status = value;
            event.info.si_signo = SIGTRAP;
            event.info.si_code = SIGTRAP | 0x80;
            event.info_valid = true;
            remember_event(&event);
            copy_guest(&value, (uintptr_t)status, sizeof(value), true);
        }
        return pid;
    }
    /* At the kernel exec stop the interpreter has not initialized yet. Only
     * advance our own interpreter, never an arbitrary native tracee. */
    /* A newborn fork/thread SIGSTOP is a debugger-visible event. Only the
     * actual exec SIGTRAP may advance through interpreter initialization. */
    if (WSTOPSIG(value) != SIGTRAP
        || (((unsigned)value >> 16) && ((unsigned)value >> 16) != PTRACE_EVENT_EXEC)) return pid;
    char path[64];
    struct stat own, child;
    snprintf(path, sizeof(path), "/proc/%ld/exe", pid);
    if (stat("/proc/self/exe", &own) || stat(path, &child)
        || own.st_dev != child.st_dev || own.st_ino != child.st_ino) return pid;
    if (host_ptrace(PTRACE_CONT, pid, 0, 0) < 0) return pid;
    TRACE("advancing startup pid=%ld", pid);
    int actual;
    long ret;
    do { ret = waitpid(pid, &actual, __WALL); } while (ret < 0 && errno == EINTR);
    if (ret < 0) return -errno;
    bridge = locate(pid, &state);
    if (!bridge || !state.stopped) {
        value = actual;
        capture_event(pid, value, &event);
        remember_event(&event);
    } else {
        struct user_ptrace_stop stop;
        if (user_ptrace_events_get(pid, &stop)) {
            uint32_t options = stop.options;
            remote(pid, bridge + offsetof(struct bridge, options), &options, sizeof(options), true);
            uint32_t mode = stop.resume_request == PTRACE_SYSCALL;
            remote(pid, bridge + offsetof(struct bridge, syscall_mode), &mode, sizeof(mode), true);
        }
    }
    copy_guest(&value, (uintptr_t)status, sizeof(value), true);
    return pid;
}

long user_ptrace_waitid(long result, siginfo_t* ptr, int options)
{
    if (result || !ptr) return result;
    siginfo_t info;
    if (copy_wait_status(&info, (uintptr_t)ptr, sizeof(info)) || info.si_pid <= 0) return result;
    if (info.si_code == CLD_EXITED || info.si_code == CLD_KILLED || info.si_code == CLD_DUMPED) {
        if (!(options & WNOWAIT)) {
            user_ptrace_events_remove(info.si_pid);
            user_ptrace_replay_remove(info.si_pid);
        }
        return result;
    }
    if (info.si_code != CLD_TRAPPED) return result;
    int status = (info.si_status << 8) | 0x7f;
    struct rusage usage = {0};
    long ret = 0;
    if (options & WNOWAIT) {
        user_ptrace_events_normalize_lock();
        if (user_ptrace_waitid_ready(P_PID, info.si_pid, ptr, options, NULL, &ret))
            goto done;
        struct user_ptrace_event identity = {.pid = info.si_pid};
        user_ptrace_events_identify(&identity);
        /* A sibling can observe this stop, but cannot issue ptrace on behalf
         * of its owning thread. Preserve the native event for that owner. */
        if (identity.owner_tid && identity.owner_tid != syscall(SYS_gettid)) goto done;
        /* Normalize once, then preserve the logical event for repeated peeks.
         * Leaving it in the kernel would expose the interpreter's exec stop. */
        long got;
        do { got = wait4(info.si_pid, &status, __WALL | WNOHANG, &usage); } while (got < 0 && errno == EINTR);
        if (got < 0) { ret = -errno; goto done; }
        /* Another consuming waiter may have won after our native peek. The
         * already observed event remains a valid successful WNOWAIT result. */
        if (!got) goto done;
    }
    ret = user_ptrace_wait(info.si_pid, &status);
    if (ret < 0) goto done;
    if (options & WNOWAIT) {
        struct user_ptrace_stop stop;
        struct user_ptrace_event event;
        if (user_ptrace_events_get(info.si_pid, &stop)) event = stop.event;
        else capture_event(info.si_pid, status, &event);
        event.status = status;
        event.deferred = false;
        event.usage = usage;
        if (!user_ptrace_events_push(&event)) { ret = -ENOMEM; goto done; }
    }
    if (WIFEXITED(status)) { info.si_code = CLD_EXITED; info.si_status = WEXITSTATUS(status); }
    else if (WIFSIGNALED(status)) { info.si_code = CLD_KILLED; info.si_status = WTERMSIG(status); }
    else info.si_status = (unsigned)status >> 8;
    ret = copy_guest(&info, (uintptr_t)ptr, sizeof(info), true);
done:
    if (options & WNOWAIT) user_ptrace_events_normalize_unlock();
    return ret;
}

static int dirty_process(pid_t pid)
{
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%u/maps", pid);
    user_fd_lock();
    struct user_proc_reader maps;
    if (!user_proc_open(&maps, path)) { user_fd_unlock(); return -errno; }
    int ret = 0;
    while (user_proc_line(&maps, line, sizeof(line))) {
        uintptr_t start = bridge_mapping_address(line);
        if (!start) continue;
        uint64_t magic;
        ret = remote(pid, start, &magic, sizeof(magic), false);
        if (ret || magic != BRIDGE_MAGIC) continue;
        uint32_t dirty = 1;
        ret = remote(pid, start + offsetof(struct bridge, dirty), &dirty, sizeof(dirty), true);
        if (ret) break;
    }
    user_proc_close(&maps);
    user_fd_unlock();
    return ret;
}

static int defer_detach_signals(pid_t pid)
{
    struct user_ptrace_event event;
    while (user_ptrace_events_pop_deferred(pid, &event)) {
        if (!WIFSTOPPED(event.status) || ((unsigned)event.status >> 16)
            || !event.info_valid) continue;
        int ret = user_ptrace_replay_store_unsent(pid, &event.info);
        if (ret) { user_ptrace_events_push(&event); return ret; }
    }
    return 0;
}

static int detach_mailbox(pid_t pid, uintptr_t address, struct bridge* state)
{
    if (!user_ptrace_replay_pending(pid)) return 0;
    if (!state->stopped) {
        state->phase = PHASE_RUNNING;
        int ret = synchronize(pid, address, state);
        if (ret) return ret;
        if (!state->stopped) return -EAGAIN;
    }
    for (;;) {
        uint64_t count = user_ptrace_replay_count(pid);
        uint32_t command = BRIDGE_TRANSFER;
        int ret = remote(pid, address + offsetof(struct bridge, replay_requested), &count, sizeof(count), true);
        if (!ret) ret = remote(pid, address + offsetof(struct bridge, command), &command, sizeof(command), true);
        if (!ret) ret = host_ptrace(PTRACE_CONT, pid, 0, 0);
        if (ret) return ret;
        for (;;) {
            int status;
            do { ret = waitpid(pid, &status, __WALL); } while (ret < 0 && errno == EINTR);
            if (ret < 0) return -errno;
            if (!WIFSTOPPED(status)) return -ESRCH;
            ret = remote(pid, address, state, sizeof(*state), false);
            if (ret) return ret;
            if (WSTOPSIG(status) == SIGSTOP && !state->command) break;
            struct user_ptrace_event event;
            capture_event(pid, status, &event);
            if (!event.info_valid || !user_ptrace_replay_hold(pid, &event.info)) {
                event.deferred = true;
                if (!user_ptrace_events_push(&event)) return -ENOMEM;
            }
            ret = host_ptrace(PTRACE_CONT, pid, 0, 0);
            if (ret) return ret;
        }
        if (state->replay_error) return -state->replay_error;
        int ret_deferred = defer_detach_signals(pid);
        if (ret_deferred) return ret_deferred;
        if (user_ptrace_replay_count(pid) != count) continue;
        if (count > SIZE_MAX / sizeof(struct user_ptrace_replay_entry)) return -ENOMEM;
        size_t bytes = count * sizeof(struct user_ptrace_replay_entry);
        struct user_ptrace_replay_entry* entries = user_ptrace_replay_temporary(bytes);
        if (!entries) return -ENOMEM;
        int exported = user_ptrace_replay_export(pid, entries, count);
        ret = exported < 0 ? exported : remote(pid, state->replay_area, entries, bytes, true);
        user_ptrace_replay_temporary_free(entries);
        return ret ? ret : user_ptrace_replay_resend(pid, state->tgid);
    }
}

static siginfo_t resume_info(const struct user_ptrace_stop* stop, unsigned signo)
{
    siginfo_t info = stop->event.info;
    if (!stop->event.info_valid || info.si_signo != (int)signo) {
        memset(&info, 0, sizeof(info));
        info.si_signo = signo; info.si_code = SI_USER;
        info.si_pid = getpid(); info.si_uid = geteuid();
    }
    return info;
}

long user_ptrace_request(unsigned long request, pid_t pid, uintptr_t addr, uintptr_t data)
{
    TRACE("request=%lu pid=%d addr=%lx", request, pid, (unsigned long)addr);
    if (request == PTRACE_TRACEME) return host_ptrace(request, pid, addr, data);
    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        long ret = host_ptrace(request, pid, addr, data);
        if (!ret) {
            struct user_ptrace_stop stop = {.pid = pid, .owner_tid = syscall(SYS_gettid),
                                           .options = request == PTRACE_SEIZE ? data : 0};
            user_ptrace_events_set(&stop);
        }
        return ret;
    }
    /* These describe native syscall/signal-mask state, not the guest state.
     * Keep the old unsupported result until they have explicit translation. */
    if (request == 0x420f) return -ENOSYS;
    if (request == 12 || request == 13 || request == 14 || request == 15
        || request == 18 || request == 19 || request == 23 || request == 25
        || request == 26 || request == 30 || request == 31 || request == 32) return -EIO;
    struct bridge state;
    uintptr_t bridge = locate(pid, &state);
    if (!bridge && (request == PTRACE_GETREGSET || request == PTRACE_SETREGSET)) {
        /* A sibling WNOWAIT observer cannot advance this thread's tracee.
         * Normalize its pending startup event here without consuming the
         * logical event that the owner still needs to wait for. */
        siginfo_t stop, pending = {0};
        if (!host_ptrace(PTRACE_GETSIGINFO, pid, 0, (uintptr_t)&stop)
            && !waitid(P_PID, pid, &pending, WSTOPPED | WNOWAIT | WNOHANG | __WALL)
            && pending.si_pid == pid) {
            long ret = user_ptrace_waitid(0, &pending, WSTOPPED | WNOWAIT | __WALL);
            if (ret < 0) return ret;
            bridge = locate(pid, &state);
        }
    }
    if (!bridge) return host_ptrace(request, pid, addr, data);
    if (request == PTRACE_PEEKUSER || request == PTRACE_POKEUSER) return -EIO;
    struct user_ptrace_stop logical;
    bool recorded = user_ptrace_events_get(pid, &logical) && logical.stopped;
    if (request == PTRACE_GETSIGMASK || request == PTRACE_SETSIGMASK) {
        if (addr != 8) return -EINVAL;
        uint64_t mask;
        uintptr_t mask_address = state.signal_mask_pointer ? state.signal_mask_pointer
            : bridge + offsetof(struct bridge, signal_mask_value);
        int ret = remote(pid, mask_address, &mask, sizeof(mask), false);
        if (ret) return ret;
        if (request == PTRACE_GETSIGMASK) return copy_guest(&mask, data, sizeof(mask), true);
        uint64_t old = mask;
        if (copy_guest(&mask, data, sizeof(mask), false)) return -EFAULT;
        mask &= ~(UINT64_C(1) << (SIGKILL - 1)) & ~(UINT64_C(1) << (SIGSTOP - 1));
        ret = remote(pid, mask_address, &mask, sizeof(mask), true);
        if (ret) return ret;
        mask &= ~(UINT64_C(1) << (SIGSEGV - 1)) & ~(UINT64_C(1) << (SIGBUS - 1));
        ret = host_ptrace(request, pid, addr, (uintptr_t)&mask);
        if (ret) remote(pid, mask_address, &old, sizeof(old), true);
        return ret;
    }
    if (request == 0x420e) { /* PTRACE_GET_SYSCALL_INFO */
        struct user_ptrace_syscall_state syscall = state.syscall;
        uint64_t regs[32];
        int ret = 0;
        if (state.phase == PHASE_EXIT) memcpy(regs, state.exit_regs, sizeof(regs));
        else {
            ret = remote(pid, state.hart + offsetof(rvvm_hart_t, registers), regs, sizeof(regs), false);
            if (!ret) ret = remote(pid, state.hart + offsetof(rvvm_hart_t, registers)
                                  + RISCV_REG_PC * sizeof(rvvm_uxlen_t), regs, 8, false);
        }
        if (ret) return ret;
        syscall.ip = regs[0]; syscall.sp = regs[2];
        if (!state.stopped && state.phase == PHASE_DISPATCH) syscall.ip += 4;
        if (state.stop_type == STOP_ENTRY) {
            syscall.phase = 1; syscall.nr = (int32_t)regs[17];
            for (unsigned i = 1; i < 6; i++) syscall.args[i] = regs[10 + i];
        } else if (state.stop_type == STOP_EXIT) { syscall.phase = 2; syscall.result = regs[10]; }
        else syscall.phase = 0;
        unsigned char output[88];
        size_t full = user_ptrace_syscall_info(&syscall, state.options & PTRACE_O_TRACESYSGOOD, output, sizeof(output));
        size_t size = addr < full ? addr : full;
        return size && copy_guest(output, data, size, true) ? -EFAULT : (long)full;
    }
    if (request == PTRACE_GETEVENTMSG && recorded && logical.event.eventmsg_valid)
        return copy_guest(&logical.event.eventmsg, data, sizeof(logical.event.eventmsg), true);
    if (request == PTRACE_SETSIGINFO && state.stopped && state.saved_info_valid == 1) {
        siginfo_t info;
        if (copy_guest(&info, data, sizeof(info), false)) return -EFAULT;
        long ret = host_ptrace(request, pid, addr, (uintptr_t)&info);
        if (ret < 0) return ret;
        ret = remote(pid, bridge + offsetof(struct bridge, saved_info), &info, sizeof(info), true);
        if (!ret && recorded) {
            logical.event.info = info;
            logical.event.info_valid = true;
            user_ptrace_events_set(&logical);
        }
        return ret;
    }
    if (request == PTRACE_GETSIGINFO && recorded && logical.event.info_valid
        && (((unsigned)logical.event.status >> 16) || state.saved_info_valid))
        return copy_guest(&logical.event.info, data, sizeof(siginfo_t), true);
    if (request == PTRACE_GETSIGINFO && state.stopped && state.saved_info_valid)
        return state.saved_info_valid == 1 ? copy_guest(&state.saved_info, data, sizeof(siginfo_t), true) : -EINVAL;
    if (request == PTRACE_GETSIGINFO && state.stopped && state.trap_code) {
        siginfo_t info;
        long ret = host_ptrace(request, pid, addr, (uintptr_t)&info);
        if (ret < 0) return ret;
        info.si_signo = SIGTRAP;
        info.si_code = state.trap_code;
        uint64_t pc;
        ret = remote(pid, state.hart + offsetof(rvvm_hart_t, registers)
                     + RISCV_REG_PC * sizeof(rvvm_uxlen_t), &pc, sizeof(pc), false);
        if (ret) return ret;
        info.si_addr = (void*)(uintptr_t)pc;
        return copy_guest(&info, data, sizeof(info), true);
    }
    if (request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) {
        if (addr != 1 && addr != 2) return -EINVAL;
        int ret = 0;
        struct iovec iov;
        if (copy_guest(&iov, data, sizeof(iov), false)) return -EFAULT;
        /* Linux requires whole regset slots. GDB probes 33*4 bytes first to
         * distinguish an F-only target from our 64-bit D register file. */
        if (iov.iov_len % 8) return -EINVAL;
        uint64_t regs[33] = {0};
        size_t size = addr == 1 ? 256 : 264;
        if (iov.iov_len < size) size = iov.iov_len;
        if (state.phase == PHASE_EXIT) {
            memcpy(regs, addr == 1 ? state.exit_regs : state.exit_fp, addr == 1 ? 256 : 264);
            ret = 0;
        } else if (addr == 1) {
            ret = remote(pid, state.hart + offsetof(rvvm_hart_t, registers), regs, 256, false);
            if (!ret) ret = remote(pid, state.hart + offsetof(rvvm_hart_t, registers)
                + RISCV_REG_PC * sizeof(rvvm_uxlen_t), regs, 8, false);
        } else {
            ret = remote(pid, state.hart + offsetof(rvvm_hart_t, fpu_registers), regs, 256, false);
            regs[32] = state.fcsr;
        }
        if (ret) return ret;
        bool in_host_call = state.phase == PHASE_DISPATCH && !state.stopped;
        if (addr == 1 && in_host_call) {
            regs[0] += 4;
            if (state.tid != (uint32_t)pid) regs[10] = 0;
        }
        if (request == PTRACE_GETREGSET) {
            if (copy_guest(regs, (uintptr_t)iov.iov_base, size, true)) return -EFAULT;
            iov.iov_len = size;
            return copy_guest(&iov, data, sizeof(iov), true);
        }
        if (copy_guest(regs, (uintptr_t)iov.iov_base, size, false)) return -EFAULT;
        if (state.phase == PHASE_EXIT)
            return remote(pid, bridge + (addr == 1 ? offsetof(struct bridge, exit_regs)
                          : offsetof(struct bridge, exit_fp)), regs, size, true);
        if (addr == 1) {
            if (in_host_call) regs[0] -= 4;
            ret = remote(pid, state.hart + offsetof(rvvm_hart_t, registers)
                + RISCV_REG_PC * sizeof(rvvm_uxlen_t), regs, 8, true);
            if (!ret) ret = remote(pid, state.hart + offsetof(rvvm_hart_t, registers) + 8,
                                   regs + 1, 248, true);
        } else {
            ret = remote(pid, state.hart + offsetof(rvvm_hart_t, fpu_registers), regs, 256, true);
            uint32_t fcsr = regs[32] & 255, dirty = 1;
            if (!ret) ret = remote(pid, bridge + offsetof(struct bridge, fcsr), &fcsr, 4, true);
            if (!ret) ret = remote(pid, bridge + offsetof(struct bridge, fp_dirty), &dirty, 4, true);
        }
        return ret;
    }
    if (request == PTRACE_SINGLESTEP) {
        if (state.stop_type == STOP_SIGNAL) {
            uint32_t signal = data;
            int ret = remote(pid, bridge + offsetof(struct bridge, resume_signal), &signal, sizeof(signal), true);
            if (ret) return ret;
            data = 0;
        }
        int ret = synchronize(pid, bridge, &state);
        if (ret) return ret;
        ret = dirty_process(pid);
        if (ret) return ret;
        uint32_t mode = 0;
        ret = remote(pid, bridge + offsetof(struct bridge, syscall_mode), &mode, sizeof(mode), true);
        if (ret) return ret;
        uint32_t command = state.stop_type == STOP_ENTRY ? BRIDGE_STEP_CALL : BRIDGE_STEP;
        ret = remote(pid, bridge + offsetof(struct bridge, command), &command, 4, true);
        if (!ret) ret = host_ptrace(PTRACE_CONT, pid, addr, data);
        if (!ret && recorded) {
            logical.stopped = false;
            logical.resume_request = request;
            user_ptrace_events_set(&logical);
        }
        return ret;
    }
    if (request == PTRACE_CONT || request == PTRACE_DETACH || request == PTRACE_SYSCALL) {
        int ret = 0;
        if (state.stop_type == STOP_SIGNAL) {
            uint32_t signal = data;
            ret = remote(pid, bridge + offsetof(struct bridge, resume_signal), &signal, sizeof(signal), true);
            if (ret) return ret;
            data = 0;
        }
        /* The real fault was consumed to publish precise JIT registers. Its
         * reinjection arrives at our safe stop, so restore guest metadata there. */
        uint32_t inject = state.stopped && state.saved_info_valid == 1
            && state.saved_info.si_code > 0 && data == (uintptr_t)state.saved_info.si_signo
            && (data == SIGSEGV || data == SIGBUS) ? data : 0;
        ret = remote(pid, bridge + offsetof(struct bridge, inject_fault), &inject, sizeof(inject), true);
        if (ret) return ret;
        uint32_t mode = request == PTRACE_SYSCALL;
        ret = remote(pid, bridge + offsetof(struct bridge, syscall_mode), &mode, sizeof(mode), true);
        uint32_t command = 0;
        if (!ret) ret = remote(pid, bridge + offsetof(struct bridge, command), &command, sizeof(command), true);
        /* GDB can write through /proc/pid/mem instead of POKETEXT. All harts
         * must invalidate translated code before any guest execution resumes. */
        if (!ret) ret = dirty_process(pid);
        bool delivery = recorded && !((unsigned)logical.event.status >> 16)
            && WSTOPSIG(logical.event.status) != (SIGTRAP | 0x80);
        bool queued = false;
        if (!ret && request == PTRACE_DETACH) {
            ret = defer_detach_signals(pid);
            if (!ret && data && delivery && user_ptrace_replay_pending(pid)) {
                siginfo_t info = resume_info(&logical, data);
                ret = user_ptrace_replay_store_unsent(pid, &info);
                if (!ret) data = 0;
            }
            if (!ret) ret = detach_mailbox(pid, bridge, &state);
        } else if (!ret) {
            queued = user_ptrace_events_release(pid);
            if (data && delivery && (queued || user_ptrace_replay_pending(pid))) {
                siginfo_t info = resume_info(&logical, data);
                ret = user_ptrace_replay_queue(pid, state.tgid, &info);
                if (!ret) data = 0;
            }
        }
        if (!ret && queued) {
            syscall(SYS_kill, getpid(), SIGCHLD);
        } else if (!ret) {
            if (data && delivery) {
                siginfo_t info = resume_info(&logical, data);
                ret = host_ptrace(PTRACE_SETSIGINFO, pid, 0, (uintptr_t)&info);
            }
            if (!ret) ret = host_ptrace(request == PTRACE_SYSCALL ? PTRACE_CONT : request, pid, addr, data);
        }
        if (!ret && request == PTRACE_DETACH) {
            user_ptrace_events_remove(pid);
            user_ptrace_replay_remove(pid);
        }
        else if (!ret && recorded) { logical.stopped = false; logical.resume_request = request; user_ptrace_events_set(&logical); }
        return ret;
    }
    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        long ret = host_ptrace(request, pid, addr, data);
        if (ret < 0) return ret;
        return dirty_process(pid);
    }
    long ret = host_ptrace(request, pid, addr, data);
    if (!ret && request == PTRACE_SETOPTIONS) {
        uint32_t options = data;
        remote(pid, bridge + offsetof(struct bridge, options), &options, sizeof(options), true);
        if (!recorded) memset(&logical, 0, sizeof(logical));
        logical.pid = pid; logical.options = data;
        user_ptrace_events_set(&logical);
    }
    return ret;
}

bool user_ptrace_remote_auxv(pid_t pid, uint64_t buffer[64], size_t* size)
{
    struct bridge state;
    if (!locate_inner(pid, &state, true) || state.auxv_size > sizeof(state.auxv)) return false;
    memcpy(buffer, state.auxv, state.auxv_size);
    *size = state.auxv_size;
    return true;
}

bool user_ptrace_remote_exe_descriptor(pid_t pid, char* buffer, size_t size)
{
    struct bridge state;
    uint32_t fd;
    if (!locate_inner(pid, &state, true)
        || remote_read(pid, state.exe_fd_pointer, &fd, sizeof(fd)) || (int32_t)fd < 0) return false;
    int len = snprintf(buffer, size, "/proc/%u/fd/%u", pid, fd);
    return len >= 0 && (size_t)len < size;
}

void user_ptrace_set_exe_fd_pointer(uint32_t* fd)
{
    executable_fd = fd;
    if (self) self->exe_fd_pointer = (uintptr_t)fd;
}
#endif
