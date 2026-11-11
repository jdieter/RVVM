/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Linux RV64 signal delivery. Host Linux owns routing and pending queues;
 * only one caught signal is removed from that queue at a time per thread. */
#ifndef RVVM_USER_SIGNAL_H
#define RVVM_USER_SIGNAL_H

#include "rvvm.h"
#include "cpu/riscv_csr.h"
#include <ucontext.h>
#include "rvvm_user_signal_state.h"
#include <setjmp.h>
#include "cpu/riscv_cpu.h"
static THREAD_LOCAL sigjmp_buf user_fault_resume;
static THREAD_LOCAL volatile sig_atomic_t user_fault_armed;
static THREAD_LOCAL uint32_t user_fault_fp_control;
#if defined(__aarch64__)
static THREAD_LOCAL uint32_t user_fault_fp_status;
#endif

static void user_fault_save_fenv(const ucontext_t* uc)
{
#if defined(__x86_64__)
    user_fault_fp_control = uc->uc_mcontext.fpregs->mxcsr;
#elif defined(__aarch64__)
    const unsigned char* p = uc->uc_mcontext.__reserved;
    const unsigned char* end = p + sizeof(uc->uc_mcontext.__reserved);
    while (p + 8 <= end) {
        uint32_t magic, size;
        memcpy(&magic, p, 4); memcpy(&size, p + 4, 4);
        if (size < 8 || size > (size_t)(end - p)) break;
        if (magic == 0x46508001 && size >= 16) {
            memcpy(&user_fault_fp_status, p + 8, 4);
            memcpy(&user_fault_fp_control, p + 12, 4);
            return;
        }
        p += size;
    }
#endif
}

static void user_fault_restore_fenv(void)
{
    /* siglongjmp bypasses the host sigreturn that normally restores FP state. */
#if defined(__x86_64__)
    __asm__ volatile("ldmxcsr %0" : : "m"(user_fault_fp_control));
#elif defined(__aarch64__)
    __asm__ volatile("msr fpcr,%0\nmsr fpsr,%1" : : "r"((uint64_t)user_fault_fp_control),
                     "r"((uint64_t)user_fault_fp_status));
#endif
}

struct user_sigstack { uint64_t sp; int32_t flags; uint32_t pad; uint64_t size; };
struct user_siginfo {
    int32_t signo, error, code, pad;
    union {
        struct { int32_t pid; uint32_t uid; int32_t status, pad; int64_t utime, stime; } child;
        struct { int32_t pid; uint32_t uid; uint64_t value; } sender;
        struct { int32_t id, overrun; uint64_t value; } timer;
        struct { uint64_t address; } fault;
        uint8_t bytes[112];
    } data;
};
struct user_sigframe {
    struct user_siginfo info;
    struct {
        uint64_t flags, link;
        struct user_sigstack stack;
        uint64_t mask;
        uint8_t mask_pad[120];
        struct {
            uint64_t regs[32]; // PC, x1..x31
            uint64_t fp[32];
            uint32_t fcsr;
            uint8_t fp_pad[256];
            uint32_t reserved, magic, size;
        } __attribute__((aligned(16))) context;
    } uc;
};
_Static_assert(sizeof(struct user_sigaction) == 24, "RV64 sigaction");
_Static_assert(sizeof(struct user_siginfo) == 128, "RV64 siginfo");
// waitid writes only SIGCHLD fields; supported LP64 Linux hosts share this ABI.
#define CHILD_INFO_ABI(guest, host) \
    _Static_assert(offsetof(struct user_siginfo, guest) == offsetof(siginfo_t, host), "siginfo offset"); \
    _Static_assert(sizeof(((struct user_siginfo*)0)->guest) == sizeof(((siginfo_t*)0)->host), "siginfo width")
_Static_assert(sizeof(siginfo_t) == 128, "Linux siginfo size");
CHILD_INFO_ABI(signo, si_signo);
CHILD_INFO_ABI(error, si_errno);
CHILD_INFO_ABI(code, si_code);
CHILD_INFO_ABI(data.child.pid, si_pid);
CHILD_INFO_ABI(data.child.uid, si_uid);
CHILD_INFO_ABI(data.child.status, si_status);
CHILD_INFO_ABI(data.child.utime, si_utime);
CHILD_INFO_ABI(data.child.stime, si_stime);
CHILD_INFO_ABI(data.sender.value, si_value);
#undef CHILD_INFO_ABI
_Static_assert(sizeof(struct rusage) == 144 && sizeof(struct timeval) == 16,
               "RV64 rusage uses LP64 longs and 64-bit timeval");
_Static_assert(offsetof(struct user_sigframe, uc.context) == 304, "RV64 mcontext");
_Static_assert(sizeof(struct user_sigframe) == 1088, "RV64 signal frame");
_Static_assert(offsetof(struct user_sigframe, uc.context.reserved) == 1076, "RV64 extension header");

static THREAD_LOCAL struct {
    rvvm_hart_t* cpu;
    volatile sig_atomic_t pending;
    siginfo_t info;
    /* At most one captured signal per number; later instances stay in Linux. */
    uint64_t deferred_mask;
    siginfo_t deferred[65];
    uint64_t mask;
    uint64_t saved_mask;
    bool restore_mask;
    struct user_sigstack stack;
    bool syscall_unstarted;
    bool synchronous;
} user_sig;
static THREAD_LOCAL bool user_native_child_active;
#include "rvvm_user_native_jump.h"
static void* user_sigtramp;
static void user_fault_handler(int, siginfo_t*, void*);
static void user_exec_trampoline(void*);

/* No C instructions can be inserted into this check-to-syscall window.
 * The host handler redirects an interrupted entry to the EINTR return.
 * A signal after the syscall instruction preserves its completed result. */
extern char user_safe_begin[], user_safe_end[], user_safe_abort[];
extern long user_safe_raw(volatile sig_atomic_t*, long, long, long, long, long, long, long);
#if defined(__aarch64__)
__asm__(".text\n.balign 4\n.global user_safe_raw\n.hidden user_safe_raw\n"
        "user_safe_raw:\n mov x9,x0\n mov x8,x1\n mov x0,x2\n mov x1,x3\n"
        "mov x2,x4\n mov x3,x5\n mov x4,x6\n mov x5,x7\n"
        ".global user_safe_begin\n.hidden user_safe_begin\nuser_safe_begin:\n"
        "ldr w10,[x9]\n cbnz w10,user_safe_abort\n svc #0\n"
        ".global user_safe_end\n.hidden user_safe_end\nuser_safe_end:\n ret\n"
        ".global user_safe_abort\n.hidden user_safe_abort\nuser_safe_abort:\n mov x0,#-512\n ret\n");
#elif defined(__x86_64__)
__asm__(".text\n.global user_safe_raw\n.hidden user_safe_raw\nuser_safe_raw:\n"
        "mov %rdi,%r11\n mov %rsi,%rax\n mov %rdx,%rdi\n mov %rcx,%rsi\n"
        "mov %r8,%rdx\n mov %r9,%r10\n mov 8(%rsp),%r8\n mov 16(%rsp),%r9\n"
        ".global user_safe_begin\n.hidden user_safe_begin\nuser_safe_begin:\n"
        "cmpl $0,(%r11)\n jne user_safe_abort\n syscall\n"
        ".global user_safe_end\n.hidden user_safe_end\nuser_safe_end:\n ret\n"
        ".global user_safe_abort\n.hidden user_safe_abort\nuser_safe_abort:\n mov $-512,%rax\n ret\n");
#else
#error "RVVM userspace signals need a safe syscall entry for this host"
#endif

static long user_safe_syscall(long nr, long a, long b, long c, long d, long e, long f)
{
    const void* set = NULL;
    size_t size = 0;
    struct { const void* set; size_t size; } select_mask;
    if (nr == SYS_rt_sigsuspend) {
        if (b != 8) { errno = EINVAL; return -1; }
        if (!a) { errno = EFAULT; return -1; }
        set = (void*)a; size = b;
    }
    if (nr == SYS_ppoll) { set = (void*)d; size = e; }
    if (nr == SYS_epoll_pwait || nr == SYS_epoll_pwait2) { set = (void*)e; size = f; }
    if (nr == SYS_pselect6 && f) {
        if (uapi_extra_copy(&select_mask, (void*)f, sizeof(select_mask), false)) { errno = EFAULT; return -1; }
        set = select_mask.set; size = select_mask.size;
    }
    uint64_t temporary, host_mask, original = user_sig.mask;
    if (set) {
        if (size != 8) { errno = EINVAL; return -1; }
        if (uapi_extra_copy(&temporary, (void*)set, 8, false)) { errno = EFAULT; return -1; }
        temporary &= ~(UINT64_C(1) << (SIGKILL - 1)) & ~(UINT64_C(1) << (SIGSTOP - 1));
        uint64_t ready = user_sig.deferred_mask & ~temporary;
        if (!user_sig.pending && ready) {
            int sig = __builtin_ctzll(ready) + 1;
            user_sig.info = user_sig.deferred[sig];
            user_sig.pending = sig;
            user_sig.deferred_mask &= ~(UINT64_C(1) << (sig - 1));
        }
        user_sig.mask = temporary;
        host_mask = temporary | user_sig.deferred_mask;
        if (nr == SYS_rt_sigsuspend) a = (long)&host_mask;
        else if (nr == SYS_ppoll) d = (long)&host_mask;
        else if (nr == SYS_pselect6) { select_mask.set = &host_mask; f = (long)&select_mask; }
        else e = (long)&host_mask;
    }
    long ret = user_safe_raw(&user_sig.pending, nr, a, b, c, d, e, f);
    if (ret == -512) {
        // No host syscall ran: resume its guest instruction after the handler,
        // regardless of SA_RESTART. Never expose this private result to Linux.
        user_sig.syscall_unstarted = !set;
        ret = -EINTR;
    }
    if (set) {
        if (ret == -EINTR && user_sig.pending) {
            user_sig.saved_mask = original;
            user_sig.restore_mask = true;
        } else user_sig.mask = original;
    }
    if ((unsigned long)ret >= (unsigned long)-4095) { errno = -ret; return -1; }
    return ret;
}
#define USER_SYSCALL(n,a,b,c,d,e,f) user_safe_syscall(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))

static uint64_t user_signal_mask(uint64_t mask)
{
    return mask & ~(UINT64_C(1) << (SIGKILL - 1)) & ~(UINT64_C(1) << (SIGSTOP - 1));
}

static void user_apply_mask(void)
{
    uint64_t held = UINT64_MAX;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, NULL, 8);
    uint64_t ready = user_sig.deferred_mask & ~user_sig.mask;
    if (!user_sig.pending && ready) {
        int sig = __builtin_ctzll(ready) + 1;
        user_sig.info = user_sig.deferred[sig];
        user_sig.pending = sig;
        user_sig.deferred_mask &= ~(UINT64_C(1) << (sig - 1));
    }
    uint64_t mask = user_sig.mask | user_sig.deferred_mask;
    if (user_sig.pending) mask = UINT64_MAX;
    /* Hardware faults must reach the dispatcher even while guest-blocked. */
    mask &= ~(UINT64_C(1) << (SIGSEGV - 1)) & ~(UINT64_C(1) << (SIGBUS - 1));
    if (user_sig.cpu) atomic_store_uint32(&user_sig.cpu->user_signal_pending, !!user_sig.pending);
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &mask, NULL, 8);
}

static void user_defer_pending(void)
{
    int sig = user_sig.pending;
    if (!sig) return;
    uint64_t bit = UINT64_C(1) << (sig - 1);
    if (!(user_sig.deferred_mask & bit)) user_sig.deferred[sig] = user_sig.info;
    user_sig.deferred_mask |= bit;
    user_sig.pending = 0;
}

static void user_signal_capture(int signo, siginfo_t* info, void* context)
{
    int saved_errno = errno;
    user_ptrace_restore_signal(info);
    ucontext_t* uc = context;
    user_defer_pending();
    user_sig.info = *info;
    user_sig.pending = signo;
    if (user_sig.cpu) {
        atomic_store_uint32(&user_sig.cpu->user_signal_pending, 1);
        atomic_store_uint32(&user_sig.cpu->running, 0);
    }
    /* Guest libc owns its private thread signals too. Credential syscalls must
     * bypass host libc's competing setxid protocol. */
    uint64_t held = UINT64_MAX
        & ~(UINT64_C(1) << (SIGSEGV - 1)) & ~(UINT64_C(1) << (SIGBUS - 1));
    memcpy(&uc->uc_sigmask, &held, 8);
#if defined(__aarch64__)
    uintptr_t pc = uc->uc_mcontext.pc;
    if (pc >= (uintptr_t)user_safe_begin && pc < (uintptr_t)user_safe_end)
        uc->uc_mcontext.pc = (uintptr_t)user_safe_abort;
#elif defined(__x86_64__)
    uintptr_t pc = uc->uc_mcontext.gregs[REG_RIP];
    if (pc >= (uintptr_t)user_safe_begin && pc < (uintptr_t)user_safe_end)
        uc->uc_mcontext.gregs[REG_RIP] = (uintptr_t)user_safe_abort;
#endif
    errno = saved_errno;
}

static int user_private_sigaction(int signo, uintptr_t handler)
{
    // libc rejects its reserved signals. Retain the native sigreturn restorer.
    struct {
        uint64_t handler, flags;
#if defined(__aarch64__) || defined(__x86_64__)
        uint64_t restorer;
#endif
        uint64_t mask;
    } kernel = {0}, fault;
    int result = syscall(SYS_rt_sigaction, SIGSEGV, NULL, &fault, 8);
    if (result) return result;
    kernel.handler = handler > 1 ? (uintptr_t)user_signal_capture : handler;
    kernel.flags = handler > 1 ? SA_SIGINFO : 0;
#if defined(__aarch64__) || defined(__x86_64__)
    kernel.flags |= fault.flags & UINT64_C(0x04000000);
    kernel.restorer = fault.restorer;
#endif
    kernel.mask = UINT64_MAX;
    return syscall(SYS_rt_sigaction, signo, &kernel, NULL, 8);
}

#include "rvvm_user_signal_mask.h"

static void user_private_signals_restore(void)
{
    // The first native pthread_create installs NPTL's setxid handler. Restore
    // guest ownership before publishing the new guest TID or running its code.
    spin_lock(&user_action_lock);
    for (int signo = 32; signo <= 33; signo++)
        if (user_private_installed[signo - 32]
            && user_private_sigaction(signo, user_actions[signo].handler))
            rvvm_fatal("Cannot restore guest private signal handler");
    spin_unlock(&user_action_lock);
}

static void user_host_sigfillset(sigset_t* set)
{
    sigfillset(set);
    // libc omits 32/33; guest dispatchers must also block those while updating
    // the per-thread pending signal and siginfo together.
    uint64_t all = UINT64_MAX;
    memcpy(set, &all, sizeof(all));
}

static long user_rt_sigaction(int signo, void* act, void* old, size_t size)
{
    // Linux permits querying uncatchable signals; only changes are forbidden.
    if (size != 8 || signo < 1 || signo > 64
        || (act && (signo == SIGKILL || signo == SIGSTOP))) return -EINVAL;
    struct user_sigaction next;
    if (act && uapi_extra_copy(&next, act, sizeof(next), false)) return -EFAULT;
    spin_lock(&user_action_lock);
    long ret = old ? uapi_extra_copy(&user_actions[signo], old, sizeof(next), true) : 0;
    if (!ret && act) {
        struct sigaction host = {0};
        if (next.handler > 1) {
            host.sa_sigaction = user_signal_capture;
            host.sa_flags = SA_SIGINFO | (next.flags & (SA_NOCLDSTOP | SA_NOCLDWAIT));
            user_host_sigfillset(&host.sa_mask);
        } else host.sa_handler = (void*)(uintptr_t)next.handler;
        // Retain the emulator fault dispatcher even for guest DFL/IGN actions.
        // It distinguishes kernel memory faults from kill/raise/queued signals.
        if (signo == SIGSEGV || signo == SIGBUS) {
            host.sa_sigaction = user_fault_handler;
            host.sa_flags = SA_SIGINFO;
            user_host_sigfillset(&host.sa_mask);
        }
        int result;
        if (signo == 32 || signo == 33) {
            result = user_private_sigaction(signo, next.handler);
            if (!result) user_private_installed[signo - 32] = true;
        } else result = sigaction(signo, &host, NULL);
        if (result) ret = -errno;
        else user_actions[signo] = next;
    }
    spin_unlock(&user_action_lock);
    return ret;
}

static long user_rt_sigprocmask(int how, void* set, void* old, size_t size)
{
    if (size != 8) return -EINVAL;
    uint64_t mask;
    if (set && uapi_extra_copy(&mask, set, 8, false)) return -EFAULT;
    if (set && how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) return -EINVAL;
    if (old && uapi_extra_copy(&user_sig.mask, old, 8, true)) return -EFAULT;
    if (set) {
        if (how == SIG_BLOCK) mask |= user_sig.mask;
        if (how == SIG_UNBLOCK) mask = user_sig.mask & ~mask;
        user_sig.mask = user_signal_mask(mask);
        user_apply_mask();
    }
    return 0;
}

#define USER_SS_AUTODISARM (1U << 31)
static bool user_on_altstack(uint64_t sp)
{
    return !(user_sig.stack.flags & USER_SS_AUTODISARM) && user_sig.stack.size
        && sp > user_sig.stack.sp && sp - user_sig.stack.sp <= user_sig.stack.size;
}

static int user_set_altstack(const struct user_sigstack* next, uint64_t sp)
{
    if (user_on_altstack(sp)) return -EPERM;
    unsigned mode = (uint32_t)next->flags & ~USER_SS_AUTODISARM;
    if (mode != 0 && mode != SS_DISABLE && mode != SS_ONSTACK) return -EINVAL;
    if (mode != SS_DISABLE && next->size < 2048) return -ENOMEM; // RV64 MINSIGSTKSZ
    user_sig.stack = *next;
    user_sig.stack.pad = 0;
    if (mode == SS_DISABLE) { user_sig.stack.sp = 0; user_sig.stack.size = 0; }
    return 0;
}

static long user_sigaltstack(rvvm_hart_t* cpu, void* set, void* old)
{
    struct user_sigstack next, previous = user_sig.stack;
    uint64_t sp = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 2);
    if (set && uapi_extra_copy(&next, set, sizeof(next), false)) return -EFAULT;
    previous.flags = (previous.flags & USER_SS_AUTODISARM)
        | (!previous.size ? SS_DISABLE : user_on_altstack(sp) ? SS_ONSTACK : 0);
    int ret = set ? user_set_altstack(&next, sp) : 0;
    if (!ret && old) ret = uapi_extra_copy(&previous, old, sizeof(previous), true);
    return ret;
}

static void user_info_convert(struct user_siginfo* dst, const siginfo_t* src)
{
    memset(dst, 0, sizeof(*dst));
    dst->signo = src->si_signo; dst->error = src->si_errno; dst->code = src->si_code;
    if ((src->si_signo == SIGBUS || src->si_signo == SIGSEGV
         || src->si_signo == SIGILL || src->si_signo == SIGTRAP || src->si_signo == SIGFPE) && src->si_code > 0) {
        dst->data.fault.address = (uintptr_t)src->si_addr;
    } else if (src->si_code == SI_TIMER) {
        dst->data.timer.id = src->si_timerid; dst->data.timer.overrun = src->si_overrun;
        dst->data.timer.value = (uintptr_t)src->si_value.sival_ptr;
    } else if (src->si_signo == SIGCHLD && src->si_code > 0) {
        dst->data.child.pid = src->si_pid; dst->data.child.uid = src->si_uid;
        dst->data.child.status = src->si_status;
        dst->data.child.utime = src->si_utime; dst->data.child.stime = src->si_stime;
    } else {
        dst->data.sender.pid = src->si_pid; dst->data.sender.uid = src->si_uid;
        dst->data.sender.value = (uintptr_t)src->si_value.sival_ptr;
    }
}

static long user_rt_sigpending(void* out, size_t size)
{
    if (size > 8) return -EINVAL;
    uint64_t mask = 0;
    if (syscall(SYS_rt_sigpending, &mask, size)) return -errno;
    mask |= user_sig.deferred_mask & user_sig.mask;
    return uapi_extra_copy(&mask, out, size, true);
}

static long user_rt_sigtimedwait(void* set, void* out, void* timeout, size_t size)
{
    uint64_t mask;
    if (size != 8) return -EINVAL;
    if (uapi_extra_copy(&mask, set, 8, false)) return -EFAULT;
    if (timeout) {
        struct timespec ts;
        if (uapi_extra_copy(&ts, timeout, sizeof(ts), false)) return -EFAULT;
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000) return -EINVAL;
    }
    siginfo_t info;
    uint64_t ready = mask & user_sig.deferred_mask;
    long ret;
    if (ready) {
        ret = __builtin_ctzll(ready) + 1;
        info = user_sig.deferred[ret];
        user_sig.deferred_mask &= ~(UINT64_C(1) << (ret - 1));
        user_apply_mask();
    } else {
        ret = USER_SYSCALL(SYS_rt_sigtimedwait, set, &info, timeout, size, 0, 0);
        if (ret < 0) return -errno;
    }
    if (out) {
        struct user_siginfo guest;
        user_info_convert(&guest, &info);
        if (uapi_extra_copy(&guest, out, sizeof(guest), true)) return -EFAULT;
    }
    return ret;
}

static void user_bad_signal_frame(int signo)
{
    uint64_t held = UINT64_MAX;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, NULL, 8);
    if (signo == SIGSEGV) {
        spin_lock(&user_action_lock);
        user_actions[SIGSEGV].handler = 0;
        spin_unlock(&user_action_lock);
    }
    user_defer_pending();
    memset(&user_sig.info, 0, sizeof(user_sig.info));
    user_sig.info.si_signo = SIGSEGV;
    user_sig.info.si_code = SI_KERNEL;
    user_sig.pending = SIGSEGV;
    user_sig.synchronous = true;
}

static void user_fault_address(rvvm_hart_t* cpu)
{
    /* x86 reports #GP for a noncanonical pointer as SI_KERNEL with no address.
     * Recover the guest effective address from its pre-instruction registers. */
    if (user_sig.info.si_signo != SIGSEGV || user_sig.info.si_code != SI_KERNEL) return;
    uintptr_t pc = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC), addr = pc;
    uint32_t insn = 0;
    if (!uapi_extra_copy(&insn, (void*)pc, 2, false)) {
        unsigned base = 0; int64_t offset = 0;
        if ((insn & 3) == 3 && !uapi_extra_copy(&insn, (void*)pc, 4, false)) {
            base = (insn >> 15) & 31;
            switch (insn & 0x7f) {
                case 3: case 7: offset = (int32_t)insn >> 20; break;
                case 0x23: case 0x27:
                    offset = ((int32_t)insn >> 25) * 32 + ((insn >> 7) & 31); break;
                case 0x2f: break;
                case 0x0f: break;
                default: return;
            }
        } else if ((insn & 3) == 0) {
            base = 8 + ((insn >> 7) & 7);
            unsigned kind = insn >> 13;
            if (kind == 2 || kind == 6)
                offset = ((insn << 1) & 0x40) | ((insn >> 4) & 4) | ((insn >> 7) & 0x38);
            else if (kind == 4)
                offset = ((insn & 0x20) >> 4) | ((insn & 0x400) ? 0 : ((insn & 0x40) >> 6));
            else offset = ((insn << 1) & 0xc0) | ((insn >> 7) & 0x38);
        } else if ((insn & 3) == 2) {
            base = 2;
            switch (insn >> 13) {
                case 1: case 3: offset = ((insn >> 2) & 0x18) | ((insn >> 7) & 0x20) | ((insn << 4) & 0x1c0); break;
                case 2: offset = ((insn >> 2) & 0x1c) | ((insn >> 7) & 0x20) | ((insn << 4) & 0xc0); break;
                case 5: case 7: offset = ((insn >> 1) & 0x1c0) | ((insn >> 7) & 0x38); break;
                case 6: offset = ((insn >> 1) & 0xc0) | ((insn >> 7) & 0x3c); break;
                default: return;
            }
        } else return;
        addr = (base ? rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + base) : 0) + offset;
        if ((insn & 0x7f) == 0x0f) addr &= ~(uintptr_t)63;
    }
    user_sig.info.si_addr = (void*)addr;
    user_sig.info.si_code = SEGV_MAPERR;
}

static void user_signal_init(rvvm_hart_t* cpu, uint64_t mask)
{
    memset(&user_sig, 0, sizeof(user_sig));
    user_sig.cpu = cpu;
    user_sig.mask = mask;
    user_sig.stack.flags = SS_DISABLE;
    DO_ONCE({
        for (int signo = 1; signo <= 64; ++signo) {
            struct sigaction inherited;
            if (!sigaction(signo, NULL, &inherited) && inherited.sa_handler == SIG_IGN)
                user_actions[signo].handler = 1;
        }
        uint32_t code[2];
        code[0] = 0x08b00893; // li a7,139
        code[1] = 0x00000073; // ecall
        user_fd_lock();
        user_sigtramp = user_vma_map(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        user_fd_unlock();
        if (user_sigtramp == MAP_FAILED) abort();
        memcpy(user_sigtramp, code, sizeof(code));
        if (mprotect(user_sigtramp, 4096, PROT_READ)) abort();
        user_exec_trampoline(user_sigtramp);
    });
    user_apply_mask();
}

static void user_signal_deliver(rvvm_hart_t* cpu)
{
    if (!user_sig.pending) return;
    // Fault-recovering frame copies need native faults even while guest signals
    // are held. Their leaf-PC fixup does not touch the pending guest signal.
    uint64_t held = UINT64_MAX & ~(UINT64_C(1) << (SIGSEGV - 1))
                              & ~(UINT64_C(1) << (SIGBUS - 1));
retry:
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, NULL, 8);
    if (user_sig.pending && !user_sig.synchronous
        && (user_sig.mask & (UINT64_C(1) << (user_sig.pending - 1)))) {
        user_defer_pending();
        user_apply_mask();
    }
    int signo = user_sig.pending;
    if (!signo) { user_apply_mask(); return; }
    struct user_sigaction act;
    spin_lock(&user_action_lock);
    act = user_actions[signo];
    /* Linux forces synchronous faults through DFL if blocked or ignored. */
    if (user_sig.synchronous && (act.handler == 1 || (user_sig.mask & (UINT64_C(1) << (signo - 1))))) {
        act.handler = 0;
        user_sig.mask &= ~(UINT64_C(1) << (signo - 1));
    }
    if (act.flags & SA_RESETHAND) user_actions[signo].handler = 0;
    spin_unlock(&user_action_lock);
    user_sig.synchronous = false;
    if (act.handler <= 1) {
        user_sig.pending = 0;
        atomic_store_uint32(&cpu->user_signal_pending, 0);
        if (!act.handler) {
            struct sigaction sa = { .sa_handler = SIG_DFL };
            if (signo == 32 || signo == 33) user_private_sigaction(signo, 0);
            else sigaction(signo, &sa, NULL);
            syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), signo);
        }
        if (user_sig.restore_mask) {
            user_sig.mask = user_sig.saved_mask;
            user_sig.restore_mask = false;
        }
        user_apply_mask();
        return;
    }
    struct user_sigframe frame = {0};
    user_info_convert(&frame.info, &user_sig.info);
    frame.uc.mask = user_sig.restore_mask ? user_sig.saved_mask : user_sig.mask;
    frame.uc.stack = user_sig.stack;
    for (unsigned i = 1; i < 32; ++i) frame.uc.context.regs[i] = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + i);
    frame.uc.context.regs[0] = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC);
    for (unsigned i = 0; i < 32; ++i) frame.uc.context.fp[i] = rvvm_read_cpu_reg(cpu, RVVM_REGID_F0 + i);
    rvvm_uxlen_t fcsr = 0;
    riscv_csr_op(cpu, CSR_FCSR, &fcsr, CSR_SETBITS);
    frame.uc.context.fcsr = fcsr;
    uintptr_t original_sp = frame.uc.context.regs[2], top = original_sp;
    bool on_stack = user_on_altstack(original_sp);
    bool switch_stack = (act.flags & SA_ONSTACK) && user_sig.stack.size && !on_stack;
    if (switch_stack) {
        top = user_sig.stack.sp + user_sig.stack.size;
        if (top < user_sig.stack.sp) goto badframe;
    }
    uintptr_t sp = (top - sizeof(frame)) & ~(uintptr_t)15;
    if (top < sizeof(frame) || ((on_stack || switch_stack) && sp < user_sig.stack.sp))
        goto badframe;
    // Match Linux's sparse writes, including the 264-byte D extension. Go can
    // leave a return address below SP briefly; zeroing unused Q-state storage
    // corrupts it when libc's setxid handler runs without an alternate stack.
    const size_t offsets[] = {0, offsetof(struct user_sigframe, uc.context),
                             offsetof(struct user_sigframe, uc.context.reserved)};
    const size_t lengths[] = {offsetof(struct user_sigframe, uc.mask_pad), 256 + 264, 12};
    for (unsigned i = 0; i < 3; i++) {
        if (user_memory_copy((void*)(sp + offsets[i]), (char*)&frame + offsets[i], lengths[i]))
            goto badframe;
    }
    if (user_sig.stack.flags & USER_SS_AUTODISARM)
        user_sig.stack = (struct user_sigstack){ .flags = SS_DISABLE };
    cpu->lrsc = false;
    rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, act.handler);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 1, (uintptr_t)user_sigtramp);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 2, sp);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 10, signo);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 11, sp);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 12, sp + offsetof(struct user_sigframe, uc));
    user_sig.mask |= act.mask;
    if (!(act.flags & SA_NODEFER)) user_sig.mask |= UINT64_C(1) << (signo - 1);
    user_sig.mask = user_signal_mask(user_sig.mask);
    user_sig.restore_mask = false;
    user_sig.pending = 0;
    atomic_store_uint32(&cpu->user_signal_pending, 0);
    user_apply_mask();
    return;
badframe:
    user_sig.pending = 0; // The failed delivery consumes this signal.
    user_bad_signal_frame(signo);
    goto retry;
}

static void user_rt_sigreturn(rvvm_hart_t* cpu)
{
    struct user_sigframe frame;
    uintptr_t sp = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 2);
    if ((sp & 15) || user_memory_copy(&frame, (void*)sp, sizeof(frame))
        || frame.uc.context.reserved || frame.uc.context.magic || frame.uc.context.size)
    {
        user_bad_signal_frame(0);
        return;
    }
    for (unsigned i = 1; i < 32; ++i) rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + i, frame.uc.context.regs[i]);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, frame.uc.context.regs[0]);
    for (unsigned i = 0; i < 32; ++i) rvvm_write_cpu_reg(cpu, RVVM_REGID_F0 + i, frame.uc.context.fp[i]);
    rvvm_uxlen_t fcsr = frame.uc.context.fcsr & 255;
    riscv_csr_op(cpu, CSR_FCSR, &fcsr, CSR_SWAP);
    user_sig.mask = user_signal_mask(frame.uc.mask);
    (void)user_set_altstack(&frame.uc.stack, frame.uc.context.regs[2]);
    cpu->lrsc = false;
    user_apply_mask();
}

static bool user_restart_syscall(rvvm_hart_t* cpu, unsigned nr)
{
    // Guest registers still contain the original arguments, including the fd.
    unsigned long a0 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10);
    unsigned long a1 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 11);
    unsigned long a3 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 13);
    if (nr == 98) {
        // A timed futex wait uses ERESTART_RESTARTBLOCK, which Linux exposes as
        // EINTR when a handler runs, even with SA_RESTART. Never reset its timer.
        unsigned op = a1 & FUTEX_CMD_MASK;
        return !a3 && (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET);
    }
    int timeout_option = 0;
    switch (nr) {
        case 202: case 207: case 212: case 242: // accept, recvfrom, recvmsg, accept4
            timeout_option = SO_RCVTIMEO;
            break;
        case 203: case 206: case 211: case 269: // connect, sendto, sendmsg, sendmmsg
            timeout_option = SO_SNDTIMEO;
            break;
        case 243: // recvmmsg
            timeout_option = SO_RCVTIMEO;
            break;
    }
    if (timeout_option) {
        struct timeval timeout;
        socklen_t size = sizeof(timeout);
        return !getsockopt(a0, SOL_SOCKET, timeout_option, &timeout, &size)
            && !timeout.tv_sec && !timeout.tv_usec;
    }
    // epoll/poll/select/sigsuspend deliberately remain EINTR with SA_RESTART.
    return nr == 25 || nr == 32 || nr == 56 || nr == 63 || nr == 64
        || nr == 65 || nr == 66 || nr == 67 || nr == 68 || nr == 69 || nr == 70 || nr == 77
        || nr == 75 || nr == 116 || nr == 182 || nr == 183 || nr == 286 || nr == 287
        || nr == 95 || nr == 260 || nr == 278 || nr == 437;
}

static long user_epoll_wait(long nr, int fd, void* events, int maxevents,
                           uintptr_t timeout, const void* mask, size_t masksize)
{
    if (maxevents <= 0 || maxevents > INT_MAX / 16) return -EINVAL;
    struct epoll_event host[128];
    struct uapi_extra_epoll_event guest[128];
    int count = maxevents > 128 ? 128 : maxevents;
    long ret = USER_SYSCALL(nr, fd, host, count, timeout, mask, masksize);
    if (ret < 0) return -errno;
    for (long i = 0; i < ret; ++i) {
        guest[i].events = host[i].events;
        guest[i].padding = 0;
        guest[i].data = host[i].data.u64;
    }
    if (ret && uapi_extra_copy(guest, events, ret * sizeof(*guest), true)) return -EFAULT;
    return ret;
}

static long user_sigqueue(int tgid, int tid, int signo, void* guest, bool thread)
{
    struct user_siginfo info;
    if (uapi_extra_copy(&info, guest, sizeof(info), false)) return -EFAULT;
    // glibc AIO queues SI_ASYNCIO with the same sender/value layout.
    if (info.code != SI_QUEUE && info.code != SI_ASYNCIO && info.code != SI_MESGQ) return -ENOSYS;
    siginfo_t host = {0};
    host.si_signo = info.signo; host.si_errno = info.error; host.si_code = info.code;
    host.si_pid = info.data.sender.pid; host.si_uid = info.data.sender.uid;
    host.si_value.sival_ptr = (void*)(uintptr_t)info.data.sender.value;
    long ret = thread ? syscall(SYS_rt_tgsigqueueinfo, tgid, tid, signo, &host)
                      : syscall(SYS_rt_sigqueueinfo, tgid, signo, &host);
    return ret < 0 ? -errno : ret;
}

#endif
