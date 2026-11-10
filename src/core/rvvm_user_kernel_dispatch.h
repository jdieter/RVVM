/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_KERNEL_DISPATCH_H
#define RVVM_USER_KERNEL_DISPATCH_H

_Static_assert(sizeof(long) == 8 && sizeof(struct iovec) == 16
               && sizeof(struct timeval) == 16 && sizeof(struct timezone) == 8
               && sizeof(struct timex) == 208, "RV64 Linux time and vector ABI");
_Static_assert(sizeof(struct sigevent) == 64
               && offsetof(struct sigevent, sigev_value) == 0
               && offsetof(struct sigevent, sigev_signo) == 8
               && offsetof(struct sigevent, sigev_notify) == 12
               && offsetof(struct sigevent, _sigev_un._tid) == 16, "RV64 sigevent ABI");
_Static_assert(sizeof(struct pollfd) == 8 && offsetof(struct pollfd, events) == 4
               && offsetof(struct pollfd, revents) == 6, "RV64 poll ABI");

/* Both runtimes use the same ABI conversion and signal-aware kernel entry.
 * Shared-mm children select private tracing/descriptor contexts and allocate
 * through their worker. Lifecycle and mapping publication stay with callers. */
static void user_wait_reaped(pid_t pid)
{
    /* A shared-mm child has no ordinary-fork cache of its own. */
    if (user_native_child_active) return;
    user_fork_cache_reaped(pid);
}

/* An init or subreaper guest's __WALL/__WCLONE waits for any child would
 * also select its direct observer: Linux can't exclude one child. Poll
 * with WNOHANG instead, report ECHILD once only internal tasks remain, and
 * otherwise sleep (1-10ms backoff) interruptibly by guest signals. */
static long user_wait_backoff(unsigned* delay)
{
    struct timespec pause = {0, (long)*delay * 1000000};
    long slept = (long)errno_ret(USER_SYSCALL(SYS_nanosleep, &pause, NULL, 0, 0, 0, 0));
    if (slept == -EINTR) return -EINTR;
    if (*delay < 10) *delay = *delay * 2 > 10 ? 10 : *delay * 2;
    return USER_PTRACE_WAIT_AGAIN;
}

/* Whether a wait with no ready child should end: ECHILD without real
 * children, 0 for WNOHANG, or a backoff before polling again. */
static long user_wait_internal(struct user_observer* direct, bool nohang, unsigned* delay)
{
    if (!user_observer_others(direct)) return -ECHILD;
    return nohang ? 0 : user_wait_backoff(delay);
}

static long user_wait4(long a[6])
{
    long ret, queued;
    bool started = false;
    struct user_observer* direct = a[0] == -1 && (a[2] & (__WALL | __WCLONE)) ? user_observer_direct() : NULL;
    unsigned delay = 1;
    do {
        bool poll = user_ptrace_events_tracing() && !(a[2] & WNOHANG);
        uint32_t generation = poll ? user_ptrace_events_generation() : 0;
        int scratch;
        int* status = a[1] ? (void*)a[1] : &scratch;
        if (user_ptrace_wait_ready(a[0], status, a[2], (void*)a[3], &queued)) return queued;
        ret = (long)errno_ret(USER_SYSCALL(SYS_wait4, a[0], status,
            a[2] | (poll || direct ? WNOHANG : 0), a[3], 0, 0));
        if (user_observer_hidden(ret, ret > 0 && (WIFEXITED(*status) || WIFSIGNALED(*status)))) {
            ret = USER_PTRACE_WAIT_AGAIN;
            continue;
        }
        if (direct && !ret && !poll) {
            started = true;
            ret = user_wait_internal(direct, a[2] & WNOHANG, &delay);
            if (ret == USER_PTRACE_WAIT_AGAIN) continue;
        }
        if (ret > 0 && (WIFEXITED(*status) || WIFSIGNALED(*status))) user_wait_reaped(ret);
        if (started && ret == -EINTR) user_sig.syscall_unstarted = false;
        if (poll && !ret) {
            started = true;
            ret = user_ptrace_wait_pause(generation);
            continue;
        }
        ret = user_ptrace_wait(ret, status);
    } while (ret == USER_PTRACE_WAIT_AGAIN);
    return ret;
}

static long user_waitid(long a[6])
{
    long ret, queued;
    bool started = false;
    struct user_observer* direct = a[0] == P_ALL && (a[3] & (__WALL | __WCLONE)) ? user_observer_direct() : NULL;
    unsigned delay = 1;
    do {
        bool poll = !(a[3] & WNOHANG) && (user_ptrace_events_tracing()
            || (a[3] & (WNOWAIT | WSTOPPED)) == (WNOWAIT | WSTOPPED));
        if (poll && a[0] == 3 && (fcntl((int)a[1], F_GETFL) & O_NONBLOCK)) poll = false;
        uint32_t generation = poll ? user_ptrace_events_generation() : 0;
        siginfo_t scratch = {0};
        siginfo_t* caller = a[2] ? (void*)a[2] : &scratch;
        if (user_ptrace_waitid_ready(a[0], a[1], caller, a[3], (void*)a[4], &queued)) return queued;
        siginfo_t* native = poll ? &scratch : caller;
        ret = (long)errno_ret(USER_SYSCALL(SYS_waitid, (int)a[0], (unsigned)a[1],
            native, (int)a[3] | (poll || direct ? WNOHANG : 0), a[4], 0));
        if (!ret && user_observer_hidden(native->si_pid, !(a[3] & WNOWAIT)
                && (native->si_code == CLD_EXITED || native->si_code == CLD_KILLED
                    || native->si_code == CLD_DUMPED))) {
            ret = USER_PTRACE_WAIT_AGAIN;
            continue;
        }
        if (direct && !ret && !native->si_pid && !poll) {
            started = true;
            ret = user_wait_internal(direct, a[3] & WNOHANG, &delay);
            if (ret == USER_PTRACE_WAIT_AGAIN) continue;
        }
        if (!ret && native->si_pid && !(a[3] & WNOWAIT)
            && (native->si_code == CLD_EXITED || native->si_code == CLD_KILLED
                || native->si_code == CLD_DUMPED)) user_wait_reaped(native->si_pid);
        if (started && ret == -EINTR) user_sig.syscall_unstarted = false;
        if (poll && !ret && !scratch.si_pid) {
            started = true;
            ret = user_ptrace_wait_pause(generation);
            continue;
        }
        ret = user_ptrace_waitid(ret, native, a[3]);
        if (poll && !ret && a[2]) ret = uapi_extra_copy(&scratch, (void*)a[2], sizeof(scratch), true);
    } while (ret == USER_PTRACE_WAIT_AGAIN);
    return ret;
}

/* Provision the observer before this process lowers its own NOFILE limit. */
static void user_observer_limit(pid_t pid, long resource, void* limit)
{
    struct rlimit next;
    if (resource != RLIMIT_NOFILE || !limit || (pid && pid != getpid())
        || uapi_extra_copy(&next, limit, sizeof(next), false)) return;
    user_observer_provision(next.rlim_cur, next.rlim_max);
}

/* A guest call naming one of RVVM's internal tasks, or the process group
 * each leads after setsid, finds no such process or child. */
static long user_internal_target(long nr, const long* a)
{
    long pid = 0, thread = 0;
    switch (nr) {
        case 129: pid = a[0] < -1 ? -a[0] : a[0]; break; // kill
        case 130: case 138: case 434: pid = a[0]; break; // tkill, rt_sigqueueinfo, pidfd_open
        case 131: case 240: pid = a[0]; thread = a[1]; break; // tgkill, rt_tgsigqueueinfo
        case 118: case 119: case 120: case 121: case 122: case 123: case 127: case 274: case 275:
            pid = a[0]; break; // sched_*
        case 140: case 141: if (a[0] == PRIO_PROCESS || a[0] == PRIO_PGRP) pid = a[1]; break;
        case 30: case 31: if (a[0] == 1 || a[0] == 2) pid = a[1]; break; // ioprio: process, group
        case 154: case 155: case 156: pid = a[0]; break; // setpgid, getpgid, getsid
        case 100: case 238: case 239: case 261: case 270: case 271: pid = a[0]; break;
        case 117: pid = a[1]; break; // ptrace
        case 260:
            return user_internal_task(a[0] < -1 ? -a[0] : a[0]) ? -ECHILD : 0;
        case 95:
            return (a[0] == P_PID || a[0] == P_PGID) && user_internal_task(a[1]) ? -ECHILD : 0;
        default: return 0;
    }
    return user_internal_task(pid) || user_internal_task(thread) ? -ESRCH : 0;
}

static bool user_kernel_dispatch(rvvm_hart_t* cpu, long nr, long a[6], long* result)
{
    long host;
    long hidden = user_internal_target(nr, a);
    if (hidden) { *result = hidden; return true; }
    switch (nr) {
        case 95: *result = user_waitid(a); return true;
        case 117: *result = user_ptrace_request(a[0], a[1], a[2], a[3]); return true;
        case 138: *result = user_sigqueue(a[0], 0, a[1], (void*)a[2], false); return true;
        case 240: *result = user_sigqueue(a[0], a[1], a[2], (void*)a[3], true); return true;
        case 89: *result = user_host_path_call(SYS_acct, a[0], 0, 0, 0, 0); return true;
        case 224: *result = user_host_path_call(SYS_swapon, a[0], a[1], 0, 0, 0); return true;
        case 225: *result = user_host_path_call(SYS_swapoff, a[0], 0, 0, 0, 0); return true;
        case 41: *result = user_host_path_call(SYS_pivot_root, a[0], a[1], 0, 0, 0); return true;
        case 268:
            /* Prepare only for a PID namespace: the workers are threads, and
             * entering a user namespace needs a single-threaded caller. */
            if (!(a[1] & CLONE_NEWUSER)) {
                long type = a[1] ? a[1] : (long)ioctl((int)a[0], 0xb703 /* NS_GET_NSTYPE */);
                if (type > 0 && (type & CLONE_NEWPID)) user_observer_namespace(CLONE_NEWPID);
            }
            *result = user_host_fd_call(SYS_setns, a[0], a[1], 0); return true;
        case 428: *result = user_host_path_call(SYS_open_tree, a[0], a[1], a[2], 0, 0); return true;
        case 429: *result = user_host_path_call(SYS_move_mount, a[0], a[1], a[2], a[3], a[4]); return true;
        case 431: *result = user_host_fsconfig(a[0], a[1], (void*)a[2], (void*)a[3], a[4]); return true;
        case 432: *result = user_host_fd_call(SYS_fsmount, a[0], a[1], a[2]); return true;
        case 433: *result = user_host_path_call(SYS_fspick, a[0], a[1], a[2], 0, 0); return true;
        case 442: *result = user_host_mount_setattr(a[0], (void*)a[1], a[2], (void*)a[3], a[4]); return true;
        case 219: *result = user_host_keyctl(a[0], a[1], a[2], a[3], a[4]); return true;
        case 60: *result = user_host_quotactl(a[0], (void*)a[1], a[2], a[3]); return true;
        case 443: *result = user_host_quotactl_fd(a[0], a[1], a[2], a[3]); return true;
        case 260: *result = user_wait4(a); return true;
        case 17: *result = rvvm_sys_getcwd((void*)a[0], a[1]); return true;
        /* Hides private descriptors, untraced tasks and internal tasks. */
        case 61: *result = rvvm_sys_getdents64(a[0], (void*)a[1], a[2]); return true;
        case 78: *result = rvvm_sys_readlinkat(a[0], (void*)a[1], (void*)a[2], a[3]); return true;
        case 56: *result = rvvm_sys_openat(a[0], (const char*)a[1], a[2], a[3]); return true;
#ifdef SYS_openat2
        case 437: *result = (long)rvvm_sys_openat2(a[0], (const char*)a[1], (void*)a[2], a[3]); return true;
#endif
        case 258: *result = user_cpu_hwprobe((void*)a[0], a[1], a[2], (void*)a[3], a[4]); return true;
        case 30: case 31: case 81: case 84: case 274: case 275:
            *result = user_control_extra(nr, a[0], a[1], a[2], a[3]); return true;
        case 75: *result = user_io_vmsplice(a[0], a[1], a[2], a[3]); return true;
        case 243: *result = user_io_recvmmsg(a[0], a[1], a[2], a[3], a[4]); return true;
        case 181: case 182: case 183: case 185: case 190: case 192: case 193:
            *result = user_ipc_syscall(nr, a[0], a[1], a[2], a[3], a[4]); return true;
        case 186: case 187: case 188: case 189:
            *result = user_msg_syscall(nr, a[0], a[1], a[2], a[3], a[4]); return true;
        case 116: *result = user_system_control(nr, a[0], a[1], a[2]); return true;
        case 228: case 229: case 284:
            *result = user_lock_memory(nr, a[0], a[1], a[2]); return true;
        case 451: *result = user_fs_cachestat(a[0], a[1], a[2], a[3]); return true;
        case 263:
            if (user_private_fd((int)a[3])) a[3] = -1;
            *result = user_fs_fanotify_mark(a[0], a[1], a[2], a[3], (const char*)a[4]); return true;
        case 180: *result = uapi_extra_mq_open((const char*)a[0], a[1], a[2], (void*)a[3]); return true;
        case 191: *result = uapi_extra_semctl(a[0], a[1], a[2], a[3]); return true;
        case 262: *result = uapi_extra_fanotify_init(a[0], a[1]); return true;
        case 265: *result = uapi_extra_open_by_handle_at(a[0], (void*)a[1], a[2]); return true;
        case 21: {
            struct epoll_event host_event, *event = NULL;
            if (a[3] && a[1] != EPOLL_CTL_DEL) {
                struct uapi_epoll_event guest;
                if (uapi_extra_copy(&guest, (void*)a[3], sizeof(guest), false)) {
                    *result = -EFAULT; return true;
                }
                host_event.events = guest.event;
                host_event.data.u64 = guest.data.u64;
                event = &host_event;
            }
            *result = (long)errno_ret(USER_SYSCALL(SYS_epoll_ctl, a[0], a[1], a[2], event, 0, 0));
            return true;
        }
        case 22: case 441:
            *result = user_epoll_wait(nr == 22 ? SYS_epoll_pwait : SYS_epoll_pwait2,
                a[0], (void*)a[1], a[2], a[3], (void*)a[4], a[5]);
            return true;
        case 59:
            *result = (long)errno_ret(USER_SYSCALL(SYS_pipe2, a[0], uapi_open_flags_to_host(a[1]), 0, 0, 0, 0));
            return true;
        case 43: case 44: {
            struct statfs st;
            char snapshot[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
            const char* path = (const char*)a[0];
            if (nr == 43) user_host_path(snapshot, wrapped, &path);
            long ret = nr == 43 ? (long)errno_ret(USER_SYSCALL(SYS_statfs, path, &st, 0, 0, 0, 0))
                : (long)errno_ret(USER_SYSCALL(SYS_fstatfs, a[0], &st, 0, 0, 0, 0));
            if (!ret) {
                struct uapi_statfs64 guest;
                uapi_statfs64_convert(&guest, &st);
                ret = uapi_extra_copy(&guest, (void*)a[1], sizeof(guest), true);
            }
            *result = ret; return true;
        }
        case 79: case 80: {
            char snapshot[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
            const char* path = (const char*)a[1];
            if (nr == 79) user_host_path(snapshot, wrapped, &path);
#if defined(__aarch64__) && defined(__AARCH64EL__)
            *result = nr == 79 ? (long)errno_ret(USER_SYSCALL(SYS_newfstatat, a[0], path, a[2], a[3], 0, 0))
                : (long)errno_ret(USER_SYSCALL(SYS_fstat, a[0], a[1], 0, 0, 0, 0));
#else
            struct stat st;
            long ret = nr == 79 ? (long)errno_ret(USER_SYSCALL(SYS_newfstatat, a[0], path, &st, a[3], 0, 0))
                : (long)errno_ret(USER_SYSCALL(SYS_fstat, a[0], &st, 0, 0, 0, 0));
            if (!ret) {
                struct uapi_stat guest;
                uapi_stat_convert(&guest, &st);
                ret = uapi_extra_copy(&guest, (void*)(nr == 79 ? a[2] : a[1]), sizeof(guest), true);
            }
            *result = ret;
#endif
            return true;
        }
        case 98: *result = rvvm_sys_futex((void*)a[0], a[1], a[2], a[3], (void*)a[4], a[5]); return true;
        case 113: case 114: {
            /* Keep the host vDSO fast path, without letting its direct store
             * turn an invalid guest output pointer into an emulator fault. */
            struct timespec value;
            long ret = (long)errno_ret(nr == 113 ? clock_gettime(a[0], &value)
                : clock_getres(a[0], a[1] ? &value : NULL));
            if (!ret && (nr == 113 || a[1])) ret = user_memory_copy((void*)a[1], &value, sizeof(value));
            *result = ret; return true;
        }
        case 69: case 70: case 286: case 287:
            *result = user_posix_vector(nr == 69 ? SYS_preadv : nr == 70 ? SYS_pwritev
                : nr == 286 ? SYS_preadv2 : SYS_pwritev2,
                a[0], a[1], a[2], a[3], a[4], nr < 286 ? 0 : a[5]);
            return true;
        case 118: case 119: case 120: case 121: case 125: case 126: case 127:
            *result = user_posix_scheduler(nr, a[0], a[1], a[2]); return true;
        case 132: *result = user_sigaltstack(cpu, (void*)a[0], (void*)a[1]); return true;
        case 134: *result = user_rt_sigaction(a[0], (void*)a[1], (void*)a[2], a[3]); return true;
        case 135: *result = user_rt_sigprocmask(a[0], (void*)a[1], (void*)a[2], a[3]); return true;
        case 136: *result = user_rt_sigpending((void*)a[0], a[1]); return true;
        case 137: *result = user_rt_sigtimedwait((void*)a[0], (void*)a[1], (void*)a[2], a[3]); return true;
        case 143: case 145:
            if (fake_root) {
                int* identity = nr == 143 ? &fake_gid : &fake_uid;
                if ((uint32_t)a[1] != UINT32_MAX) *identity = a[1];
                else if ((uint32_t)a[0] != UINT32_MAX) *identity = a[0];
                *result = 0; return true;
            }
            host = nr == 143 ? SYS_setregid : SYS_setreuid; break;
        case 144: *result = rvvm_sys_setgid(a[0]); return true;
        case 146: *result = rvvm_sys_setuid(a[0]); return true;
        case 147: case 149:
            if (fake_root) {
                *result = nr == 147 ? rvvm_sys_setuid(a[0]) : rvvm_sys_setgid(a[0]);
                return true;
            }
            host = nr == 147 ? SYS_setresuid : SYS_setresgid; break;
        case 148: *result = rvvm_sys_getresuid((void*)a[0], (void*)a[1], (void*)a[2]); return true;
        case 150: *result = rvvm_sys_getresgid((void*)a[0], (void*)a[1], (void*)a[2]); return true;
        case 151: case 152:
            if (fake_root) { *result = nr == 151 ? fake_uid : fake_gid; return true; }
            host = nr == 151 ? SYS_setfsuid : SYS_setfsgid; break;
        case 159:
            if (fake_root) { *result = 0; return true; }
            host = SYS_setgroups; break;
        case 160: {
            struct uapi_new_utsname st;
            struct uapi_new_utsname guest = {
                .sysname = "Linux", .release = "6.6.6",
                .version = "RVVM " RVVM_VERSION, .machine = "riscv64",
            };
            long ret = (long)errno_ret(USER_SYSCALL(SYS_uname, &st, 0, 0, 0, 0, 0));
            if (!ret) {
                memcpy(guest.nodename, st.nodename, sizeof(guest.nodename));
                memcpy(guest.domainname, st.domainname, sizeof(guest.domainname));
                ret = uapi_extra_copy(&guest, (void*)a[0], sizeof(guest), true);
            }
            *result = ret; return true;
        }
        case 174: case 175:
            if (fake_root) { *result = fake_uid; return true; }
            host = nr == 174 ? SYS_getuid : SYS_geteuid; break;
        case 176: case 177:
            if (fake_root) { *result = fake_gid; return true; }
            host = nr == 176 ? SYS_getgid : SYS_getegid; break;
        case 163: *result = (long)errno_ret(USER_SYSCALL(SYS_prlimit64, 0, a[0], 0, a[1], 0, 0)); return true;
        case 164:
            user_observer_limit(0, a[0], (void*)a[1]);
            *result = (long)errno_ret(USER_SYSCALL(SYS_prlimit64, 0, a[0], a[1], 0, 0, 0)); return true;
        case 167: *result = uapi_extra_prctl(a[0], a[1], a[2], a[3], a[4]); return true;
        case 272: case 438: *result = -ENOSYS; return true;
        case 5: host = SYS_setxattr; break;
        case 6: host = SYS_lsetxattr; break;
        case 7: host = SYS_fsetxattr; break;
        case 8: host = SYS_getxattr; break;
        case 9: host = SYS_lgetxattr; break;
        case 10: host = SYS_fgetxattr; break;
        case 11: host = SYS_listxattr; break;
        case 12: host = SYS_llistxattr; break;
        case 13: host = SYS_flistxattr; break;
        case 14: host = SYS_removexattr; break;
        case 15: host = SYS_lremovexattr; break;
        case 16: host = SYS_fremovexattr; break;
        case 19: host = SYS_eventfd2; break;
        case 20: host = SYS_epoll_create1; break;
        case 26: host = SYS_inotify_init1; break;
        case 27: host = SYS_inotify_add_watch; break;
        case 28: host = SYS_inotify_rm_watch; break;
        case 74: host = SYS_signalfd4; break;
        case 76: host = SYS_splice; break;
        case 71: host = SYS_sendfile; break;
        case 77: host = SYS_tee; break;
        case 85: host = SYS_timerfd_create; break;
        case 86: host = SYS_timerfd_settime; break;
        case 87: host = SYS_timerfd_gettime; break;
        case 264: host = SYS_name_to_handle_at; break;
        case 29: host = SYS_ioctl; break;
        case 32: host = SYS_flock; break;
        case 33: host = SYS_mknodat; break;
        case 34: host = SYS_mkdirat; break;
        case 35: host = SYS_unlinkat; break;
        case 36: host = SYS_symlinkat; break;
        case 37: host = SYS_linkat; break;
        case 38: host = SYS_renameat; break;
        case 45: host = SYS_truncate; break;
        case 46: host = SYS_ftruncate; break;
        case 47: host = SYS_fallocate; break;
        case 48: host = SYS_faccessat; break;
        case 49: host = SYS_chdir; break;
        case 50: host = SYS_fchdir; break;
        case 51:
            /* Real kernel operation in binfmt mode; the identity prefix
             * remains valid after the kernel changes root. */
            if (prefix_path && *prefix_path && strcmp(prefix_path, "/")) { *result = -ENOSYS; return true; }
            host = SYS_chroot; break;
        case 52: host = SYS_fchmod; break;
        case 53: host = SYS_fchmodat; break;
        case 54: host = SYS_fchownat; break;
        case 55: host = SYS_fchown; break;
        case 58: host = SYS_vhangup; break;
        case 62: host = SYS_lseek; break;
        case 63: host = SYS_read; break;
        case 64: host = SYS_write; break;
        case 65: host = SYS_readv; break;
        case 66: host = SYS_writev; break;
        case 67: host = SYS_pread64; break;
        case 68: host = SYS_pwrite64; break;
        case 72: host = SYS_pselect6; break;
        case 73: host = SYS_ppoll; break;
        case 82: host = SYS_fsync; break;
        case 83: host = SYS_fdatasync; break;
        case 88: host = SYS_utimensat; break;
        case 90: host = SYS_capget; break;
        case 91: host = SYS_capset; break;
        case 92: host = SYS_personality; break;
        case 99: host = SYS_set_robust_list; break;
        case 100: host = SYS_get_robust_list; break;
        case 101: host = SYS_nanosleep; break;
        case 102: host = SYS_getitimer; break;
        case 103: host = SYS_setitimer; break;
        case 106: host = SYS_delete_module; break;
        case 107: host = SYS_timer_create; break;
        case 108: host = SYS_timer_gettime; break;
        case 109: host = SYS_timer_getoverrun; break;
        case 110: host = SYS_timer_settime; break;
        case 111: host = SYS_timer_delete; break;
        case 112: host = SYS_clock_settime; break;
        case 115: host = SYS_clock_nanosleep; break;
        case 122: host = SYS_sched_setaffinity; break;
        case 123: host = SYS_sched_getaffinity; break;
        case 124: host = SYS_sched_yield; break;
        case 129: host = SYS_kill; break;
        case 130: host = SYS_tkill; break;
        case 131: host = SYS_tgkill; break;
        case 133: host = SYS_rt_sigsuspend; break;
        case 140: host = SYS_setpriority; break;
        case 141: host = SYS_getpriority; break;
        case 142: host = SYS_reboot; break;
        case 153: host = SYS_times; break;
        case 154: host = SYS_setpgid; break;
        case 155: host = SYS_getpgid; break;
        case 156: host = SYS_getsid; break;
        case 157: host = SYS_setsid; break;
        case 158: host = SYS_getgroups; break;
        case 161: host = SYS_sethostname; break;
        case 162: host = SYS_setdomainname; break;
        case 165: host = SYS_getrusage; break;
        case 166: host = SYS_umask; break;
        case 168: host = SYS_getcpu; break;
        case 169: host = SYS_gettimeofday; break;
        case 170: host = SYS_settimeofday; break;
        case 171: host = SYS_adjtimex; break;
        case 172: host = SYS_getpid; break;
        case 173: host = SYS_getppid; break;
        case 178: host = SYS_gettid; break;
        case 179: host = SYS_sysinfo; break;
        case 184: host = SYS_mq_notify; break;
        case 198: host = SYS_socket; break;
        case 199: host = SYS_socketpair; break;
        case 200: host = SYS_bind; break;
        case 201: host = SYS_listen; break;
        case 202: host = SYS_accept; break;
        case 203: host = SYS_connect; break;
        case 204: host = SYS_getsockname; break;
        case 205: host = SYS_getpeername; break;
        case 206: host = SYS_sendto; break;
        case 207: host = SYS_recvfrom; break;
        case 208: host = SYS_setsockopt; break;
        case 209: host = SYS_getsockopt; break;
        case 210: host = SYS_shutdown; break;
        case 211: host = SYS_sendmsg; break;
        case 212: host = SYS_recvmsg; break;
        case 213: host = SYS_readahead; break;
        case 217: host = SYS_add_key; break;
        case 218: host = SYS_request_key; break;
        case 223: host = SYS_fadvise64; break;
        case 227: host = SYS_msync; break;
        /* Plain pass-throughs, shared so shared-mm VFORK children get them. */
        case 39: host = SYS_umount2; break; // flags are architecture independent
        case 40: host = SYS_mount; break; // namespace and privilege checks stay with Linux
        case 194: host = SYS_shmget; break;
        case 195: host = SYS_shmctl; break; // TODO: struct conversion?
        case 232: host = SYS_mincore; break; // host mapping residency, one byte per host page
        case 242: host = SYS_accept4; break;
        case 269: host = SYS_sendmmsg; break;
        case 270: host = SYS_process_vm_readv; break; // LP64 iovec, same address space
        case 271: host = SYS_process_vm_writev; break;
        case 280: *result = user_bpf((unsigned int)a[0], (void*)a[1], (unsigned int)a[2]); return true;
        case 452:
#ifdef SYS_fchmodat2
            host = SYS_fchmodat2; break;
#else
            *result = -ENOSYS; return true;
#endif
        case 261:
            user_observer_limit(a[0], a[1], (void*)a[2]);
            host = SYS_prlimit64; break;
        case 266: host = SYS_clock_adjtime; break;
        case 267: host = SYS_syncfs; break;
        case 276: host = SYS_renameat2; break;
        case 278: host = SYS_getrandom; break;
        case 279: host = SYS_memfd_create; break;
        case 285: host = SYS_copy_file_range; break;
        case 291: host = SYS_statx; break;
        case 424: host = SYS_pidfd_send_signal; break;
        case 430: host = SYS_fsopen; break;
        case 434: host = SYS_pidfd_open; break;
        case 439: host = SYS_faccessat2; break;
        case 457: host = SYS_statmount; break;
        case 458: host = SYS_listmount; break;
        case 459: host = SYS_lsm_get_self_attr; break;
        case 460: host = SYS_lsm_set_self_attr; break;
        case 461: host = SYS_lsm_list_modules; break;
        default: return false;
    }
    if (nr == 51 && prefix_path && *prefix_path && strcmp(prefix_path, "/")) {
        *result = -ENOSYS; return true;
    }
    if ((nr == 54 || nr == 55) && fake_root) { *result = 0; return true; }
    if (nr == 5 || nr == 6 || nr == 7)
        a[4] = uapi_translate_flags(a[4], uapi_xattr_flags, STATIC_ARRAY_SIZE(uapi_xattr_flags), true);
    if (nr == 26 || nr == 74 || nr == 85) {
        unsigned arg = nr == 26 ? 0 : nr == 74 ? 3 : 1;
        a[arg] = uapi_translate_flags(a[arg], uapi_fd_create_flags,
                                      STATIC_ARRAY_SIZE(uapi_fd_create_flags), true);
    }
    if (nr == 76 || nr == 77) {
        unsigned arg = nr == 76 ? 5 : 3;
        a[arg] = uapi_translate_flags(a[arg], uapi_splice_flags,
                                      STATIC_ARRAY_SIZE(uapi_splice_flags), true);
    }
    if (nr == 88 || nr == 439 || nr == 452)
        a[3] = uapi_translate_flags(a[3], uapi_path_flags, STATIC_ARRAY_SIZE(uapi_path_flags), true);
    unsigned paths = 0;
    switch (nr) {
        case 5: case 6: case 8: case 9: case 11: case 12: case 14: case 15:
        case 45: case 49: paths = 1; break;
        case 33: case 34: case 35: case 48: case 53: case 54: case 88:
        case 27: case 264: case 291: case 439: case 452: paths = 2; break;
        case 36: paths = 5; break;
        case 37: case 38: case 276: paths = 10; break;
    }
    char snapshot[2][UAPI_PATH_MAX], wrapped[2][UAPI_PATH_MAX];
    unsigned slot = 0;
    for (unsigned i = 0; i < 4; ++i) {
        if (!(paths & (1U << i))) continue;
        const char* path = (const char*)a[i];
        user_host_path(snapshot[slot], wrapped[slot], &path);
        a[i] = (long)path;
        ++slot;
    }
    *result = (long)errno_ret(USER_SYSCALL(host, a[0], a[1], a[2], a[3], a[4], a[5]));
    return true;
}
#endif

