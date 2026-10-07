/*
rvvm_user.c - RVVM Linux binary emulator
Copyright (C) 2024  LekKit <github.com/LekKit>
              2023  nebulka1

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
 * This thing is hugely WIP, altho it runs static binaries fairly well.
 * With dynamic binaries, it usually either crashes in ld-linux.so, or
 * in random executable locations... Debugging this is a nightmare.
 *
 * Upon debugging this thing, I figured it would be a good idea to remove
 * CPU/syscall emulation out of the equation, so simply test a combination
 * of ELF loader + stack setup thingy. So there is a native x86_64 jump_start()
 * implementation to do exactly that
 *
 * Some helpful resources:
 *   https://jborza.com/post/2021-05-11-riscv-linux-syscalls/
 *   https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html
 *
 * Now if we ever get this to work, here are some interesting further goals:
 *
 * - Implement some kind of fake /usr overlay so you can still run RISC-V
 *   binaries without chroot, and without putting RISC-V libs into your system
 *
 * - Allow to run Linux binaries on non-Linux host to some degree. The ELF
 *   loader runs even on Windows (lol), so do the rest of RVVM abstractions.
 *   So maybe for many simple syscalls we can do exactly that, at least on Mac/BSD..
 *
 * - Ask some guys that use qemu-user for build system purposes to try out rvvm-user :D
 *   With some local JIT patches rvvm-user already beats qemu-user on statically
 *   built benches
 */

#include "feature_test.h"

//#define RVVM_USER_TEST
//#define RVVM_USER_TEST_X86
//#define RVVM_USER_TEST_RISCV

// Guard this for now
#if defined(RVVM_USER_TEST)

// Guest fd numbers passed through the syscall dispatch are not host fds,
// GCC static analyzer (-fanalyzer) misinterprets them as leaked descriptors
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 12
#pragma GCC diagnostic ignored "-Wanalyzer-fd-leak"
#pragma GCC diagnostic ignored "-Wanalyzer-fd-use-after-close"
#pragma GCC diagnostic ignored "-Wanalyzer-fd-double-close"
#pragma GCC diagnostic ignored "-Wanalyzer-fd-access-mode-mismatch"
#endif

#include <stdio.h>

#include <errno.h>
#include <unistd.h>

#include <time.h>     // clock_gettime(), etc
#include <signal.h>   // sigaction(), etc

#include <sched.h>    // sched_getaffinity()

#include <fcntl.h>    // O_RDONLY

#include <sys/types.h>
#include <sys/param.h>

#include <sys/time.h> // setitimer()

// File stuff
#include <sys/file.h>  // fcntl(), flock(), fallocate(), openat()
#include <sys/uio.h>   // readv(), writev()
#include <sys/stat.h>  // mknodat(), mkdirat(), fchmod(), fchmodat(), fstatat(), fstat(), umask(), statx()
#include <sys/mount.h> // struct statfs

// VMA manipulation
#include <sys/mman.h> // mmap(), munmap(), mprotect()
#include <sys/shm.h>  // shmget(), shmctl(), shmat(), shmdt()

// Sockets
#include <sys/socket.h>
#include <sys/ioctl.h>  // ioctl()
#include <sys/select.h> // select()
#include <poll.h>       // poll()

// Misc
#include <sys/times.h>    // times()
#include <sys/wait.h>     // wait4()
#include <sys/resource.h> // getrusage()
#include <grp.h>          // setgroups()

// Linux-specific stuff
#ifdef __linux__
#include <sys/eventfd.h> // eventfd()
#include <sys/epoll.h>   // epoll_create1(), etc
#include <sys/sysinfo.h> // sysinfo()
#include <sys/fsuid.h>   // setfsuid(), setfsgid()
#include <sys/vfs.h>     // struct statfs
#include <sys/xattr.h>   // fgetxattr(), fsetxattr()
#include <sys/inotify.h>
#include <sys/timerfd.h>

// Put syscall headers here
#include <linux/futex.h> // FUTEX_*
#include <linux/openat2.h> // struct open_how
#include <sys/syscall.h> // SYS_*
#include <unistd.h>
#endif

#include "rvvmlib.h"
#include "elf_load.h"
#include "mem_ops.h"
#include "utils.h"
#include "blk_io.h"
#include "threading.h"
#include "vma_ops.h"
#include "spinlock.h"
#include "rvtimer.h"
#include "stacktrace.h"
#include "rvvm_user_flags.h"
#ifdef __linux__
#include "rvvm_user_extra.h"
#include "rvvm_user_brk.h"
#endif

#define RVVM_USER_RISCV64

#ifdef RVVM_USER_RISCV64
typedef uint64_t uapi_size_t;
typedef uint64_t uapi_ulong_t;
typedef int64_t  uapi_long_t;
#else
typedef uint32_t uapi_size_t;
typedef uint32_t uapi_ulong_t;
typedef int32_t  uapi_long_t;
#endif

#define UAPI_PATH_MAX 4096

#define UAPI_EPERM   1
#define UAPI_ENOENT  2
#define UAPI_EINTR   4
#define UAPI_E2BIG   7
#define UAPI_EIO     5
#define UAPI_EBADF   9
#define UAPI_EAGAIN  11
#define UAPI_ENOMEM  12
#define UAPI_EACCESS 13
#define UAPI_EFAULT  14
#define UAPI_EBUSY   16
#define UAPI_EEXIST  17
#define UAPI_EINVAL  22
#define UAPI_ENOSYS  38

#ifdef __linux__
static const struct uapi_flag_map uapi_xattr_flags[] = {
    { 1, 1, XATTR_CREATE, XATTR_CREATE },
    { 2, 2, XATTR_REPLACE, XATTR_REPLACE },
};

static const struct uapi_flag_map uapi_splice_flags[] = {
    { 1, 1, SPLICE_F_MOVE, SPLICE_F_MOVE },
    { 2, 2, SPLICE_F_NONBLOCK, SPLICE_F_NONBLOCK },
    { 4, 4, SPLICE_F_MORE, SPLICE_F_MORE },
    { 8, 8, SPLICE_F_GIFT, SPLICE_F_GIFT },
};

static const struct uapi_flag_map uapi_fd_create_flags[] = {
    { 00004000, 00004000, O_NONBLOCK, O_NONBLOCK },
    { 02000000, 02000000, O_CLOEXEC, O_CLOEXEC },
};

/* These interfaces share their Linux ABI on RV64, AArch64 and x86-64. */
BUILD_ASSERT(IN_NONBLOCK == O_NONBLOCK && IN_CLOEXEC == O_CLOEXEC);
BUILD_ASSERT(TFD_NONBLOCK == O_NONBLOCK && TFD_CLOEXEC == O_CLOEXEC);
BUILD_ASSERT(TFD_TIMER_ABSTIME == 1 && TFD_TIMER_CANCEL_ON_SET == 2);
BUILD_ASSERT(sizeof(struct itimerspec) == 32);
BUILD_ASSERT(offsetof(struct itimerspec, it_value) == 16);
BUILD_ASSERT(sizeof(struct inotify_event) == 16);
BUILD_ASSERT(offsetof(struct inotify_event, mask) == 4);
BUILD_ASSERT(offsetof(struct inotify_event, cookie) == 8);
BUILD_ASSERT(offsetof(struct inotify_event, len) == 12);
BUILD_ASSERT(POSIX_FADV_NORMAL == 0 && POSIX_FADV_RANDOM == 1 && POSIX_FADV_SEQUENTIAL == 2);
BUILD_ASSERT(POSIX_FADV_WILLNEED == 3 && POSIX_FADV_DONTNEED == 4 && POSIX_FADV_NOREUSE == 5);

static const struct uapi_flag_map uapi_path_flags[] = {
    { 0x100, 0x100, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_NOFOLLOW },
    { 0x1000, 0x1000, AT_EMPTY_PATH, AT_EMPTY_PATH },
};

/* These Linux interfaces use fixed-width fields shared by our 64-bit,
 * little-endian hosts. Let the kernel copy buffers and report EFAULT and
 * EOVERFLOW, including the updated handle size on failure. */
BUILD_ASSERT(sizeof(int) == 4);
BUILD_ASSERT(offsetof(struct file_handle, handle_type) == 4);
BUILD_ASSERT(offsetof(struct file_handle, f_handle) == 8);
BUILD_ASSERT(AT_SYMLINK_FOLLOW == 0x400);
BUILD_ASSERT(AT_EMPTY_PATH == 0x1000);
BUILD_ASSERT(sizeof(struct timespec) == 16);
BUILD_ASSERT(sizeof(((struct timespec*)0)->tv_sec) == 8);
BUILD_ASSERT(sizeof(((struct timespec*)0)->tv_nsec) == 8);
BUILD_ASSERT(offsetof(struct timespec, tv_nsec) == 8);
BUILD_ASSERT(UTIME_NOW == 0x3fffffff);
BUILD_ASSERT(UTIME_OMIT == 0x3ffffffe);
#endif

// RISC-V UAPI struct definitions & conversions
struct uapi_new_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

struct uapi_stat {
    uapi_ulong_t dev;
    uapi_ulong_t ino;
    uint32_t     mode;
    uint32_t     nlink;
    uint32_t     uid;
    uint32_t     gid;
    uapi_ulong_t rdev;
    uapi_ulong_t pad1;
    uapi_long_t  size;
    int32_t      blksize;
    int32_t      pad2;
    uapi_long_t  blocks;
    uapi_long_t  atime;
    uapi_ulong_t atime_nsec;
    uapi_long_t  mtime;
    uapi_ulong_t mtime_nsec;
    uapi_long_t  ctime;
    uapi_ulong_t ctime_nsec;
    uint32_t     unused4;
    uint32_t     unused5;
};

struct uapi_statfs64 {
    uapi_size_t type;
    uapi_size_t bsize;
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    struct {
        int32_t val[2];
    } fsid;
    uapi_size_t namelen;
    uapi_size_t frsize;
    uapi_size_t flags;
    uapi_size_t spare[4];
};

struct uapi_sigaltstack {
    uapi_size_t sp;
    int32_t flags;
    uapi_size_t size;
};

struct uapi_sched_param {
    int32_t sched_priority;
};

struct uapi_cap_data_struct {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

union uapi_epoll_data {
    uapi_size_t ptr;
    int32_t     fd;
    uint32_t    u32;
    uint64_t    u64;
};

struct uapi_epoll_event {
    uint32_t event;
    union uapi_epoll_data data;
};

struct uapi_timeval32 {
    uapi_long_t tv_sec;
    uapi_long_t tv_usec;
};

struct uapi_timespec32 {
    uapi_long_t tv_sec;
    uapi_long_t tv_nsec;
};

struct uapi_timespec {
    uint64_t tv_sec;
    uint64_t tv_nsec;
};

struct uapi_pollfd {
    int32_t  fd;
    uint16_t events;
    uint16_t revents;
};

struct uapi_linux_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[0];
};

#ifdef __riscv

BUILD_ASSERT(sizeof(struct uapi_stat) == sizeof(struct stat));
BUILD_ASSERT(sizeof(struct uapi_statfs64) == sizeof(struct statfs));

#endif

#if defined(__linux__) && defined(__aarch64__) && defined(__AARCH64EL__)
// Linux ARM64's native stat uses the same LP64 asm-generic ABI as RV64.
// Check every field before forwarding kernel output directly to guest memory.
#define STAT_ABI_FIELD(guest, host) \
    BUILD_ASSERT(offsetof(struct uapi_stat, guest) == offsetof(struct stat, host)); \
    BUILD_ASSERT(sizeof(((struct uapi_stat*)0)->guest) == sizeof(((struct stat*)0)->host))
BUILD_ASSERT(sizeof(struct uapi_stat) == 128 && sizeof(struct stat) == 128);
STAT_ABI_FIELD(dev, st_dev);
STAT_ABI_FIELD(ino, st_ino);
STAT_ABI_FIELD(mode, st_mode);
STAT_ABI_FIELD(nlink, st_nlink);
STAT_ABI_FIELD(uid, st_uid);
STAT_ABI_FIELD(gid, st_gid);
STAT_ABI_FIELD(rdev, st_rdev);
STAT_ABI_FIELD(size, st_size);
STAT_ABI_FIELD(blksize, st_blksize);
STAT_ABI_FIELD(blocks, st_blocks);
STAT_ABI_FIELD(atime, st_atim.tv_sec);
STAT_ABI_FIELD(atime_nsec, st_atim.tv_nsec);
STAT_ABI_FIELD(mtime, st_mtim.tv_sec);
STAT_ABI_FIELD(mtime_nsec, st_mtim.tv_nsec);
STAT_ABI_FIELD(ctime, st_ctim.tv_sec);
STAT_ABI_FIELD(ctime_nsec, st_ctim.tv_nsec);
#undef STAT_ABI_FIELD

static inline rvvm_addr_t uapi_stat_syscall(long nr, long fd, long arg1, long arg2, long flags)
{
    // The kernel already returns the guest's negative errno convention.
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x3 __asm__("x3") = flags;
    register long x8 __asm__("x8") = nr;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory", "cc");
    return x0;
}
#else
static void uapi_stat_convert(struct uapi_stat* dst, const struct stat* src)
{
    memset(dst, 0, sizeof(*dst));
    dst->dev = src->st_dev;
    dst->ino = src->st_ino;
    dst->mode = src->st_mode;
    dst->nlink = src->st_nlink;
    dst->uid = src->st_uid;
    dst->gid = src->st_gid;
    dst->rdev = src->st_rdev;
    dst->pad1 = 0;
    dst->size = src->st_size;
    dst->blksize = src->st_blksize;
    dst->pad2 = 0;
    dst->blocks = src->st_blocks;
    dst->atime = src->st_atime;
    dst->mtime = src->st_mtime;
    dst->ctime = src->st_ctime;
#ifdef __APPLE__
    dst->atime_nsec = src->st_atimespec.tv_nsec;
    dst->mtime_nsec = src->st_mtimespec.tv_nsec;
    dst->ctime_nsec = src->st_ctimespec.tv_nsec;
#else
    dst->atime_nsec = src->st_atim.tv_nsec;
    dst->mtime_nsec = src->st_mtim.tv_nsec;
    dst->ctime_nsec = src->st_ctim.tv_nsec;
#endif
}
#endif

static void uapi_statfs64_convert(struct uapi_statfs64* dst, const struct statfs* src)
{
    memset(dst, 0, sizeof(*dst));
    dst->type = src->f_type;
    dst->bsize = src->f_bsize;
    dst->blocks = src->f_blocks;
    dst->bfree = src->f_bfree;
    dst->bavail = src->f_bavail;
    dst->files = src->f_files;
    dst->ffree = src->f_ffree;
    memcpy(&dst->fsid, &src->f_fsid, sizeof(dst->fsid));
    dst->namelen = src->f_namelen;
    dst->frsize = src->f_frsize;
    dst->flags = src->f_flags;
}

static rvvm_machine_t* userland; // Emulated RVVM process context

// Short cast rvvm_addr_t -> void*
static void* to_ptr(rvvm_addr_t addr)
{
    return (void*)(size_t)addr;
}

// Short cast rvvm_addr_t -> const char*
static const char* to_str(rvvm_addr_t addr)
{
    return (const char*)(size_t)addr;
}

// Return last errno like a syscall interface
static int last_errno(void)
{
    // TODO: Host->Guest errno conversion
    return -errno;
}

// Return negative values on -1 error like a syscall interface does
static rvvm_addr_t errno_ret(int64_t val)
{
    if (val == -1) {
        return last_errno();
    } else {
        return val;
    }
}

// This is for debugging sake
#ifdef __linux__
static void* user_elf_map(void* addr, size_t size)
{
    size_t offset = (uintptr_t)addr & (vma_page_size() - 1);
    if (size > SIZE_MAX - offset) return NULL;
    user_fd_lock();
    void* ret = user_vma_map((void*)((uintptr_t)addr - offset), size + offset, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | (addr ? MAP_FIXED_NOREPLACE : 0), -1, 0);
    user_fd_unlock();
    return ret == MAP_FAILED ? NULL : (char*)ret + offset;
}
#endif
static elf_desc_t elf = {
    .base = NULL,
#ifdef __linux__
    .map = user_elf_map,
#endif
};
static elf_desc_t interp = {
    .base = NULL,
#ifdef __linux__
    .map = user_elf_map,
#endif
};

static bool proc_mem_readable(const void* addr, size_t size)
{
    char scratch[32];
    if (size > sizeof(scratch)) return false;
    struct iovec local = {scratch, size}, remote = {(void*)addr, size};
    return syscall(SYS_process_vm_readv, syscall(SYS_gettid), &local, 1, &remote, 1, 0) == (ssize_t)size;
}

#ifndef __riscv
static const char* prefix_path = "/home/lekkit/stuff/userland/debian";
#else
static const char* prefix_path = NULL;
#endif

static bool fake_root = true;
static const char* user_binfmt_executable;

static bool path_bypass(const char* path)
{
    return prefix_path == NULL
        || rvvm_strfind(path, "/dev") == path
        || rvvm_strfind(path, "/sys") == path
        || rvvm_strfind(path, "/proc") == path
        || rvvm_strfind(path, "/tmp") == path
        || rvvm_strfind(path, "/var/tmp") == path;
}

static bool path_wrapped(const char* path)
{
    return prefix_path == NULL
        || rvvm_strfind(path, prefix_path) == path
        || path_bypass(path);
}

static const char* wrap_path(char* buffer, const char* path)
{
    if (prefix_path && path) {
        if (path_bypass(path)) {
            return path;
        }

        if (rvvm_strfind(path, "/") == path) {
            size_t prefix_len = rvvm_strlcpy(buffer, prefix_path, UAPI_PATH_MAX);
            rvvm_strlcpy(buffer + prefix_len, path, UAPI_PATH_MAX - prefix_len);
            return buffer;
        }
    }
    return path;
}

#include "rvvm_user_path.h"
#include "user_ptrace/user_ptrace.h"
#include "user_ptrace/user_ptrace_events.h"
#include "rvvm_user_vm_pause.h"
#include "rvvm_user_signal.h"
#include "rvvm_user_posix.h"
#include "rvvm_user_ipc.h"
#include "rvvm_user_io_extra.h"
#include "rvvm_user_control_extra.h"
#include "rvvm_user_msg.h"
#include "rvvm_user_lock_memory.h"
#include "rvvm_user_fs_watch.h"
#include "rvvm_user_system_control.h"
#include "rvvm_user_exe.h"
#include "rvvm_user_exec.h"
#include "user_ptrace/user_ptrace_proc.h"
#include "rvvm_user_cpu.h"
#include "rvvm_user_bpf.h"

static long user_ptrace_wait_pause(uint32_t generation)
{
    /* Logical queue publication wakes immediately. Native-only stops have no
     * pollable descriptor, so tracer waits also recheck them after 50 us. */
    const struct timespec delay = {.tv_nsec = 50000};
    uint32_t* address = user_ptrace_events_sleep_begin();
    long ret = errno_ret(USER_SYSCALL(SYS_futex, address, FUTEX_WAIT_PRIVATE,
                                      generation, &delay, 0, 0));
    user_ptrace_events_sleep_end();
    /* The guest wait already started; only this internal sleep was unstarted.
     * Its signal must obey the guest wait's SA_RESTART decision. */
    if (ret == -EINTR) user_sig.syscall_unstarted = false;
    return !ret || ret == -EAGAIN || ret == -ETIMEDOUT ? USER_PTRACE_WAIT_AGAIN : ret;
}

#if defined(__linux__) && defined(SYS_openat2)
static rvvm_addr_t rvvm_sys_openat2(int dirfd, const char* path, void* guest_how, size_t size)
{
    BUILD_ASSERT(sizeof(struct open_how) == 24);
    BUILD_ASSERT(offsetof(struct open_how, mode) == 8);
    BUILD_ASSERT(offsetof(struct open_how, resolve) == 16);
    if (size < sizeof(struct open_how)) return -UAPI_EINVAL;
    if (size > (size_t)sysconf(_SC_PAGESIZE)) return -UAPI_E2BIG;

    struct open_how* how = malloc(size);
    if (!how) return -UAPI_ENOMEM;
    struct iovec local = { .iov_base = how, .iov_len = size };
    struct iovec remote = { .iov_base = guest_how, .iov_len = size };
    // A kernel-mediated copy returns EFAULT instead of faulting the emulator.
    ssize_t copied = process_vm_readv(syscall(SYS_gettid), &local, 1, &remote, 1, 0);
    rvvm_addr_t ret;
    if (copied != (ssize_t)size) {
        ret = copied < 0 ? last_errno() : -UAPI_EFAULT;
    } else {
        // Keep high flag bits and extension bytes for host kernel validation.
        how->flags = (how->flags & ~UINT64_C(0xffffffff))
                   | uapi_open_flags_to_host((uint32_t)how->flags);
        char snapshot[UAPI_PATH_MAX], path_buf[UAPI_PATH_MAX];
        ret = user_path_copy(snapshot, path, sizeof(snapshot));
        if ((int64_t)ret >= 0) {
            const char* wrapped = wrap_path(path_buf, snapshot);
            ret = errno_ret(USER_SYSCALL(SYS_openat2, dirfd, wrapped, how, size, 0, 0));
            ret = user_cpu_opened((int64_t)ret, how->flags, dirfd, wrapped);
        }
    }
    free(how);
    return ret;
}
#endif

// Debug: current running hart, for host fault diagnostics
static THREAD_LOCAL rvvm_hart_t* current_user_hart = NULL;

static void user_fault_hex(char** p, uint64_t val)
{
    char tmp[17];
    uint32_t i = 0;
    do {
        uint32_t d = val & 0xF;
        tmp[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        val >>= 4;
    } while (val);
    while (i) {
        *(*p)++ = tmp[--i];
    }
    *(*p)++ = '\n';
}

static void user_fault_handler(int sig, siginfo_t* info, void* ucontext)
{
    if (user_vm_pause_signal(info)) return;
    if (user_ptrace_signal(user_sig.cpu, sig, info)) return;
    bool replayed = user_ptrace_restore_signal(info);
    if ((replayed && info->si_code > 0) || user_ptrace_injected(sig, info)) {
        user_signal_capture(sig, info, ucontext);
        user_sig.synchronous = true;
        return;
    }
    if (info->si_code > 0 && user_path_fault(ucontext)) return;
#if defined(USER_FAULT_POC)
    rvvm_hart_t* fault_cpu = user_sig.cpu;
    ucontext_t* uc = ucontext;
#if defined(__aarch64__)
    uintptr_t host_pc = uc->uc_mcontext.pc;
#else
    uintptr_t host_pc = uc->uc_mcontext.gregs[REG_RIP];
#endif
#ifdef USER_FAULT_META
    extern const uintptr_t __start_rvvm_user_access[], __stop_rvvm_user_access[];
    bool jit_fault = false;
#ifdef USE_JIT
    const rvjit_fault_t* fault = NULL;
#endif
    if (info->si_code > 0 && user_fault_armed && fault_cpu) {
        for (const uintptr_t* site = __start_rvvm_user_access; site < __stop_rvvm_user_access; ++site) {
            if (*site == host_pc) {
                fault_cpu->user_fault_interpreted = 1;
                fault_cpu->user_fault_pc = fault_cpu->registers[RISCV_REG_PC];
                break;
            }
        }
#ifdef USE_JIT
        fault = rvjit_fault_lookup(&fault_cpu->jit, host_pc);
#endif
    }
#ifdef USE_JIT
    if (fault) {
        jit_fault = true;
        uint64_t host_regs[32];
#if defined(__aarch64__)
        for (unsigned i = 0; i < 31; ++i) host_regs[i] = uc->uc_mcontext.regs[i];
        host_regs[31] = 0;
#else
        static const unsigned indices[16] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX,
            REG_RSP, REG_RBP, REG_RSI, REG_RDI, REG_R8, REG_R9, REG_R10, REG_R11,
            REG_R12, REG_R13, REG_R14, REG_R15};
        for (unsigned i = 0; i < 16; ++i) host_regs[i] = uc->uc_mcontext.gregs[indices[i]];
#endif
        for (unsigned i = 0; i < sizeof(fault->regs); ++i)
            if (fault->regs[i] != REG_ILL)
                fault_cpu->registers[fault->regs[i]] = host_regs[i];
        fault_cpu->user_fault_pc = fault->guest_pc;
    }
#endif
    if (info->si_code > 0 && user_fault_armed && fault_cpu
        && (fault_cpu->user_fault_interpreted || jit_fault)) {
#else
    if (info->si_code > 0 && user_fault_armed && fault_cpu
        && (fault_cpu->user_fault_interpreted
#ifdef USE_JIT
            || (host_pc >= (uintptr_t)fault_cpu->jit.heap.code
                && host_pc < (uintptr_t)fault_cpu->jit.heap.code + fault_cpu->jit.heap.curr)
#endif
            )) {
#endif
        user_defer_pending();
        user_sig.info = *info;
        user_sig.pending = sig;
        user_sig.synchronous = true;
        user_fault_save_fenv(uc);
        user_fault_armed = 0;
        siglongjmp(user_fault_resume, 1);
    }
#endif
    if (info->si_code <= 0 && user_sig.cpu) {
        user_signal_capture(sig, info, ucontext);
        return;
    }
    char buf[8192];
    char* p = buf;
    UNUSED(ucontext);
    const char* hdr = "=== HOST FAULT inside guest === sig=";
    while (*hdr) *p++ = *hdr++;
    user_fault_hex(&p, (uint64_t)(size_t)sig);
    const char* addr = "fault addr(si_addr): ";
    while (*addr) *p++ = *addr++;
    user_fault_hex(&p, (uint64_t)(size_t)info->si_addr);
    rvvm_hart_t* cpu = current_user_hart;
    if (cpu) {
        const char* pch = "guest PC: ";
        while (*pch) *p++ = *pch++;
        user_fault_hex(&p, rvvm_read_cpu_reg(cpu, RVVM_REGID_PC));
        for (uint32_t i = 0; i < 32; ++i) {
            *p++ = 'x';
            user_fault_hex(&p, i);
            const char* eq = "= ";
            while (*eq) *p++ = *eq++;
            user_fault_hex(&p, rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + i));
        }
    }
    (void)!write(2, buf, (size_t)(p - buf));
    _Exit(128 + sig);
}

static void user_fault_handler_install(void)
{
    struct sigaction sa = {0};
    sa.sa_sigaction = user_fault_handler;
    sa.sa_flags = SA_SIGINFO;
    user_host_sigfillset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

typedef struct rvvm_user_thread {
    rvvm_hart_t* cpu;
    uint32_t* child_settid;
    uint32_t* child_cleartid;
    uint32_t* parent_settid;
    uint32_t tid;
    uint32_t refs;
    uint64_t signal_mask;
    bool process_thread;
    void* ptrace_state;
    user_fd_table_t* fd_table;
    struct user_signal_process* signals;
    bool inherit_signal_stack;
    struct user_sigstack signal_stack;
    rvvm_thread_t* host_thread;
    struct rvvm_user_thread* reap_next;
} rvvm_user_thread_t;

static void rvvm_user_thread_put(rvvm_user_thread_t* thread)
{
    if (atomic_sub_uint32(&thread->refs, 1) == 1) free(thread);
}

// Main execution loop (Run the user CPU, handle syscalls)
static void* rvvm_user_thread_wrap(void* arg);

static spinlock_t brk_lock = {0};
static spinlock_t mmap_lock = {0};
static user_fd_mutex_t user_vm_transition_lock;
static THREAD_LOCAL unsigned user_vm_transition_depth;
static THREAD_LOCAL bool user_vm_service, user_vm_child;

static void user_vm_enter(void)
{
    if (!user_vm_service && !user_vm_transition_depth++) user_fd_mutex_lock(&user_vm_transition_lock);
}

static void user_vm_leave(void)
{
    if (!user_vm_service && !--user_vm_transition_depth) user_fd_mutex_unlock(&user_vm_transition_lock);
}

static rvvm_user_thread_t* user_reap_threads;
static bool user_reaper_running;
/* Publish the last guest exit status together with the live count. The
 * internal reaper must not turn a nonzero last-thread exit into success. */
static uint64_t user_thread_lifetime = 1;
static uint32_t user_reap_wake;

static void user_reap_finished(void)
{
    for (rvvm_user_thread_t** slot = &user_reap_threads; *slot;) {
        rvvm_user_thread_t* thread = *slot;
        if (!rvvm_thread_try_join(thread->host_thread)) { slot = &thread->reap_next; continue; }
        /* Kernel robust-list cleanup must precede guest pthread_join's
         * permission to free guest TLS. Never replace glibc's native
         * clear_child_tid: pthread_join still needs its native TCB. */
        uint32_t zero = 0;
        if (thread->child_cleartid
            && !uapi_extra_copy(&zero, thread->child_cleartid, sizeof(zero), true))
            syscall(SYS_futex, thread->child_cleartid, FUTEX_WAKE, 1, NULL, NULL, 0);
        *slot = thread->reap_next;
        rvvm_user_thread_put(thread);
    }
}

/* The reaper lock keeps exited threads registered until native join proves
 * that their last kernel writes have finished. Helpers never execute guest
 * code and all their guest-memory writes are excluded by this same lock. */
static int user_vm_pause_collect(pid_t self)
{
    /* Remove finished native tasks before looking up TIDs: the kernel may
     * already have reused a dead guest's number for an internal helper. */
    user_reap_finished();
    if (user_vm_pause_add(user_vm_initial_tid, self)) return -1;
    for (rvvm_user_thread_t* thread = user_reap_threads; thread; thread = thread->reap_next)
        if (user_vm_pause_add(atomic_load_uint32(&thread->tid), self)) return -1;
    return 0;
}

static void* user_thread_reaper(void* unused)
{
    UNUSED(unused);
    atomic_store_uint32(&user_vm_reaper_tid, gettid());
    rvvm_futex_wake(&user_vm_reaper_tid, 1);
    for (;;) {
        user_fd_mutex_lock(&user_vm_reaper_lock);
        user_reap_finished();
        bool pending = user_reap_threads != NULL;
        uint32_t wake = atomic_load_uint32(&user_reap_wake);
        uint64_t lifetime = atomic_load_uint64(&user_thread_lifetime);
        if (!pending && !(uint32_t)lifetime) {
            user_reaper_running = false;
            user_fd_mutex_unlock(&user_vm_reaper_lock);
            syscall(SYS_exit, lifetime >> 32);
            return NULL;
        }
        user_fd_mutex_unlock(&user_vm_reaper_lock);
        if (pending) sleep_ms(1);
        else rvvm_futex_wait(&user_reap_wake, wake, RVVM_FUTEX_INFINITE);
    }
}

static void user_reap_notify(void)
{
    atomic_add_uint32(&user_reap_wake, 1);
    rvvm_futex_wake(&user_reap_wake, 1);
}
#ifdef USER_FAULT_META
#include "rvvm_user_memory.h"
#endif
#ifdef __linux__
static struct uapi_brk_heap brk_heap;

static void* rvvm_sys_brk(void* addr)
{
    user_fd_lock();
    spin_lock(&brk_lock);
    uintptr_t ret = uapi_brk(&brk_heap, (uintptr_t)addr);
    spin_unlock(&brk_lock);
    user_fd_unlock();
    return (void*)ret;
}
#else
#define BRK_HEAP_SIZE 0x40000000
static uint8_t* brk_buffer = NULL;
static uint8_t* brk_ptr = NULL;

// We can't touch the native brk heap since it would likely blow up the process
static void* rvvm_sys_brk(void* addr)
{
    uint8_t* brk_new = addr;
    uint8_t* brk_ret = NULL;
    DO_ONCE({
        brk_buffer = vma_alloc(NULL, BRK_HEAP_SIZE, VMA_RDWR);
        brk_ptr = brk_buffer;
    });

    spin_lock(&brk_lock);
    if (brk_new >= brk_buffer && brk_new < (brk_buffer + BRK_HEAP_SIZE)) {
        if (brk_new > brk_ptr) {
            // Newly allocated brk memory should be zeroed
            memset(brk_ptr, 0, brk_new - brk_ptr);
        }
        brk_ptr = brk_new;
    } else if (brk_new) {
        rvvm_warn("invalid brk %p, current %p, off %ld!", brk_new, brk_ptr, brk_new - brk_buffer);
    }
    brk_ret = brk_ptr;
    spin_unlock(&brk_lock);
    return brk_ret;
}
#endif

#define UAPI_CLONE_VM             0x00000100
#define UAPI_CLONE_SIGHAND        0x00000800
#define UAPI_CLONE_PIDFD          0x00001000
#define UAPI_CLONE_THREAD         0x00010000
#define UAPI_CLONE_VFORK          0x00004000
#define UAPI_CLONE_SETTLS         0x00080000
#define UAPI_CLONE_PARENT_SETTID  0x00100000
#define UAPI_CLONE_CHILD_CLEARTID 0x00200000
#define UAPI_CLONE_CHILD_SETTID   0x01000000

#define UAPI_CLONE_THREAD_FLAGS 0x00050f00 // VM, FS, FILES, SIGHAND, THREAD, SYSVSEM
#define UAPI_CLONE_IGNORED_FLAGS 0x80400000 // IO, DETACHED
#define UAPI_CLONE_OPTIONAL_FLAGS (UAPI_CLONE_SETTLS | UAPI_CLONE_PARENT_SETTID \
    | UAPI_CLONE_CHILD_CLEARTID | UAPI_CLONE_CHILD_SETTID)

static rvvm_hart_t* user_clone_cpu(rvvm_hart_t* parent)
{
    rvvm_hart_t* cpu = rvvm_create_user_thread(userland);
    for (size_t i = 1; i < 32; ++i)
        rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + i, rvvm_read_cpu_reg(parent, RVVM_REGID_X0 + i));
    for (size_t i = 0; i < 32; ++i)
        rvvm_write_cpu_reg(cpu, RVVM_REGID_F0 + i, rvvm_read_cpu_reg(parent, RVVM_REGID_F0 + i));
    // Children inherit rounding mode and accrued FP exceptions as well as registers.
    rvvm_uxlen_t fcsr = 0;
    riscv_csr_op(parent, CSR_FCSR, &fcsr, CSR_SETBITS);
    riscv_csr_op(cpu, CSR_FCSR, &fcsr, CSR_SWAP);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, rvvm_read_cpu_reg(parent, RVVM_REGID_PC) + 4);
    rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 10, 0);
    return cpu;
}

// long sys_clone(unsigned long flags, void *stack, int *parent_tid, unsigned long tls, int *child_tid);
static int rvvm_sys_vfork(rvvm_user_thread_t*, uint32_t, size_t, uint32_t*, size_t, uint32_t*);

static int rvvm_sys_clone_impl(rvvm_user_thread_t* current, uint32_t flags, size_t stack, uint32_t* parent_tid, size_t tls, uint32_t* child_tid)
{
    rvvm_hart_t* cpu = current->cpu;
    flags &= ~UAPI_CLONE_IGNORED_FLAGS;
    if (flags & UAPI_CLONE_VM) {
        const uint32_t supported = 0xff | UAPI_CLONE_THREAD_FLAGS | UAPI_CLONE_OPTIONAL_FLAGS
            | 0x00008000; // CLONE_PARENT
        if ((flags & UAPI_CLONE_THREAD_FLAGS) != UAPI_CLONE_THREAD_FLAGS || (flags & ~supported)) {
            return -UAPI_EINVAL;
        }

        uint64_t held = UINT64_MAX, saved_mask;
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, &saved_mask, 8);
        if (!user_reaper_running) {
            rvvm_thread_t* reaper = rvvm_thread_create(user_thread_reaper, NULL);
            if (!reaper) {
                syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
                return -EAGAIN;
            }
            user_reaper_running = true;
            thread_detach(reaper);
            while (!atomic_load_uint32(&user_vm_reaper_tid))
                rvvm_futex_wait(&user_vm_reaper_tid, 0, RVVM_FUTEX_INFINITE);
        }

        rvvm_user_thread_t* thread = safe_new_obj(rvvm_user_thread_t);
        thread->cpu = user_clone_cpu(cpu);

        // Set guest stack pointer
        rvvm_write_cpu_reg(thread->cpu, RVVM_REGID_X0 + 2, stack);

        if (flags & UAPI_CLONE_SETTLS) {
            // Set guest TLS register
            rvvm_write_cpu_reg(thread->cpu, RVVM_REGID_X0 + 4, tls);
        }

        // Publish all guest TID addresses before the child can use them.
        if (flags & UAPI_CLONE_CHILD_SETTID) thread->child_settid = child_tid;
        if (flags & UAPI_CLONE_CHILD_CLEARTID) thread->child_cleartid = child_tid;
        if (flags & UAPI_CLONE_PARENT_SETTID) thread->parent_settid = parent_tid;
        thread->refs = 3; // Parent, child and native-exit reaper.
        thread->signal_mask = user_sig.mask;
        thread->signals = user_signal_process_retain();
        thread->fd_table = user_fd_table_retain();
        thread->ptrace_state = user_ptrace_prepare(thread->cpu, user_cpu_auxv, user_cpu_auxv_size, thread->signal_mask);
        atomic_add_uint64(&user_thread_lifetime, 1);
        rvvm_thread_t* host_thread = rvvm_thread_create_ex(rvvm_user_thread_wrap, thread, 0);
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
        if (!host_thread) {
            atomic_sub_uint64(&user_thread_lifetime, 1);
            user_signal_process_release(thread->signals);
            user_fd_table_release(thread->fd_table);
            user_ptrace_cancel(thread->ptrace_state);
            rvvm_free_user_thread(thread->cpu);
            free(thread);
            return -UAPI_EAGAIN;
        }
        thread->host_thread = host_thread;
        user_fd_mutex_lock(&user_vm_reaper_lock);
        thread->reap_next = user_reap_threads;
        user_reap_threads = thread;
        user_fd_mutex_unlock(&user_vm_reaper_lock);
        user_reap_notify();

        uint32_t tid = atomic_load_uint32(&thread->tid);
        while (!tid) {
            rvvm_futex_wait(&thread->tid, 0, RVVM_FUTEX_INFINITE);
            tid = atomic_load_uint32(&thread->tid);
        }

        rvvm_user_thread_put(thread);

        return tid;
    } else {
        const uint32_t supported = 0xff | UAPI_CLONE_OPTIONAL_FLAGS | UAPI_CLONE_PIDFD;
        if ((flags & ~supported) || (flags & 0xff) != SIGCHLD) return -UAPI_EINVAL;
        if ((flags & UAPI_CLONE_PIDFD) && (flags & UAPI_CLONE_PARENT_SETTID))
            return -EINVAL;
        int publish[2] = {-1, -1};
        user_fd_lock();
        // Linux publishes parent_tid before the child can observe shared memory.
        if ((flags & (UAPI_CLONE_PARENT_SETTID | UAPI_CLONE_PIDFD))
            && socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, publish)) {
            int error = -errno;
            user_fd_unlock();
            return error;
        }
        // Own shared userspace state at fork: other host threads disappear
        // in the child. None of these paths nests the locks in reverse order.
        uint64_t held = UINT64_MAX, saved_mask;
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, &saved_mask, 8);
        spin_lock(&user_action_lock);
        spin_lock(&brk_lock);
        spin_lock(&mmap_lock);
        user_fd_mutex_lock(&user_exe_lock);
        user_fd_mutex_lock(&user_vm_reaper_lock);
        rvvm_user_fork_lock();
        user_ptrace_clone(cpu);
        pid_t pid = fork();
        int fork_errno = errno;
        if (!pid) {
            /* Other native threads, their join handles and wake queues do
             * not survive host fork. The survivor is now a process thread. */
            user_reap_threads = NULL;
            user_reaper_running = false;
            user_thread_lifetime = 1;
            user_reap_wake = 0;
            user_vm_reaper_tid = 0;
            user_vm_initial_tid = gettid();
            user_vm_pi_users = 0;
            user_vm_pi_owned = 0;
            user_fd_fork_reset();
            rvvm_user_fork_child(cpu);
            user_ptrace_fork(cpu);
        }
        rvvm_user_fork_unlock();
        user_fd_mutex_unlock(&user_vm_reaper_lock);
        user_fd_mutex_unlock(&user_exe_lock);
        if (!pid) user_fd_table_fork_child();
        spin_unlock(&mmap_lock);
        spin_unlock(&brk_lock);
        spin_unlock(&user_action_lock);
        if (pid == 0) {
            if (publish[0] >= 0) {
                char ready;
                close(publish[0]);
                ssize_t received;
                do { received = read(publish[1], &ready, 1); } while (received < 0 && errno == EINTR);
                close(publish[1]);
                if ((flags & UAPI_CLONE_PIDFD) && received != 1) _exit(127);
            }
            user_fd_unlock();
            /* A new ordinary-fork child must not keep its parent's vfork
             * completion channel alive after that parent execs or exits. */
            if (user_vm_fd >= 0) {
                close(user_vm_fd);
                atomic_store_uint32_relax(&user_fd_table()->vm_fd, UINT32_MAX);
            }
            current->tid = gettid();
            atomic_store_uint32_relax(&user_signal_process_current()->refs, 1);
            user_host_exe_link.st_ino = 0; // The child has a different proc inode.
            user_fork_exe_link_ready = false;
            current->refs = 1;
            current->process_thread = true;
            current->parent_settid = NULL;
            current->child_settid = NULL;
            current->child_cleartid = (flags & UAPI_CLONE_CHILD_CLEARTID) ? child_tid : NULL;
            syscall(SYS_set_tid_address, current->child_cleartid);
            if (flags & UAPI_CLONE_CHILD_SETTID)
                (void)uapi_extra_copy(&current->tid, child_tid, sizeof(current->tid), true);
            if (flags & UAPI_CLONE_SETTLS) rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 4, tls);
            cpu->lrsc = false;
            user_sig.pending = 0;
            user_sig.deferred_mask = 0;
            user_sig.synchronous = false;
            user_sig.restore_mask = false;
            user_sig.syscall_unstarted = false;
            atomic_store_uint32(&cpu->user_signal_pending, 0);
            /* A fork service starts guest dispatch only after publication
             * and wrapper initialization; keep its native signals blocked. */
            if (!user_vm_service) user_apply_mask();
        } else {
            int publish_error = 0;
            if (pid > 0 && (flags & UAPI_CLONE_PIDFD)) {
                // The child cannot exit/exec until its pidfd is opened and published.
                int pidfd = syscall(SYS_pidfd_open, pid, 0);
                publish_error = pidfd < 0 ? -errno : uapi_extra_copy(&pidfd, parent_tid, sizeof(pidfd), true);
                if (publish_error && pidfd >= 0) close(pidfd);
            }
            if (pid > 0 && (flags & UAPI_CLONE_PARENT_SETTID))
                (void)uapi_extra_copy(&pid, parent_tid, sizeof(pid), true);
            if (publish[0] >= 0) {
                close(publish[1]);
                if (pid > 0 && !publish_error) (void)!send(publish[0], "", 1, MSG_NOSIGNAL);
                close(publish[0]);
            }
            user_fd_unlock();
            syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
            if (publish_error) {
                while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
                return publish_error;
            }
        }
        if (pid < 0) return -fork_errno;
        if (pid == 0 && stack) {
            // The guest clone wrapper placed its child entry point on this stack.
            rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 2, stack);
        }
        return pid;
    }
}

static int rvvm_sys_clone(rvvm_user_thread_t* current, uint32_t flags, size_t stack,
                          uint32_t* parent_tid, size_t tls, uint32_t* child_tid)
{
    if (user_vm_child) return -ENOSYS;
    if (flags & UAPI_CLONE_VFORK) return rvvm_sys_vfork(current, flags, stack, parent_tid, tls, child_tid);
    user_vm_enter();
    int ret = rvvm_sys_clone_impl(current, flags, stack, parent_tid, tls, child_tid);
    user_vm_leave();
    return ret;
}

#include "rvvm_user_vm.h"
static void user_vm_serve(struct user_vm*, int);

struct user_vfork {
    rvvm_user_thread_t child;
    __typeof__(user_sig) signal;
    user_fd_table_t* source_table;
    uint32_t flags;
    size_t stack, tls;
    uint32_t *parent_tid, *child_tid;
    int result;
    int publish_error;
    uint32_t stage;
};

static void* user_vfork_worker(void* opaque)
{
    struct user_vfork* request = opaque;
    user_vm_service = true;
    user_sig = request->signal;
    user_sig.cpu = NULL;
    user_signal_process = request->child.signals;
    user_fd_table_t* source = request->source_table;
    user_fd_table_enter(source);
    uint64_t mask = UINT64_MAX;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &mask, NULL, 8);
    user_fd_mutex_lock(&user_vm_transition_lock);
    user_fd_lock();
    struct user_vm* vm = NULL;
    int control[2] = {-1, -1};
    bool transition_held = true;
    user_fd_table_t* table = calloc(1, sizeof(*table));
    if (!table) { request->result = -ENOMEM; goto out; }
    table->refs = 1;
    table->exe_fd = source->exe_fd;
    table->vm_fd = UINT32_MAX;
    table->vm_service = true;
    table->guard = user_fd_guard_create();
    memcpy(table->descriptor, source->descriptor, sizeof(table->descriptor));
    if (syscall(SYS_unshare, CLONE_FILES)) { request->result = -errno; user_fd_table_release(table); goto out; }
    /* The service's private descriptors must not block unrelated guest IO. */
    user_fd_unlock();
    user_fd_table_enter(table);
    if ((int)source->vm_fd >= 0) close((int)source->vm_fd);
    user_fd_table_release(source);
    request->source_table = NULL;
    user_fd_lock();
    spin_lock(&brk_lock);
    spin_lock(&mmap_lock);
    if (request->flags & UAPI_CLONE_VM) vm = user_vm_prepare();
    if (vm && (request->flags & UAPI_CLONE_CHILD_CLEARTID)) vm->child_cleartid = (uintptr_t)request->child_tid;
    if (((request->flags & UAPI_CLONE_VM) && !vm)
        || socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control)) request->result = -errno;
    else if (vm) {
        if (user_vm_pause_begin()) request->result = -errno;
        else {
            /* Moving an anonymous mapping changes non-private PI futex keys.
             * Never migrate a live kernel PI owner or waiter. */
            if (atomic_load_uint32(&user_vm_pi_users)) request->result = -ENOSYS;
            else {
                atomic_store_uint32(&user_vm_shared_active, 1);
                request->result = user_vm_share(vm) ? -errno : 0;
                if (request->result) atomic_store_uint32(&user_vm_shared_active, 0);
            }
            user_vm_pause_end();
        }
    }
    spin_unlock(&mmap_lock);
    spin_unlock(&brk_lock);
    if (request->result) goto out;

    /* Host fork isolates every native allocation and lock while inheriting
     * shared guest VMAs. The existing fork path owns signal/FD/CPU recovery. */
    int pid = rvvm_sys_clone_impl(&request->child,
        request->flags & ~(UAPI_CLONE_VM | UAPI_CLONE_VFORK | UAPI_CLONE_PIDFD | UAPI_CLONE_PARENT_SETTID), request->stack,
        request->parent_tid, request->tls, request->child_tid);
    if (!pid) {
        close(control[0]);
        table->vm_fd = control[1];
        table->vm_service = false;
        char ready;
        ssize_t received;
        do { received = recv(control[1], &ready, 1, 0); } while (received < 0 && errno == EINTR);
        if (received != 1) _exit(127);
        /* These descriptors and native aliases belong to the service only. */
        if (vm) user_vm_destroy(vm);
        user_fd_unlock();
        user_vm_service = false;
        user_vm_child = (request->flags & UAPI_CLONE_VM) != 0;
        user_vm_transition_lock = (user_fd_mutex_t){0};
        user_vm_transition_depth = 0;
        user_vm_pause.active = 0;
        request->child.fd_table = table;
        request->child.signal_mask = request->signal.mask;
        request->child.inherit_signal_stack = true;
        request->child.signal_stack = request->signal.stack;
        current_user_hart = request->child.cpu;
        rvvm_user_thread_wrap(&request->child);
        _exit(127);
    }
    request->result = pid;
    close(control[1]);
    control[1] = -1;
    if (pid > 0) {
        atomic_store_uint32(&request->stage, 1);
        rvvm_futex_wake(&request->stage, 1);
        while (atomic_load_uint32(&request->stage) == 1)
            rvvm_futex_wait(&request->stage, 1, RVVM_FUTEX_INFINITE);
        if (request->publish_error) {
            close(control[0]);
            control[0] = -1;
            while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
            request->result = request->publish_error;
        } else {
            if (!vm) {
                user_fd_mutex_unlock(&user_vm_transition_lock);
                transition_held = false;
            }
            (void)!send(control[0], "", 1, MSG_NOSIGNAL);
            /* CLOEXEC closes the peer only after successful exec. A failed exec
             * keeps guest bytes shared until the child writes its error and exits.
             * Kernel close on process death also covers SIGKILL and host faults. */
            user_vm_serve(vm, control[0]);
        }
    }
    if (vm) {
        /* EOF follows kernel exec/exit cleanup. The private host mm has only
         * one guest thread, so Linux may skip its clear_child_tid store;
         * publish it into the shared guest view before restoring COW. */
        uint32_t zero = 0;
        if (vm->child_cleartid
            && !uapi_extra_copy(&zero, (void*)vm->child_cleartid, sizeof(zero), true))
            syscall(SYS_futex, (void*)vm->child_cleartid, FUTEX_WAKE, 1, NULL, NULL, 0);
        spin_lock(&brk_lock);
        spin_lock(&mmap_lock);
        if (user_vm_pause_begin() || user_vm_restore(vm)) rvvm_fatal("Cannot restore vfork guest mappings");
        atomic_store_uint32(&user_vm_shared_active, 0);
        user_vm_pause_end();
        spin_unlock(&mmap_lock);
        spin_unlock(&brk_lock);
    }
out:
    if (control[0] >= 0) close(control[0]);
    if (control[1] >= 0) close(control[1]);
    if (vm) user_vm_destroy(vm);
    user_fd_unlock();
    if (transition_held) user_fd_mutex_unlock(&user_vm_transition_lock);
    rvvm_free_user_thread(request->child.cpu);
    user_fd_table_leave();
    if (request->source_table) request->source_table = NULL;
    user_signal_process_release(request->child.signals);
    atomic_store_uint32(&request->stage, 3);
    rvvm_futex_wake(&request->stage, 1);
    return NULL;
}

static int rvvm_sys_vfork(rvvm_user_thread_t* current, uint32_t flags, size_t stack,
                          uint32_t* parent_tid, size_t tls, uint32_t* child_tid)
{
    flags &= ~UAPI_CLONE_IGNORED_FLAGS;
    const uint32_t supported = 0xff | UAPI_CLONE_OPTIONAL_FLAGS | UAPI_CLONE_VM | UAPI_CLONE_VFORK | UAPI_CLONE_PIDFD;
    if ((flags & ~supported) || (flags & 0xff) != SIGCHLD) return -EINVAL;
    if ((flags & UAPI_CLONE_PIDFD) && (flags & UAPI_CLONE_PARENT_SETTID)) return -EINVAL;
    struct user_vfork* request = calloc(1, sizeof(*request));
    if (!request) return -ENOMEM;
    request->child.cpu = user_clone_cpu(current->cpu);
    request->child.refs = 1;
    request->child.signals = user_signal_process_retain();
    request->signal = user_sig;
    request->source_table = user_fd_table_retain();
    request->flags = flags;
    request->stack = stack;
    request->tls = tls;
    request->parent_tid = parent_tid;
    request->child_tid = child_tid;
    /* A helper must not receive guest signals before its TLS is initialized. */
    uint64_t held = UINT64_MAX, saved_mask;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, &saved_mask, 8);
    rvvm_thread_t* worker = rvvm_thread_create(user_vfork_worker, request);
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
    if (!worker) {
        rvvm_free_user_thread(request->child.cpu);
        user_signal_process_release(request->child.signals);
        user_fd_table_release(request->source_table);
        free(request);
        return -EAGAIN;
    }
    uint32_t stage;
    while (!(stage = atomic_load_uint32(&request->stage)))
        rvvm_futex_wait(&request->stage, 0, RVVM_FUTEX_INFINITE);
    if (stage == 1) {
        if (flags & UAPI_CLONE_PIDFD) {
            user_fd_lock();
            int pidfd = syscall(SYS_pidfd_open, request->result, 0);
            request->publish_error = pidfd < 0 ? -errno : uapi_extra_copy(&pidfd, parent_tid, sizeof(pidfd), true);
            if (request->publish_error && pidfd >= 0) close(pidfd);
            user_fd_unlock();
        } else if (flags & UAPI_CLONE_PARENT_SETTID)
            (void)uapi_extra_copy(&request->result, parent_tid, sizeof(request->result), true);
        atomic_store_uint32(&request->stage, 2);
        rvvm_futex_wake(&request->stage, 1);
    }
    thread_join(worker);
    int result = request->result;
    free(request);
    return result;
}

#define UAPI_FUTEX_CMD_MASK    0x3F
#define UAPI_FUTEX_WAIT        0x0
#define UAPI_FUTEX_WAKE        0x1
#define UAPI_FUTEX_WAIT_BITSET 0x9
#define UAPI_FUTEX_WAKE_BITSET 0xA

static int rvvm_sys_futex(uint32_t* addr, int futex_op, uint32_t val, size_t val2, uint32_t* uaddr2, uint32_t val3)
{
#if defined(__linux__)
    int command = futex_op & FUTEX_CMD_MASK;
    /* The worker has a different host mm. PRIVATE futex operations there
     * cannot use the suspended parent's kernel keys. Reject them explicitly
     * rather than returning a false wake or waiting on an unreachable key. */
    if (user_vm_child && (futex_op & FUTEX_PRIVATE_FLAG)) return -ENOSYS;
    bool pi_acquire = command == FUTEX_LOCK_PI || command == FUTEX_TRYLOCK_PI
                   || command == FUTEX_WAIT_REQUEUE_PI || command == FUTEX_LOCK_PI2;
    if (pi_acquire) {
        atomic_add_uint32(&user_vm_pi_users, 1);
        if (atomic_load_uint32(&user_vm_shared_active)) {
            atomic_sub_uint32(&user_vm_pi_users, 1);
            return -ENOSYS;
        }
    }
    long result;
    if (command == FUTEX_WAIT || command == FUTEX_WAIT_BITSET || command == FUTEX_LOCK_PI
        || command == FUTEX_WAIT_REQUEUE_PI || command == FUTEX_LOCK_PI2)
        result = errno_ret(USER_SYSCALL(SYS_futex, addr, futex_op, val, val2, uaddr2, val3));
    else result = errno_ret(syscall(SYS_futex, addr, futex_op, val, val2, uaddr2, val3));
    if (pi_acquire) {
        if (result < 0) atomic_sub_uint32(&user_vm_pi_users, 1);
        else ++user_vm_pi_owned;
    } else if (command == FUTEX_UNLOCK_PI && !result && user_vm_pi_owned) {
        --user_vm_pi_owned;
        atomic_sub_uint32(&user_vm_pi_users, 1);
    }
    return result;
#else
    UNUSED(val2); UNUSED(uaddr2); UNUSED(val3);
    switch (futex_op & UAPI_FUTEX_CMD_MASK) {
        case UAPI_FUTEX_WAIT:
        case UAPI_FUTEX_WAIT_BITSET:
            if (atomic_load_uint32(addr) == val) {
                sleep_ms(1);
            }
            return 0;
        case UAPI_FUTEX_WAKE:
        case UAPI_FUTEX_WAKE_BITSET:
            return 0;
    }
    rvvm_warn("Unimplemented futex op %x", futex_op);
    return -UAPI_EINVAL;
#endif
}

static int64_t rvvm_sys_getdents64(int fd, void* dirp, size_t size)
{
    return user_exe_getdents(fd, dirp, size);
}

#define UAPI_PROT_READ  0x1
#define UAPI_PROT_WRITE 0x2
#define UAPI_PROT_EXEC  0x4

#define UAPI_MAP_SHARED          0x000001
#define UAPI_MAP_PRIVATE         0x000002
#define UAPI_MAP_FIXED           0x000010
#define UAPI_MAP_ANON            0x000020
#define UAPI_MAP_FIXED_NOREPLACE 0x100000

#define UAPI_MAP_ILLEGAL         0xE00000

#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

static inline int rvvm_sys_prot(int prot)
{
    int ret = PROT_NONE;
    if (prot & UAPI_PROT_READ)  ret |= PROT_READ;
    if (prot & UAPI_PROT_WRITE) ret |= PROT_WRITE;
    // No real PROT_EXEC, since rvvm-user reads code when translating
    if (prot & UAPI_PROT_EXEC)  ret |= PROT_READ;
    return ret;
}

static rvvm_addr_t rvvm_sys_mmap(void* addr, size_t size, int prot, int flags, int fd, uint64_t offset)
{
    rvvm_info("sys_mmap(%lx, %lx, %x, %x, %d, %lx)", (size_t)addr, size, prot, flags, fd, offset);
    int mmap_flags = 0;
    if (flags & UAPI_MAP_ILLEGAL) {
        return -UAPI_EINVAL;
    }

    user_fd_lock();
    spin_lock(&mmap_lock);
    if (flags & UAPI_MAP_SHARED) mmap_flags |= MAP_SHARED;
    if (flags & UAPI_MAP_PRIVATE) mmap_flags |= MAP_PRIVATE;
    if (flags & UAPI_MAP_ANON) mmap_flags |= MAP_ANON;

    if (flags & UAPI_MAP_FIXED_NOREPLACE) {
#ifdef __linux__
        mmap_flags |= MAP_FIXED_NOREPLACE;
#else
        mmap_flags |= MAP_FIXED;
#endif
    }

    if (flags & UAPI_MAP_FIXED) {
        // This flag has destructive semantics...
        mmap_flags |= MAP_FIXED;
#ifndef __linux__
        munmap(addr, size);
#endif
    }

#ifdef __linux__
    if (flags & 0x4000) mmap_flags |= MAP_NORESERVE;
    rvvm_addr_t ret = errno_ret((size_t)user_vma_map(addr, size, rvvm_sys_prot(prot), mmap_flags, fd, offset));
#else
    rvvm_addr_t ret = errno_ret((size_t)mmap(addr, size, rvvm_sys_prot(prot), mmap_flags, fd, offset));
#endif
#ifdef USER_FAULT_META
    if (ret < (rvvm_addr_t)-4095) user_exec_update(ret, size, prot & UAPI_PROT_EXEC);
#endif
    spin_unlock(&mmap_lock);
    user_fd_unlock();
    return ret;
}

static int rvvm_sys_munmap(void* addr, size_t size)
{
    spin_lock(&mmap_lock);
#ifdef __linux__
    rvvm_addr_t ret = errno_ret(user_vma_unmap(addr, size));
#else
    rvvm_addr_t ret = errno_ret(munmap(addr, size));
#endif
#ifdef USER_FAULT_META
    if (!ret) user_exec_update((uintptr_t)addr, size, false);
#endif
    spin_unlock(&mmap_lock);
    return ret;
}

#include "rvvm_user_vm_rpc.h"

extern uint64_t __thread_selfid(void);

static int rvvm_sys_gettid(void)
{
#if defined(__APPLE__)
    return __thread_selfid();
#else
    return gettid();
#endif
}

static int fake_uid = 0;
static int fake_gid = 0;

static int rvvm_sys_getuid(void)
{
    if (fake_root) return fake_uid;
    return errno_ret(getuid());
}

static int rvvm_sys_getgid(void)
{
    if (fake_root) return fake_gid;
    return errno_ret(getgid());
}

static int rvvm_sys_setuid(int uid)
{
    if (fake_root) {
        fake_uid = uid;
        return 0;
    }
    return errno_ret(syscall(SYS_setuid, uid));
}

static int rvvm_sys_setgid(int gid)
{
    if (fake_root) {
        fake_gid = gid;
        return 0;
    }
    return errno_ret(syscall(SYS_setgid, gid));
}

static int rvvm_sys_getresuid(int* ruid, int* euid, int* suid)
{
#ifdef __linux__
    if (!fake_root) return errno_ret(syscall(SYS_getresuid, ruid, euid, suid));
#endif
    if (ruid) *ruid = rvvm_sys_getuid();
    if (euid) *euid = rvvm_sys_getuid();
    if (suid) *suid = rvvm_sys_getuid();
    return 0;
}

static int rvvm_sys_getresgid(int* rgid, int* egid, int* sgid)
{
#ifdef __linux__
    if (!fake_root) return errno_ret(syscall(SYS_getresgid, rgid, egid, sgid));
#endif
    if (rgid) *rgid = rvvm_sys_getgid();
    if (egid) *egid = rvvm_sys_getgid();
    if (sgid) *sgid = rvvm_sys_getgid();
    return 0;
}

static rvvm_addr_t rvvm_sys_getcwd(char* buffer, size_t size)
{
#ifdef __linux__
    if (!prefix_path || !*prefix_path) {
        return errno_ret(syscall(SYS_getcwd, buffer, size));
    }
#endif
    char tmp[UAPI_PATH_MAX] = {0};
    if (!getcwd(tmp, sizeof(tmp))) {
        return last_errno();
    }
    const char* path = tmp;
    size_t prefix_len = prefix_path ? strlen(prefix_path) : 0;
    if (prefix_len && !strncmp(path, prefix_path, prefix_len)
        && (path[prefix_len] == '/' || !path[prefix_len])) {
        path += prefix_len;
        if (!*path) path = "/";
    }
    // Linux returns the bytes copied INCLUDING NUL; libc may resize to this.
    size_t length = strlen(path) + 1;
    if (length > size) return -ERANGE;
#ifdef __linux__
    int ret = uapi_extra_copy((void*)path, buffer, length, true);
    if (ret) return ret;
#else
    memcpy(buffer, path, length);
#endif
    return length;
}

static rvvm_addr_t rvvm_sys_readlinkat(int dirfd, const char* pathname, char* buffer, size_t size)
{
    if (!size) return -EINVAL;
    char snapshot[UAPI_PATH_MAX], path[UAPI_PATH_MAX], tmp[UAPI_PATH_MAX];
    long path_length = user_path_copy(snapshot, pathname, sizeof(snapshot));
    if (path_length < 0) return path_length;
    const char* wrapped = wrap_path(path, snapshot);
    // readlink does not follow the final symlink. A proc executable link must
    // therefore end in the component "exe"; directory aliases still qualify.
    bool maybe_exe = path_length >= 3 && !memcmp(snapshot + path_length - 3, "exe", 3)
        && (path_length == 3 || snapshot[path_length - 4] == '/');
    if (!maybe_exe && (!prefix_path || !*prefix_path))
        return errno_ret(readlinkat(dirfd, wrapped, buffer, size));
    bool pinned = maybe_exe && user_exe_fd >= 0 && user_exe_link(dirfd, wrapped);
    if (pinned) {
        user_fd_mutex_lock(&user_exe_lock);
        dirfd = AT_FDCWD;
        wrapped = user_exe_path();
    }
    char remote_descriptor[64];
    if (!pinned && maybe_exe
        && user_ptrace_proc_exe(dirfd, wrapped, remote_descriptor, sizeof(remote_descriptor))) {
        dirfd = AT_FDCWD;
        wrapped = remote_descriptor;
    }
    if (!prefix_path || !*prefix_path) {
        long result = errno_ret(readlinkat(dirfd, wrapped, buffer, size));
        if (pinned) user_fd_mutex_unlock(&user_exe_lock);
        return result;
    }
    ssize_t length = readlinkat(dirfd, wrapped, tmp, sizeof(tmp));
    int error = length < 0 ? last_errno() : 0;
    if (pinned) user_fd_mutex_unlock(&user_exe_lock);
    if (error) return error;
    size_t offset = 0, prefix = prefix_path ? strlen(prefix_path) : 0;
    if (prefix && (size_t)length > prefix && !memcmp(tmp, prefix_path, prefix) && tmp[prefix] == '/')
        offset = prefix;
    size_t count = (size_t)length - offset;
    if (count > size) count = size;
    error = uapi_extra_copy(tmp + offset, buffer, count, true);
    return error ? error : (rvvm_addr_t)count;
}

#undef rvvm_info
//#define rvvm_info(...) rvvm_warn(__VA_ARGS__);
#define rvvm_info(...)

#include "user_ptrace/user_ptrace_restart.h"

static void* rvvm_user_thread_wrap(void* arg)
{
    user_signal_block_all();
    rvvm_user_thread_t* thread = arg;
    rvvm_hart_t* cpu = thread->cpu;
    bool running = true;
    int exit_status = 0;

    current_user_hart = cpu;
    user_signal_process = thread->signals;
    user_fd_table_enter(thread->fd_table);
    user_private_signals_restore();
    user_signal_init(cpu, thread->signal_mask);
    if (thread->inherit_signal_stack) user_sig.stack = thread->signal_stack;
    user_vm_pause_checkpoint();

    char path_buf[UAPI_PATH_MAX] = {0};
    char path_buf1[UAPI_PATH_MAX] = {0};

    // Set up thread tid, child_tid
    uint32_t tid = rvvm_sys_gettid();
    if (thread->process_thread) user_vm_initial_tid = tid;
    if (thread->child_settid) {
        (void)uapi_extra_copy(&tid, thread->child_settid, sizeof(tid), true);
    }
    // CLONE_VM shares the parent address space. Write both TID slots before
    // guest execution so the parent cannot overwrite an already-cleared TID.
    if (thread->parent_settid) (void)uapi_extra_copy(&tid, thread->parent_settid, sizeof(tid), true);
    atomic_store_uint32(&thread->tid, tid);
    rvvm_futex_wake(&thread->tid, 1);
    user_ptrace_set_exe_fd_pointer(&user_exe_fd_value);
    uint64_t initial_mask = user_sig.mask;
    user_ptrace_init(cpu, user_cpu_auxv, user_cpu_auxv_size, &user_sig.mask, &user_sig.pending, thread->ptrace_state);
    if (user_sig.mask != initial_mask) user_apply_mask();

    while (running) {
        user_ptrace_checkpoint(cpu);
        user_ptrace_pending_signal(cpu);
        user_signal_deliver(cpu);
        rvvm_addr_t cause;
#ifdef USER_FAULT_POC
        // The guest delivery path restores the host mask after building the frame.
        if (sigsetjmp(user_fault_resume, 0)) {
            user_fault_armed = 0;
            user_fault_restore_fenv();
            cpu->user_fault_interpreted = 0;
            cpu->lrsc = false;
            rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, cpu->user_fault_pc);
            user_fault_address(cpu);
            if (user_ptrace_interrupted()) {
                user_sig.pending = 0;
                user_sig.synchronous = false;
                user_apply_mask();
            }
            riscv_jit_discard(cpu);
            continue;
        }
        user_fault_armed = 1;
#endif
        cause = user_ptrace_run(cpu);
#ifdef USER_FAULT_POC
        user_fault_armed = 0;
#endif
        if (cause == (rvvm_addr_t)-1) continue;
        if (cause == 8) {
            user_ptrace_dispatch();
            if (user_sig.pending) continue;
            user_sig.syscall_unstarted = false;
            if (user_ptrace_syscall_begin(cpu)) { user_ptrace_syscall_end(cpu); continue; }
            user_ptrace_restart_prepare(cpu);
            // Handle syscall trap
            rvvm_addr_t a0 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10);
            rvvm_addr_t a1 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 11);
            rvvm_addr_t a2 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 12);
            rvvm_addr_t a3 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 13);
            rvvm_addr_t a4 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 14);
            rvvm_addr_t a5 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 15);
            rvvm_addr_t a7 = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 17);
            user_exe_relocation_resume();
            // Use an invalid host fd for the private executable pin, while
            // preserving kernel rules for ignored dirfds and argument errors.
            // The common case adds only comparisons, not a descriptor lookup.
            if (user_private_fd((int)a0) || user_private_fd((int)a1) || user_private_fd((int)a2)) {
                unsigned fds = user_exe_fd_args(a7);
                if ((fds & 1) && user_private_fd((int)a0)) a0 = -1;
                if ((fds & 2) && user_private_fd((int)a1)) a1 = -1;
                if ((fds & 4) && user_private_fd((int)a2)) a2 = -1;
                if (a7 == 95 && a0 == 3 && user_private_fd((int)a1)) a1 = -1;
            }
            bool vm_mutation = a7 == 196 || a7 == 197 || a7 == 214 || a7 == 215
                            || a7 == 216 || a7 == 222 || a7 == 226 || a7 == 233;
            if (a7 == 222 && !(a3 & UAPI_MAP_ANON) && user_private_fd((int)a4)) a4 = -1;
            if (a7 == 96 && user_vm_child) {
                thread->child_cleartid = to_ptr(a0);
                int result = user_vm_rpc(a7, a0, 0, 0, 0, 0, 0);
                a0 = result < 0 ? result : syscall(SYS_set_tid_address, a0);
            } else if (vm_mutation && user_vm_child) a0 = user_vm_rpc(a7, a0, a1, a2, a3, a4, a5);
            else {
            if (vm_mutation) user_vm_enter();
            switch (a7) {
                case 128: // restart_syscall: preserve a traced timed wait's original deadline
                    a0 = user_ptrace_restart_syscall();
                    break;
                case 132:
                    a0 = user_sigaltstack(cpu, to_ptr(a0), to_ptr(a1));
                    break;
                // Userspace emulation cannot load a guest kernel or guest modules into the host.
                case 104: // kexec_load
                case 105: // init_module
                case 273: // finit_module
                case 294: // kexec_file_load
                case 293: // rseq requires integration with guest execution
                case 426: // io_uring_enter
                case 427: // io_uring_register
                // Do not advertise a Landlock ABI until guest sandboxing is supported.
                case 444: // landlock_create_ruleset (including ABI probes)
                case 445: // landlock_add_rule
                case 446: // landlock_restrict_self
                    a0 = -UAPI_ENOSYS;
                    break;
#ifdef __linux__
                case 39: // umount2: Linux mount flags are architecture independent
                    a0 = errno_ret(syscall(SYS_umount2, to_str(a0), (int)a1));
                    break;
                case 40: // mount: leave namespace and privilege checks to Linux
                    a0 = errno_ret(syscall(SYS_mount, to_str(a0), to_str(a1), to_str(a2), a3, to_ptr(a4)));
                    break;
                case 97: // unshare
                    a0 = user_fd_unshare(a0);
                    break;
                case 107: // timer_create: use kernel timer IDs, not libc timer_t
                    BUILD_ASSERT(sizeof(struct sigevent) == 64);
                    BUILD_ASSERT(offsetof(struct sigevent, sigev_value) == 0);
                    BUILD_ASSERT(offsetof(struct sigevent, sigev_signo) == 8);
                    BUILD_ASSERT(offsetof(struct sigevent, sigev_notify) == 12);
                    BUILD_ASSERT(offsetof(struct sigevent, _sigev_un._tid) == 16);
                    a0 = errno_ret(syscall(SYS_timer_create, (int)a0, to_ptr(a1), to_ptr(a2)));
                    break;
                case 108: // timer_gettime
                    a0 = errno_ret(syscall(SYS_timer_gettime, (int)a0, to_ptr(a1)));
                    break;
                case 109: // timer_getoverrun
                    a0 = errno_ret(syscall(SYS_timer_getoverrun, (int)a0));
                    break;
                case 110: // timer_settime: RV64 uses two LP64 timespec structures
                    a0 = errno_ret(syscall(SYS_timer_settime, (int)a0, (int)a1, to_ptr(a2), to_ptr(a3)));
                    break;
                case 111: // timer_delete
                    a0 = errno_ret(syscall(SYS_timer_delete, (int)a0));
                    break;
                case 169: // gettimeofday: timeval and timezone have the LP64 Linux ABI
                    BUILD_ASSERT(sizeof(struct timeval) == 16);
                    BUILD_ASSERT(sizeof(struct timezone) == 8);
                    a0 = errno_ret(syscall(SYS_gettimeofday, to_ptr(a0), to_ptr(a1)));
                    break;
                case 117:
                    a0 = user_ptrace_request(a0, a1, a2, a3);
                    break;
                case 92: // personality: only the default Linux execution domain is emulated
                    a0 = ((uint32_t)a0 == 0 || (uint32_t)a0 == UINT32_MAX) ? 0 : -UAPI_EINVAL;
                    break;
                case 285: // copy_file_range: both offsets point to signed 64-bit values
                    a0 = errno_ret(syscall(SYS_copy_file_range, (int)a0, to_ptr(a1),
                                          (int)a2, to_ptr(a3), a4, (unsigned)a5));
                    break;
                case 227: // msync
                    a0 = errno_ret(msync(to_ptr(a0), a1, a2));
                    break;
                case 8: // getxattr
                    a0 = errno_ret(getxattr(wrap_path(path_buf, to_str(a0)), to_str(a1), to_ptr(a2), a3));
                    break;
                case 5: // setxattr
                    a0 = errno_ret(setxattr(wrap_path(path_buf, to_str(a0)), to_str(a1), to_ptr(a2), a3,
                        uapi_translate_flags(a4, uapi_xattr_flags,
                                             STATIC_ARRAY_SIZE(uapi_xattr_flags), true)));
                    break;
                case 6: // lsetxattr: operate on the link itself, not its target
                    a0 = errno_ret(lsetxattr(wrap_path(path_buf, to_str(a0)), to_str(a1), to_ptr(a2), a3,
                        uapi_translate_flags(a4, uapi_xattr_flags,
                                             STATIC_ARRAY_SIZE(uapi_xattr_flags), true)));
                    break;
                case 9: // lgetxattr
                    a0 = errno_ret(lgetxattr(wrap_path(path_buf, to_str(a0)), to_str(a1), to_ptr(a2), a3));
                    break;
                case 11: // listxattr
                    a0 = errno_ret(listxattr(wrap_path(path_buf, to_str(a0)), to_ptr(a1), a2));
                    break;
                case 12: // llistxattr
                    a0 = errno_ret(llistxattr(wrap_path(path_buf, to_str(a0)), to_ptr(a1), a2));
                    break;
                case 13: // flistxattr
                    a0 = errno_ret(flistxattr(a0, to_ptr(a1), a2));
                    break;
                case 14: // removexattr
                    a0 = errno_ret(removexattr(wrap_path(path_buf, to_str(a0)), to_str(a1)));
                    break;
                case 15: // lremovexattr
                    a0 = errno_ret(lremovexattr(wrap_path(path_buf, to_str(a0)), to_str(a1)));
                    break;
                case 16: // fremovexattr
                    a0 = errno_ret(fremovexattr(a0, to_str(a1)));
                    break;
                case 71: // sendfile: RV64 and the hosts use a signed 64-bit offset
                    a0 = errno_ret(USER_SYSCALL(SYS_sendfile, a0, a1, a2, a3, 0, 0));
                    break;
                case 180: // mq_open
                    a0 = uapi_extra_mq_open(to_str(a0), a1, a2, to_ptr(a3));
                    break;
                case 186: case 187: case 188: case 189:
                    a0 = user_msg_syscall(a7, a0, a1, a2, a3, a4);
                    break;
                case 228: case 229: case 284:
                    a0 = user_lock_memory(a7, a0, a1, a2);
                    break;
                case 116: case 162:
                    a0 = user_system_control(a7, a0, a1, a2);
                    break;
                case 263: // fanotify_mark: mask is a single RV64 argument
                    if ((int)a3 == user_exe_fd) a3 = -1;
                    a0 = user_fs_fanotify_mark(a0, a1, (uint64_t)a2, (intptr_t)a3, to_str(a4));
                    break;
                case 451: // cachestat
                    a0 = user_fs_cachestat(a0, a1, a2, a3);
                    break;
                case 181: case 182: case 183: case 185:
                case 190: case 192: case 193:
                    a0 = user_ipc_syscall(a7, a0, a1, a2, a3, a4);
                    break;
                case 30: case 31: case 81: case 84: case 213:
                case 274: case 275:
                    a0 = user_control_extra(a7, a0, a1, a2, a3);
                    break;
                case 75: // vmsplice
                    a0 = user_io_vmsplice(a0, a1, a2, a3);
                    break;
                case 243: // recvmmsg
                    a0 = user_io_recvmmsg(a0, a1, a2, a3, a4);
                    break;
                case 191: // semctl
                    a0 = uapi_extra_semctl(a0, a1, a2, a3);
                    break;
                case 262: // fanotify_init
                    a0 = uapi_extra_fanotify_init(a0, a1);
                    break;
                case 265: // open_by_handle_at
                    a0 = uapi_extra_open_by_handle_at(a0, to_ptr(a1), a2);
                    break;
                case 281: // execveat: the kernel handles ELF/script dispatch through binfmt
                    a0 = user_binfmt_executable || getenv("RVVM_USER_BINFMT")
                       ? user_execveat(a0, to_str(a1), to_ptr(a2), to_ptr(a3),
                           uapi_translate_flags(a4, uapi_path_flags, STATIC_ARRAY_SIZE(uapi_path_flags), true))
                       : -UAPI_ENOSYS;
                    break;
                case 441: // epoll_pwait2
                    a0 = user_epoll_wait(SYS_epoll_pwait2, a0, to_ptr(a1), a2, a3, to_ptr(a4), a5);
                    break;
                case 7: // fsetxattr
                    a0 = errno_ret(fsetxattr(a0, to_str(a1), to_ptr(a2), a3,
                        uapi_translate_flags(a4, uapi_xattr_flags,
                                             STATIC_ARRAY_SIZE(uapi_xattr_flags), true)));
                    break;
                case 10: // fgetxattr
                    a0 = errno_ret(fgetxattr(a0, to_str(a1), to_ptr(a2), a3));
                    break;
                case 76: // splice: offsets are pointers to signed 64-bit integers
                    a0 = errno_ret(syscall(SYS_splice, (int)a0, to_ptr(a1),
                        (int)a2, to_ptr(a3), a4,
                        uapi_translate_flags(a5, uapi_splice_flags,
                                             STATIC_ARRAY_SIZE(uapi_splice_flags), true)));
                    break;
                case 77: // tee
                    a0 = errno_ret(USER_SYSCALL(SYS_tee, a0, a1, a2,
                        uapi_translate_flags(a3, uapi_splice_flags,
                                             STATIC_ARRAY_SIZE(uapi_splice_flags), true), 0, 0));
                    break;
                case 26: // inotify_init1
                    a0 = errno_ret(syscall(SYS_inotify_init1,
                        uapi_translate_flags(a0, uapi_fd_create_flags,
                                             STATIC_ARRAY_SIZE(uapi_fd_create_flags), true)));
                    break;
                case 27: // inotify_add_watch: masks are architecture-independent Linux UAPI
                    a0 = errno_ret(syscall(SYS_inotify_add_watch, a0,
                        prefix_path && *prefix_path ? wrap_path(path_buf, to_str(a1)) : to_str(a1), a2));
                    break;
                case 28: // inotify_rm_watch
                    a0 = errno_ret(syscall(SYS_inotify_rm_watch, a0, a1));
                    break;
                case 85: // timerfd_create
                    a0 = errno_ret(syscall(SYS_timerfd_create, a0,
                        uapi_translate_flags(a1, uapi_fd_create_flags,
                                             STATIC_ARRAY_SIZE(uapi_fd_create_flags), true)));
                    break;
                case 86: // timerfd_settime
                    a0 = errno_ret(syscall(SYS_timerfd_settime, a0, a1, to_ptr(a2), to_ptr(a3)));
                    break;
                case 87: // timerfd_gettime
                    a0 = errno_ret(syscall(SYS_timerfd_gettime, a0, to_ptr(a1)));
                    break;
                case 267: // syncfs
                    a0 = errno_ret(USER_SYSCALL(SYS_syncfs, a0, 0, 0, 0, 0, 0));
                    break;
                case 264: // name_to_handle_at: mount ID may be 32 or 64 bits
                    a0 = errno_ret(syscall(SYS_name_to_handle_at, (int)a0,
                        wrap_path(path_buf, to_str(a1)), to_ptr(a2), to_ptr(a3), (int)a4));
                    break;
#endif
                case 17: { // getcwd
                    rvvm_info("sys_getcwd(%lx, %lx)", a0, a1);
                    a0 = rvvm_sys_getcwd(to_ptr(a0), a1);
                    break;
                }
#ifdef __linux__
                case 19: // eventfd2
                    rvvm_info("sys_eventfd2(%lx, %lx)", a0, a1);
                    a0 = errno_ret(eventfd(a0, a1));
                    break;
                case 20: // epoll_create1
                    rvvm_info("sys_epoll_create1(%lx)", a0);
                    a0 = errno_ret(epoll_create1(a0));
                    break;
                case 21: { // epoll_ctl
                    // Host (x86-64) epoll_event is packed (12 bytes) while
                    // RISC-V UAPI one is naturally aligned (16 bytes) - convert
                    rvvm_info("sys_epoll_ctl(%lx, %lx, %lx, %lx)", a0, a1, a2, a3);
                    struct epoll_event host_ev;
                    struct epoll_event* host_ev_ptr = NULL;
                    if (a3 && a1 != EPOLL_CTL_DEL) {
                        struct uapi_epoll_event guest_ev;
                        if (uapi_extra_copy(&guest_ev, to_ptr(a3), sizeof(guest_ev), false)) {
                            a0 = -UAPI_EFAULT;
                            break;
                        }
                        host_ev.events = guest_ev.event;
                        host_ev.data.u64 = guest_ev.data.u64;
                        host_ev_ptr = &host_ev;
                    }
                    a0 = errno_ret(epoll_ctl(a0, a1, a2, host_ev_ptr));
                    break;
                }
                case 22: // epoll_pwait
                    a0 = user_epoll_wait(SYS_epoll_pwait, a0, to_ptr(a1), a2, a3, to_ptr(a4), a5);
                    break;
#endif
                case 23: // dup
                    rvvm_info("sys_dup(%ld)", a0);
                    a0 = user_exe_dup(a0);
                    break;
                case 24: // dup3
                    rvvm_info("sys_dup3(%ld, %ld, %lx)", a0, a1, a2);
#ifdef __linux__
                    a0 = user_exe_dup3(a0, a1, uapi_open_flags_to_host(a2));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 25: { // fcntl64
                    rvvm_info("sys_fcntl64(%ld, %lx, %lx)", a0, a1, a2);
                    if (a1 == 3) { // RISC-V F_GETFL
                        long ret = user_exe_fcntl(a0, F_GETFL, 0);
                        if (ret < 0) {
                            a0 = ret;
                        } else {
                            a0 = uapi_open_flags_to_guest(ret);
                        }
                    } else if (a1 == 4) { // RISC-V F_SETFL
                        a0 = user_exe_fcntl(a0, F_SETFL, uapi_open_flags_to_host(a2));
                    } else {
                        a0 = user_exe_fcntl(a0, a1, a2);
                    }
                    break;
                }
                case 29: // ioctl
                    // TODO: I sure hope not many ioctl() interfaces need struct conversion...
                    rvvm_info("sys_ioctl(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(ioctl(a0, a1, a2));
                    break;
                case 32: // flock
                    rvvm_info("sys_flock(%ld, %lx)", a0, a1);
                    a0 = errno_ret(USER_SYSCALL(SYS_flock, a0, a1, 0, 0, 0, 0));
                    break;
                case 33: // mknodat
                    rvvm_info("sys_mknodat(%ld, %s, %lx, %lx)", a0, to_str(a1), a2, a3);
                    a0 = errno_ret(mknodat(a0, wrap_path(path_buf, to_str(a1)), a2, a3));
                    break;
                case 34: // mkdirat
                    rvvm_info("sys_mkdirat(%ld, %s, %lx)", a0, to_str(a1), a2);
                    a0 = errno_ret(mkdirat(a0, wrap_path(path_buf, to_str(a1)), a2));
                    break;
                case 35: // unlinkat
                    rvvm_info("sys_unlinkat(%ld, %s, %lx)", a0, to_str(a1), a2);
                    a0 = errno_ret(unlinkat(a0, wrap_path(path_buf, to_str(a1)), a2));
                    break;
                case 36: // symlinkat
                    rvvm_info("sys_symlinkat(%s, %ld, %s)", to_str(a0), a1, to_str(a2));
                    a0 = errno_ret(symlinkat(wrap_path(path_buf, to_str(a0)), a1,
                                             wrap_path(path_buf1, to_str(a2))));
                    break;
                case 37: // linkat
                    rvvm_info("sys_linkat(%ld, %s, %ld, %s, %lx)", a0, to_str(a1), a2, to_str(a3), a4);
                    a0 = errno_ret(linkat(a0, wrap_path(path_buf, to_str(a1)),
                                          a2, wrap_path(path_buf1, to_str(a3)), a4));
                    break;
                case 43: { // statfs64
                    struct statfs stfs = {0};
                    rvvm_info("sys_statfs64(%s, %lx, %lx)", to_str(a0), a1, a2);
                    a0 = errno_ret(statfs(wrap_path(path_buf, to_str(a0)), &stfs));
                    if (!a0) {
                        struct uapi_statfs64 guest;
                        uapi_statfs64_convert(&guest, &stfs);
                        a0 = uapi_extra_copy(&guest, to_ptr(a1), sizeof(guest), true);
                    }
                    break;
                }
                case 44: { // fstatfs64
                    struct statfs stfs = {0};
                    rvvm_info("sys_fstatfs64(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(fstatfs(a0, &stfs));
                    if (!a0) {
                        struct uapi_statfs64 guest;
                        uapi_statfs64_convert(&guest, &stfs);
                        a0 = uapi_extra_copy(&guest, to_ptr(a1), sizeof(guest), true);
                    }
                    break;
                }
                case 45: // truncate64
                    rvvm_info("sys_truncate64(%s, %lx)", to_str(a0), a1);
                    a0 = errno_ret(truncate(wrap_path(path_buf, to_str(a0)), a1));
                    break;
                case 46: // ftruncate64
                    rvvm_info("sys_ftruncate64(%ld, %lx)", a0, a1);
                    a0 = errno_ret(ftruncate(a0, a1));
                    break;
#ifdef __linux__
                case 47: // fallocate
                    rvvm_info("sys_fallocate(%ld, %lx, %lx, %lx)", a0, a1, a2, a3);
                    a0 = errno_ret(fallocate(a0, a1, a2, a3));
                    break;
#endif
                case 48: // faccessat
                    rvvm_info("sys_faccessat(%ld, %s, %lx)", a0, to_str(a1), a2);
                    a0 = errno_ret(faccessat(a0, wrap_path(path_buf, to_str(a1)), a2, 0));
                    break;
                case 49: // chdir
                    rvvm_info("sys_chdir(%s)", to_str(a0));
                    a0 = errno_ret(chdir(wrap_path(path_buf, to_str(a0))));
                    break;
                case 50: // fchdir
                    rvvm_info("sys_fchdir(%ld)", a0);
                    a0 = errno_ret(fchdir(a0));
                    break;
                case 51: // chroot: real kernel operation in binfmt mode
                    a0 = prefix_path && *prefix_path ? -UAPI_ENOSYS
                        : errno_ret(chroot(to_str(a0)));
                    break;
                case 52: // fchmod
                    rvvm_info("sys_fchmodat(%ld, %lx)", a0, a1);
                    a0 = errno_ret(fchmod(a0, a1));
                    break;
                case 53: // fchmodat
                    rvvm_info("sys_fchmodat(%ld, %s, %lx)", a0, to_str(a1), a2);
                    a0 = errno_ret(fchmodat(a0, wrap_path(path_buf, to_str(a1)), a2, 0));
                    break;
                case 54: // fchownat
                    if (fake_root) {
                        a0 = 0;
                    } else {
                        rvvm_info("sys_fchownat(%ld, %s, %lx, %lx, %lx)", a0, to_str(a1), a2, a3, a4);
                        a0 = errno_ret(fchownat(a0, wrap_path(path_buf, to_str(a1)), a2, a3, a4));
                    }
                    break;
                case 55: // fchown
                    if (fake_root) {
                        a0 = 0;
                    } else {
                        rvvm_info("sys_fchownat(%ld, %lx, %lx)", a0, a1, a2);
                        a0 = errno_ret(fchown(a0, a1, a2));
                    }
                    break;
                case 56: { // openat
                    int dirfd = a0;
                    uint32_t flags = uapi_open_flags_to_host(a2);
                    const char* path = wrap_path(path_buf, to_str(a1));
                    long special;
                    if (user_exe_fast_open(path, flags, &special)) {
                        a0 = special;
                        break;
                    }
                    rvvm_info("sys_openat(%ld, %s, %lx, %lx)", a0, to_str(a1), a2, a3);
                    a0 = errno_ret(USER_SYSCALL(SYS_openat, a0, path, flags, a3, 0, 0));
                    a0 = user_cpu_opened((int64_t)a0, flags, dirfd, path);
                    break;
                }
                case 57: // close
                    a0 = user_exe_close(a0);
                    break;
                case 59: // pipe2
                    rvvm_info("sys_pipe2(%lx, %lx)", a0, a1);
#ifdef __linux__
                    a0 = errno_ret(syscall(SYS_pipe2, to_ptr(a0), uapi_open_flags_to_host(a1)));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 61: // getdents64
                    a0 = rvvm_sys_getdents64(a0, to_ptr(a1), a2);
                    break;
                case 62: // lseek
                    a0 = errno_ret(lseek(a0, a1, a2));
                    break;
                case 63: // read
                    a0 = errno_ret(USER_SYSCALL(SYS_read, a0, a1, a2, 0, 0, 0));
                    break;
                case 64: // write
                    a0 = errno_ret(USER_SYSCALL(SYS_write, a0, a1, a2, 0, 0, 0));
                    break;
                case 65: // readv
                    // TODO: struct conversion(?)
                    a0 = errno_ret(USER_SYSCALL(SYS_readv, a0, a1, a2, 0, 0, 0));
                    break;
                case 66: // writev
                    // TODO: struct conversion(?)
                    a0 = errno_ret(USER_SYSCALL(SYS_writev, a0, a1, a2, 0, 0, 0));
                    break;
                case 67: // pread64
                    a0 = errno_ret(USER_SYSCALL(SYS_pread64, a0, a1, a2, a3, 0, 0));
                    break;
                case 68: // pwrite64
                    a0 = errno_ret(USER_SYSCALL(SYS_pwrite64, a0, a1, a2, a3, 0, 0));
                    break;
                case 69: // preadv
                    a0 = user_posix_vector(SYS_preadv, a0, a1, a2, a3, a4, 0);
                    break;
                case 70: // pwritev
                    a0 = user_posix_vector(SYS_pwritev, a0, a1, a2, a3, a4, 0);
                    break;
                case 286: // preadv2
                    a0 = user_posix_vector(SYS_preadv2, a0, a1, a2, a3, a4, a5);
                    break;
                case 287: // pwritev2
                    a0 = user_posix_vector(SYS_pwritev2, a0, a1, a2, a3, a4, a5);
                    break;
                case 72: // pselect6 (RISC-V 64-bit time and fd_set ABI)
#ifdef __linux__
                    // The sixth argument points to {sigset pointer, kernel sigset size}.
                    // Forward it so unmasking signals and waiting remain atomic.
                    BUILD_ASSERT(sizeof(void*) == 8 && sizeof(unsigned long) == 8);
                    a0 = errno_ret(USER_SYSCALL(SYS_pselect6, a0, a1, a2, a3, a4, a5));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 73: // ppoll
#ifdef __linux__
                    BUILD_ASSERT(sizeof(struct pollfd) == 8);
                    BUILD_ASSERT(offsetof(struct pollfd, events) == 4);
                    BUILD_ASSERT(offsetof(struct pollfd, revents) == 6);
                    a0 = errno_ret(USER_SYSCALL(SYS_ppoll, a0, a1, a2, a3, a4, 0));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 78: // readlinkat
                    rvvm_info("sys_readlinkat(%ld, %s, %lx, %lx)", a0, to_str(a1), a2, a3);
                    a0 = rvvm_sys_readlinkat(a0, to_str(a1), to_ptr(a2), a3);
                    break;
                case 79: { // newfstatat
#if defined(__linux__) && defined(__aarch64__) && defined(__AARCH64EL__)
                    // ARM64 and RV64 share the asm-generic kernel stat ABI.
                    // Let the kernel copy to guest memory and report EFAULT.
                    a0 = uapi_stat_syscall(SYS_newfstatat, (int)a0,
                        (long)wrap_path(path_buf, to_str(a1)), a2, (int)a3);
#else
                    struct stat st = {0};
                    rvvm_info("sys_newfstatat(%ld, %s, %lx, %lx)", a0, to_str(a1), a2, a3);
                    a0 = errno_ret(fstatat(a0, wrap_path(path_buf, to_str(a1)), &st, a3));
                    if (!a0) {
                        struct uapi_stat guest;
                        uapi_stat_convert(&guest, &st);
                        a0 = uapi_extra_copy(&guest, to_ptr(a2), sizeof(guest), true);
                    }
#endif
                    break;
                }
                case 80: { // newfstat
#if defined(__linux__) && defined(__aarch64__) && defined(__AARCH64EL__)
                    a0 = uapi_stat_syscall(SYS_fstat, (int)a0, a1, 0, 0);
#else
                    struct stat st = {0};
                    rvvm_info("sys_newfstat(%ld, %lx)", a0, a1);
                    a0 = errno_ret(fstat(a0, &st));
                    if (!a0) {
                        struct uapi_stat guest;
                        uapi_stat_convert(&guest, &st);
                        a0 = uapi_extra_copy(&guest, to_ptr(a1), sizeof(guest), true);
                    }
#endif
                    break;
                }
                case 82: // fsync
                    a0 = errno_ret(fsync(a0));
                    break;
                case 83: // fdatasync
                    a0 = errno_ret(fdatasync(a0));
                    break;
                case 88: // utimensat
#ifdef __linux__
                    // Raw syscall preserves futimens' NULL pathname and kernel EFAULT handling.
                    a0 = errno_ret(syscall(SYS_utimensat, (int)a0,
                        wrap_path(path_buf, to_str(a1)), to_ptr(a2),
                        uapi_translate_flags(a3, uapi_path_flags,
                                             STATIC_ARRAY_SIZE(uapi_path_flags), true)));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 90: // capget: Linux capability ABI uses fixed-width 32-bit fields
                    a0 = errno_ret(syscall(SYS_capget, to_ptr(a0), to_ptr(a1)));
                    break;
                case 91: // capset: change only the calling thread, as the guest syscall does
                    a0 = errno_ret(syscall(SYS_capset, to_ptr(a0), to_ptr(a1)));
                    break;
                case 93: // exit
                    if (thread->process_thread && user_vm_fd >= 0 && !user_vm_child)
                        shutdown(user_vm_fd, SHUT_WR);
                    user_ptrace_exit(cpu);
                    exit_status = a0;
                    running = false;
                    break;
                case 94: // exit_group
                    user_ptrace_exit(cpu);
                    _Exit(a0);
                    break;
                case 95: { // waitid: includes P_PIDFD and the raw syscall's rusage argument
                    long queued;
                    int type = a0;
                    bool started = false;
                    do {
                        bool poll = !(a3 & WNOHANG) && (user_ptrace_events_tracing()
                            || (a3 & (WNOWAIT | WSTOPPED)) == (WNOWAIT | WSTOPPED));
                        if (poll && type == 3 && (fcntl((int)a1, F_GETFL) & O_NONBLOCK))
                            poll = false;
                        uint32_t generation = poll ? user_ptrace_events_generation() : 0;
                        siginfo_t scratch = {0};
                        siginfo_t* caller_info = a2 ? to_ptr(a2) : &scratch;
                        if (user_ptrace_waitid_ready(type, a1, caller_info, a3, to_ptr(a4), &queued)) { a0 = queued; break; }
                        siginfo_t* native_info = poll ? &scratch : caller_info;
                        a0 = errno_ret(USER_SYSCALL(SYS_waitid, type, (unsigned int)a1,
                            native_info, (int)a3 | (poll ? WNOHANG : 0), a4, 0));
                        if (started && (long)a0 == -EINTR) user_sig.syscall_unstarted = false;
                        if (poll && !a0 && !scratch.si_pid) {
                            started = true;
                            a0 = user_ptrace_wait_pause(generation);
                            continue;
                        }
                        a0 = user_ptrace_waitid((long)a0, native_info, a3);
                        if (poll && !a0 && a2)
                            a0 = uapi_extra_copy(&scratch, to_ptr(a2), sizeof(scratch), true);
                    } while ((long)a0 == USER_PTRACE_WAIT_AGAIN);
                    break;
                }
                case 96: // set_tid_address
                    thread->child_cleartid = to_ptr(a0);
                    a0 = thread->process_thread
                        ? syscall(SYS_set_tid_address, a0) : rvvm_sys_gettid();
                    break;
                case 98: // futex
                    a0 = rvvm_sys_futex(to_ptr(a0), a1, a2, a3, to_ptr(a4), a5);
                    break;
                case 99: // set_robust_list
                    // Guest TIDs are host TIDs; the LP64 robust-list ABI is shared.
                    // Kernel cleanup also covers SIGKILL and exec, not just SYS_exit.
                    a0 = errno_ret(syscall(SYS_set_robust_list, to_ptr(a0), a1));
                    break;
                case 100: // get_robust_list
                    a0 = errno_ret(syscall(SYS_get_robust_list, a0, to_ptr(a1), to_ptr(a2)));
                    break;
                case 101: // nanosleep
                    // TODO: Struct conversion
                    a0 = errno_ret(USER_SYSCALL(SYS_nanosleep, a0, a1, 0, 0, 0, 0));
                    break;
                case 102: // getitimer: RV64 and the supported hosts use 64-bit timeval
                    BUILD_ASSERT(sizeof(struct itimerval) == 32);
                    a0 = errno_ret(syscall(SYS_getitimer, (int)a0, to_ptr(a1)));
                    break;
                case 103: // setitimer
                    rvvm_info("sys_setitimer(%lx, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(setitimer(a0, to_ptr(a1), to_ptr(a2)));
                    break;
                case 112: // clock_settime: let the kernel validate pointers and permissions
                    BUILD_ASSERT(sizeof(struct timespec) == 16);
                    a0 = errno_ret(syscall(SYS_clock_settime, (int)a0, to_ptr(a1)));
                    break;
                case 113: // clock_gettime
                    // TODO: Struct conversion!
                    rvvm_info("sys_clock_gettime(%lx, %lx)", a0, a1);
                    a0 = errno_ret(clock_gettime(a0, to_ptr(a1)));
                    break;
                case 114: // clock_getres
                    rvvm_info("sys_clock_getres(%lx, %lx)", a0, a1);
                    a0 = errno_ret(clock_getres(a0, to_ptr(a1)));
                    break;
#ifdef __linux__
                case 115: // clock_nanosleep
                    // TODO: struct conversion?
                    rvvm_info("sys_clock_nanosleep(%lx, %lx, %lx, %lx)", a0, a1, a2, a3);
                    a0 = errno_ret(USER_SYSCALL(SYS_clock_nanosleep, a0, a1, a2, a3, 0, 0));
                    break;
#endif
                case 118: // sched_setparam
                case 119: // sched_setscheduler
                case 120: // sched_getscheduler
                case 121: // sched_getparam
                case 125: // sched_get_priority_max
                case 126: // sched_get_priority_min
                case 127: // sched_rr_get_interval
                    a0 = user_posix_scheduler(a7, a0, a1, a2);
                    break;
                case 122: // sched_setaffinity
#ifdef __linux__
                    a0 = errno_ret(syscall(SYS_sched_setaffinity, a0, a1, to_ptr(a2)));
#else
                    a0 = 0;
#endif
                    break;
                case 123: { // sched_getaffinity - pass through the host affinity mask,
                    // guest allocators (f.e. Zig SmpAllocator) size per-CPU arenas by it
#ifdef __linux__
                    // The raw ABI returns bytes, unlike libc's zero-on-success wrapper.
                    // Let Linux validate the PID, buffer size, and guest pointer.
                    a0 = errno_ret(syscall(SYS_sched_getaffinity, a0, a1, to_ptr(a2)));
#else
                    if (a2 && a1) {
                        memset(to_ptr(a2), 0, a1);
                        cpu_set_t host_mask;
                        CPU_ZERO(&host_mask);
                        if (!sched_getaffinity(0, sizeof(host_mask), &host_mask)) {
                            size_t copy_len = sizeof(host_mask) < a1 ? sizeof(host_mask) : a1;
                            memcpy(to_ptr(a2), &host_mask, copy_len);
                        } else {
                            *(uint8_t*)to_ptr(a2) = 1;
                        }
                    }
                    // Syscall ABI: return the amount of bytes written into the mask
                    a0 = (a1 >= sizeof(unsigned long)) ? sizeof(unsigned long) : a1;
#endif
                    break;
                }
                case 124: // sched_yield
                    sleep_ms(0);
                    a0 = 0;
                    break;
                case 129: // kill
                    rvvm_debug("sys_kill(%lx, %lx)", a0, a1);
                    a0 = errno_ret(kill(a0, a1));
                    break;
#ifdef __linux__
                case 130: // tkill
                    rvvm_debug("sys_tkill(%lx, %lx)", a0, a1);
                    a0 = errno_ret(syscall(SYS_tkill, (int)a0, (int)a1));
                    break;
                case 131: // tgkill
                    rvvm_debug("sys_tgkill(%lx, %lx, %ld)", a0, a1, a2);
                    a0 = errno_ret(tgkill(a0, a1, a2));
                    break;
#endif
                case 133: // rt_sigsuspend
                    a0 = errno_ret(USER_SYSCALL(SYS_rt_sigsuspend, a0, a1, 0, 0, 0, 0));
                    break;
                case 134: // rt_sigaction
                    a0 = user_rt_sigaction(a0, to_ptr(a1), to_ptr(a2), a3);
                    break;
                case 135: // rt_sigprocmask
                    a0 = user_rt_sigprocmask(a0, to_ptr(a1), to_ptr(a2), a3);
                    break;
                case 136: // rt_sigpending
                    a0 = user_rt_sigpending(to_ptr(a0), a1);
                    break;
                case 137: { // rt_sigtimedwait
                    a0 = user_rt_sigtimedwait(to_ptr(a0), to_ptr(a1), to_ptr(a2), a3);
                    break;
                }
                case 139: // rt_sigreturn restores a0 and PC itself
                    user_rt_sigreturn(cpu);
                    user_ptrace_syscall_end(cpu);
                    continue;
                case 138: // rt_sigqueueinfo
                    a0 = user_sigqueue(a0, 0, a1, to_ptr(a2), false);
                    break;
                case 240: // rt_tgsigqueueinfo
                    a0 = user_sigqueue(a0, a1, a2, to_ptr(a3), true);
                    break;
                case 140: // setpriority
                    a0 = errno_ret(syscall(SYS_setpriority, (int)a0, (int)a1, (int)a2));
                    break;
                case 141: // getpriority: libc converts the kernel's 20-nice result
                    a0 = errno_ret(syscall(SYS_getpriority, (int)a0, (int)a1));
                    break;
                case 143: // setregid
                    if (!fake_root) a0 = errno_ret(syscall(SYS_setregid, (uint32_t)a0, (uint32_t)a1));
                    else {
                        if ((uint32_t)a1 != UINT32_MAX) fake_gid = a1;
                        else if ((uint32_t)a0 != UINT32_MAX) fake_gid = a0;
                        a0 = 0;
                    }
                    break;
                case 145: // setreuid
                    if (!fake_root) a0 = errno_ret(syscall(SYS_setreuid, (uint32_t)a0, (uint32_t)a1));
                    else {
                        if ((uint32_t)a1 != UINT32_MAX) fake_uid = a1;
                        else if ((uint32_t)a0 != UINT32_MAX) fake_uid = a0;
                        a0 = 0;
                    }
                    break;
                case 144: // setgid
                    a0 = rvvm_sys_setgid(a0);
                    break;
                case 146: // setuid
                    a0 = rvvm_sys_setuid(a0);
                    break;
                case 147: // setresuid - semi stub
#ifdef __linux__
                    if (!fake_root) {
                        a0 = errno_ret(syscall(SYS_setresuid, a0, a1, a2));
                        break;
                    }
#endif
                    a0 = rvvm_sys_setuid(a0);
                    break;
                case 148: // getresuid - semi stub
                    a0 = rvvm_sys_getresuid(to_ptr(a0), to_ptr(a1), to_ptr(a2));
                    break;
                case 149: // setresgid - semi stub
#ifdef __linux__
                    if (!fake_root) {
                        a0 = errno_ret(syscall(SYS_setresgid, a0, a1, a2));
                        break;
                    }
#endif
                    a0 = rvvm_sys_setgid(a0);
                    break;
                case 150: // getresgid - semi stub
                    a0 = rvvm_sys_getresgid(to_ptr(a0), to_ptr(a1), to_ptr(a2));
                    break;
                case 151: // setfsuid - ignore
                    a0 = rvvm_sys_getuid();
                    break;
                case 152: // setfsgid - ignore
                    a0 = rvvm_sys_getgid();
                    break;
                case 153: // times
                    // TODO: Struct conversion!
                    rvvm_info("sys_times(%lx)", a0);
                    a0 = errno_ret(times(to_ptr(a0)));
                    break;
#ifdef __linux__
                case 154: // setpgid
                    rvvm_info("sys_setpgid(%lx, %lx)", a0, a1);
                    a0 = errno_ret(setpgid(a0, a1));
                    break;
                case 155: // getpgid
                    rvvm_info("sys_getpgid(%lx)", a0);
                    a0 = errno_ret(getpgid(a0));
                    break;
#endif
                case 156: // getsid
                    a0 = errno_ret(syscall(SYS_getsid, (int)a0));
                    break;
                case 161: // sethostname
                    a0 = errno_ret(syscall(SYS_sethostname, to_ptr(a0), a1));
                    break;
                case 157: // setsid
                    rvvm_info("sys_setsid()");
                    a0 = errno_ret(setsid());
                    break;
                case 158: // getgroups
                    rvvm_info("sys_getgroups(%lx, %lx)", a0, a1);
                    a0 = errno_ret(getgroups(a0, to_ptr(a1)));
                    break;
                case 159: // setgroups
                    if (fake_root) {
                        a0 = 0;
                    } else {
                        a0 = errno_ret(syscall(SYS_setgroups, a0, to_ptr(a1)));
                    }
                    break;
                case 160: // newuname
                    rvvm_info("sys_newuname(%lx)", a0);
                    {
                        // Preserve the emulated machine/version identity, but
                        // hostname changes belong to the real UTS namespace.
                        struct uapi_new_utsname host;
                        struct uapi_new_utsname name = {
                            .sysname = "Linux",
                            .release = "6.6.6",
                            .version = "RVVM " RVVM_VERSION,
                            .machine = "riscv64",
                        };
                        long ret = errno_ret(syscall(SYS_uname, &host));
                        if (!ret) {
                            memcpy(name.nodename, host.nodename, sizeof(name.nodename));
                            memcpy(name.domainname, host.domainname, sizeof(name.domainname));
                            ret = uapi_extra_copy(&name, to_ptr(a0), sizeof(name), true);
                        }
                        a0 = ret;
                    }
                    break;
                case 163: // getrlimit
                    a0 = errno_ret(syscall(SYS_prlimit64, 0, a0, NULL, to_ptr(a1)));
                    break;
                case 164: // setrlimit
                    a0 = errno_ret(syscall(SYS_prlimit64, 0, a0, to_ptr(a1), NULL));
                    break;
                case 165: // getrusage
                    rvvm_info("sys_getrusage(%lx, %lx)", a0, a1);
                    a0 = errno_ret(getrusage(a0, to_ptr(a1)));
                    break;
                case 166: // umask
                    rvvm_info("sys_umask(%lx)", a0);
                    a0 = errno_ret(umask(a0));
                    break;
                case 167: // prctl
                    a0 = uapi_extra_prctl(a0, a1, a2, a3, a4);
                    break;
#ifdef __linux__
                case 168: // getcpu
                    a0 = errno_ret(syscall(SYS_getcpu, to_ptr(a0), to_ptr(a1), to_ptr(a2)));
                    break;
#endif
                case 172: // getpid
                    a0 = errno_ret(getpid());
                    break;
                case 173: // getppid
                    a0 = errno_ret(getppid());
                    break;
                case 174: // getuid
                    a0 = rvvm_sys_getuid();
                    break;
                case 175: // geteuid
                    a0 = fake_root ? fake_uid : geteuid();
                    break;
                case 176: // getgid
                    a0 = rvvm_sys_getgid();
                    break;
                case 177: // getegid
                    a0 = fake_root ? fake_gid : getegid();
                    break;
                case 178: // gettid
                    a0 = rvvm_sys_gettid();
                    break;
#ifdef __linux__
                case 179: // sysinfo
                    // TODO: struct conversion(?)
                    rvvm_info("sys_sysinfo(%lx)", a0);
                    a0 = errno_ret(sysinfo(to_ptr(a0)));
                    break;
#endif
                case 194: // shmget
                    rvvm_info("sys_shmget(%lx, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(shmget(a0, a1, a2));
                    break;
                case 195: // shmctl
                    // TODO: struct conversion?
                    rvvm_info("sys_shmctl(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(shmctl(a0, a1, to_ptr(a2)));
                    break;
                case 196: // shmat
                    rvvm_info("sys_shmat(%ld, %lx, %lx)", a0, a1, a2);
                    user_fd_lock();
                    a0 = errno_ret((size_t)user_vma_shmat(a0, to_ptr(a1), a2));
                    user_fd_unlock();
                    break;
                case 197: // shmdt
                    rvvm_info("sys_shmdt(%lx)", a0);
                    user_fd_lock();
                    a0 = errno_ret(user_vma_shmdt(to_ptr(a0)));
                    user_fd_unlock();
                    break;
                case 198: // socket
                    rvvm_info("sys_socket(%lx, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(socket(a0, a1, a2));
                    break;
                case 199: // socketpair
                    rvvm_info("sys_socketpair(%lx, %lx, %lx, %lx)", a0, a1, a2, a3);
                    a0 = errno_ret(socketpair(a0, a1, a2, to_ptr(a3)));
                    break;
                case 200: // bind
                    // TODO struct conversion
                    rvvm_info("sys_bind(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(bind(a0, to_ptr(a1), a2));
                    break;
                case 201: // listen
                    rvvm_info("sys_listen(%ld, %lx)", a0, a1);
                    a0 = errno_ret(listen(a0, a1));
                    break;
                case 202: // accept
                    // TODO: struct conversion(?)
                    rvvm_info("sys_accept(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(USER_SYSCALL(SYS_accept, a0, a1, a2, 0, 0, 0));
                    break;
                case 203: // connect
                    // TODO: struct conversion(?)
                    rvvm_info("sys_connect(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(USER_SYSCALL(SYS_connect, a0, a1, a2, 0, 0, 0));
                    break;
                case 204: // getsockname
                    // TODO: struct conversion(?)
                    rvvm_info("sys_getsockname(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(getsockname(a0, to_ptr(a1), to_ptr(a2)));
                    break;
                case 205: // getpeername
                    // TODO: struct conversion(?)
                    rvvm_info("sys_getpeername(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(getpeername(a0, to_ptr(a1), to_ptr(a2)));
                    break;
                case 206: // sendto
                    // TODO: struct conversion(?)
                    rvvm_info("sys_sendto(%ld, %lx, %lx, %lx, %lx, %lx)", a0, a1, a2, a3, a4, a5);
                    a0 = errno_ret(USER_SYSCALL(SYS_sendto, a0, a1, a2, a3, a4, a5));
                    break;
                case 207: // recvfrom
                    // TODO: struct conversion(?)
                    rvvm_info("sys_recvfrom(%ld, %lx, %lx, %lx, %lx, %lx)", a0, a1, a2, a3, a4, a5);
                    a0 = errno_ret(USER_SYSCALL(SYS_recvfrom, a0, a1, a2, a3, a4, a5));
                    break;
                case 208: // setsockopt
                    rvvm_info("sys_setsockopt(%ld, %lx, %lx, %lx, %lx)", a0, a1, a2, a3, a4);
                    a0 = errno_ret(setsockopt(a0, a1, a2, to_ptr(a3), a4));
                    break;
                case 209: // getsockopt
                    rvvm_info("sys_getsockopt(%ld, %lx, %lx, %lx, %lx)", a0, a1, a2, a3, a4);
                    a0 = errno_ret(getsockopt(a0, a1, a2, to_ptr(a3), to_ptr(a4)));
                    break;
                case 210: // shutdown
                    rvvm_info("sys_shutdown(%ld, %lx)", a0, a1);
                    a0 = errno_ret(shutdown(a0, a1));
                    break;
                case 211: // sendmsg
                    // TODO: struct conversion(?)
                    rvvm_info("sys_sendmsg(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(USER_SYSCALL(SYS_sendmsg, a0, a1, a2, 0, 0, 0));
                    break;
                case 212: // recvmsg
                    // TODO: struct conversion(?)
                    rvvm_info("sys_recvmsg(%ld, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(USER_SYSCALL(SYS_recvmsg, a0, a1, a2, 0, 0, 0));
                    break;
                case 214: // brk
                    rvvm_info("sys_brk(%lx)", a0);
                    a0 = (size_t)rvvm_sys_brk(to_ptr(a0));
                    break;
                case 215: // munmap
                    rvvm_info("sys_munmap(%lx, %lx)", a0, a1);
                    a0 = rvvm_sys_munmap(to_ptr(a0), a1);
                    break;
#ifdef __linux__
                case 216: // mremap
                    rvvm_info("sys_mremap(%lx, %lx, %lx, %lx, %lx)", a0, a1, a2, a3, a4);
#ifdef USER_FAULT_META
                    a0 = user_mremap(a0, a1, a2, a3, a4);
#else
                    user_fd_lock();
                    a0 = errno_ret((size_t)user_vma_remap(to_ptr(a0), a1, a2, a3, to_ptr(a4)));
                    user_fd_unlock();
#endif
                    break;
#endif
                case 220: // clone
                    rvvm_info("sys_clone(%lx, %lx, %lx, %lx, %lx)", a0, a1, a2, a3, a4);
                    if (getenv("RVVM_USER_NO_THREADS")) {
                        // Experimental knob: force the guest single-threaded
                        a0 = -UAPI_EAGAIN;
                        break;
                    }
                    a0 = rvvm_sys_clone(thread, a0, a1, to_ptr(a2), a3, to_ptr(a4));
                    break;
                case 221: { // execve
                    rvvm_info("sys_execve(%lx, %lx, %lx)", a0, a1, a2);
                    /* With binfmt registered, the kernel handles scripts and
                     * redispatches RISC-V ELF files to this interpreter. */
                    if (user_binfmt_executable || getenv("RVVM_USER_BINFMT")) {
                        a0 = user_execve(to_str(a0), to_ptr(a1), to_ptr(a2));
                        break;
                    }
                    if (access(wrap_path(path_buf, to_str(a0)), F_OK)) {
                        a0 = -ENOENT;
                        break;
                    }
                    char** orig_argv = to_ptr(a1);
                    char* new_argv[256] = {"/proc/self/exe", "-user", 0};
                    for (size_t i=2; i<255 && orig_argv[i - 2]; ++i) new_argv[i] = orig_argv[i - 2];
                    new_argv[2] = to_ptr(a0);
                    a0 = errno_ret(USER_SYSCALL(SYS_execve, "/proc/self/exe", new_argv, a2, 0, 0, 0));
                    break;
                }
                case 222: // mmap
                    a0 = rvvm_sys_mmap(to_ptr(a0), a1, a2, a3, a4, a5);
                    break;
                case 223: // fadvise64: raw syscall returns -1/errno, unlike posix_fadvise()
#ifdef __linux__
                    a0 = errno_ret(USER_SYSCALL(SYS_fadvise64, a0, a1, a2, a3, 0, 0));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 226: // mprotect
                    rvvm_info("sys_mprotect(%lx, %lx, %x)", a0, a1, a2);
#ifdef USER_FAULT_META
                    spin_lock(&mmap_lock);
                    {
                        rvvm_addr_t ret = errno_ret(mprotect(to_ptr(a0), a1, rvvm_sys_prot(a2)));
                        if (!ret) user_exec_update(a0, a1, a2 & UAPI_PROT_EXEC);
                        a0 = ret;
                    }
                    spin_unlock(&mmap_lock);
#else
                    a0 = errno_ret(mprotect(to_ptr(a0), a1, a2));
#endif
                    break;
#ifdef __linux__
                case 232: // mincore: host mapping residency, one byte per host page
                    a0 = errno_ret(syscall(SYS_mincore, to_ptr(a0), a1, to_ptr(a2)));
                    break;
                case 233: // madvise
                    rvvm_info("sys_madvise(%lx, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(madvise(to_ptr(a0), a1, a2));
                    break;
                case 242: // accept4
                    // TODO: struct conversion(?)
                    rvvm_info("sys_accept4(%ld, %lx, %lx, %lx)", a0, a1, a2, a3);
                    a0 = errno_ret(USER_SYSCALL(SYS_accept4, a0, a1, a2, a3, 0, 0));
                    break;
#endif
                case 258: // riscv_hwprobe
                    a0 = user_cpu_hwprobe(to_ptr(a0), a1, a2, to_ptr(a3), (unsigned int)a4);
                    break;
                case 259: // riscv_flush_icache
                    //rvvm_warn("riscv_flush_icache(%lx, %lx, %lx)", a0, a1, a2);
                    rvvm_flush_icache(userland, a0, a1 - a0);
                    if (getenv("RVVM_JITDUMP") && a1 > a0) {
                        static int jitdump_seq = 0;
                        char dump_name[128];
                        snprintf(dump_name, sizeof(dump_name), "jitdump_%03d_0x%lx.bin", jitdump_seq++, (unsigned long)a0);
                        user_fd_lock();
                        int dump_fd = open(dump_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        if (dump_fd >= 0) {
                            const char* dump_src = to_ptr(a0);
                            size_t dump_left = a1 - a0;
                            while (dump_left) {
                                ssize_t dw = write(dump_fd, dump_src, dump_left);
                                if (dw <= 0) break;
                                dump_src += dw; dump_left -= dw;
                            }
                            close(dump_fd);
                        }
                        user_fd_unlock();
                    }
                    a0 = 0;
                    break;
                case 260: { // wait4
                    long queued;
                    pid_t selector = a0;
                    bool started = false;
                    do {
                        bool tracing = user_ptrace_events_tracing();
                        bool poll = tracing && !(a2 & WNOHANG);
                        uint32_t generation = poll ? user_ptrace_events_generation() : 0;
                        int scratch;
                        int* status = !a1 && tracing ? &scratch : to_ptr(a1);
                        if (user_ptrace_wait_ready(selector, status, a2, to_ptr(a3), &queued)) { a0 = queued; break; }
                        a0 = errno_ret(USER_SYSCALL(SYS_wait4, selector, status,
                            a2 | (poll ? WNOHANG : 0), a3, 0, 0));
                        if (started && (long)a0 == -EINTR) user_sig.syscall_unstarted = false;
                        if (poll && !a0) {
                            started = true;
                            a0 = user_ptrace_wait_pause(generation);
                            continue;
                        }
                        a0 = user_ptrace_wait((long)a0, status);
                    } while ((long)a0 == USER_PTRACE_WAIT_AGAIN);
                    break;
                }
                case 261: // prlimit64: Linux rlimit64 is two uint64_t fields
                    a0 = errno_ret(syscall(SYS_prlimit64, a0, a1, to_ptr(a2), to_ptr(a3)));
                    break;
#ifdef __linux__
                case 269: // sendmmsg
                    // TODO: Struct conversion
                    rvvm_info("sys_sendmmsg(%ld, %lx, %lx, %lx)", a0, a1, a2, a3);
                    a0 = errno_ret(USER_SYSCALL(SYS_sendmmsg, a0, a1, a2, a3, 0, 0));
                    break;
                case 270: // process_vm_readv: Linux LP64 iovec and address-space identity
                    a0 = errno_ret(USER_SYSCALL(SYS_process_vm_readv, a0, a1, a2, a3, a4, a5));
                    break;
                case 271: // process_vm_writev
                    a0 = errno_ret(USER_SYSCALL(SYS_process_vm_writev, a0, a1, a2, a3, a4, a5));
                    break;
#endif
                case 276: // renameat2
                    rvvm_info("sys_renameat2(%ld, %s, %ld, %s, %lx)", a0, to_str(a1), a2, to_str(a3), a4);
#ifdef __linux__
                    a0 = errno_ret(syscall(SYS_renameat2, a0, wrap_path(path_buf, to_str(a1)),
                                          a2, wrap_path(path_buf1, to_str(a3)), a4));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 277: // Guest filters cannot safely constrain the emulator's host syscalls.
                    a0 = -UAPI_ENOSYS;
                    break;
                case 424: // pidfd_send_signal: LP64 Linux siginfo ABI
                    a0 = errno_ret(syscall(SYS_pidfd_send_signal, (int)a0, (int)a1, to_ptr(a2), (unsigned int)a3));
                    break;
                case 434: // pidfd_open: guest process IDs are host process IDs
                    a0 = errno_ret(syscall(SYS_pidfd_open, (int)a0, (unsigned int)a1));
                    break;
                case 278: // getrandom
#ifdef __linux__
                    a0 = errno_ret(USER_SYSCALL(SYS_getrandom, a0, a1, a2, 0, 0, 0));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
#ifdef __linux__
                case 279: // memfd_create
                    rvvm_info("sys_memfd_create(%s, %lx)", to_str(a0), a1);
                    a0 = errno_ret(memfd_create(to_str(a0), a1));
                    break;
                case 280: // bpf: fixed-width UAPI, programs run in the host kernel
                    a0 = user_bpf((unsigned int)a0, to_ptr(a1), (unsigned int)a2);
                    break;
                case 291: // statx
                    // TODO: Struct conversion!
                    rvvm_info("sys_statx(%ld, %s, %lx, %lx, %lx)", a0, to_str(a1), a2, a3, a4);
                    a0 = errno_ret(statx(a0, wrap_path(path_buf, to_str(a1)), a2, a3, to_ptr(a4)));
                    break;
#endif
                case 425: // io_uring_setup - guest event loop falls back to poll on ENOSYS
                    a0 = -UAPI_ENOSYS;
                    break;
                case 435: // clone3
                    // FUCK THIS FUCKING SYSCALL FOR NOW
                    a0 = -UAPI_ENOSYS;
                    break;
                case 436: // close_range
                    a0 = user_fd_close_range(a0, a1, a2);
                    break;
                case 439: // faccessat2
                    rvvm_info("sys_faccessat2(%ld, %s, %lx, %lx)", a0, to_str(a1), a2, a3);
                    a0 = errno_ret(faccessat(a0, wrap_path(path_buf, to_str(a1)), a2, a3));
                    break;
                case 437: // openat2
#if defined(__linux__) && defined(SYS_openat2)
                    a0 = rvvm_sys_openat2((int)a0, to_str(a1), to_ptr(a2), a3);
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                case 452: // fchmodat2
#if defined(__linux__) && defined(SYS_fchmodat2)
                    a0 = errno_ret(syscall(SYS_fchmodat2, (int)a0,
                        wrap_path(path_buf, to_str(a1)), (unsigned int)a2,
                        uapi_translate_flags(a3, uapi_path_flags,
                                             STATIC_ARRAY_SIZE(uapi_path_flags), true)));
#else
                    a0 = -UAPI_ENOSYS;
#endif
                    break;
                default:
#ifndef __riscv
                    rvvm_error("Unknown syscall %ld!", a7);
                    a0 = -UAPI_ENOSYS;
#else
                    a0 = errno_ret(syscall(a7, a0, a1, a2, a3, a4, a5));
#endif
                    break;
            }
            if (vm_mutation) user_vm_leave();
            }
            if ((int64_t)a0 < 0) {
                //rvvm_warn("Syscall %ld failed: %ld", a7, a0);
            }
            rvvm_info("  nr=%ld -> %lx", a7, a0);
            if ((int64_t)a0 == -EINTR && user_ptrace_interrupted()) continue;
            if (user_ptrace_interrupt_syscall(cpu, a7, (int64_t)a0)) continue;
            if ((int64_t)a0 == -EINTR && user_sig.pending && user_sig.syscall_unstarted) continue;
            if ((int64_t)a0 == -EINTR && user_sig.pending && user_restart_syscall(cpu, a7)) {
                spin_lock(&user_action_lock);
                bool restart = user_actions[user_sig.pending].flags & SA_RESTART;
                spin_unlock(&user_action_lock);
                if (restart) continue; // Preserve original syscall PC and arguments in the frame.
            }
            rvvm_write_cpu_reg(cpu, RVVM_REGID_X0 + 10, a0);
            rvvm_write_cpu_reg(cpu, RVVM_REGID_PC, rvvm_read_cpu_reg(cpu, RVVM_REGID_PC) + 4);
            user_ptrace_syscall_end(cpu);
        } else {
            if (cause == 3 && user_ptrace_break(cpu)) continue;
            // Boom!
#ifdef USER_FAULT_META
            int signo = 0, code = 0;
            uintptr_t addr = rvvm_read_cpu_reg(cpu, RVVM_REGID_TVAL);
            switch (cause) {
                case 0: case 4: case 6: signo = SIGBUS; code = BUS_ADRALN; break;
                case 1: case 5: case 7: case 12: case 13: case 15:
                    signo = SIGSEGV; code = SEGV_MAPERR; break;
                case 2: signo = SIGILL; code = ILL_ILLOPC;
                    addr = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC); break;
                case 3: signo = SIGTRAP; code = TRAP_BRKPT;
                    addr = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC); break;
            }
            if (signo) {
                if (signo == SIGSEGV) {
                    unsigned char resident;
                    if (!mincore((void*)(addr & ~(uintptr_t)4095), 4096, &resident)) code = SEGV_ACCERR;
                }
                user_defer_pending();
                memset(&user_sig.info, 0, sizeof(user_sig.info));
                user_sig.info.si_signo = signo; user_sig.info.si_code = code;
                user_sig.info.si_addr = (void*)addr;
                user_sig.pending = signo; user_sig.synchronous = true;
                user_ptrace_guest_fault();
                riscv_jit_discard(cpu);
                continue;
            }
#endif
            rvvm_warn("Exception %lx (tval %lx) at PC %lx, SP %lx",
                      rvvm_read_cpu_reg(cpu, RVVM_REGID_CAUSE),
                      rvvm_read_cpu_reg(cpu, RVVM_REGID_TVAL),
                      rvvm_read_cpu_reg(cpu, RVVM_REGID_PC),
                      rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 2));
            for (uint32_t i=0; i<32; ++i) {
                rvvm_warn("X%d: %016lx", i, rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + i));
            }

            rvvm_addr_t pc = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC);
            rvvm_addr_t pc_al = EVAL_MAX(pc - 16, pc & ~0xFFF);

            rvvm_warn("Backtrace:");
            void **fp = NULL;
            void** next_fp = (void*)rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 8);
            do {
                rvvm_warn(" PC %lx", pc);
                if (pc >= (size_t)elf.base && pc < (size_t)elf.base + elf.buf_size) {
                    rvvm_warn("  @ Main binary, reloc: %lx", pc - (size_t)elf.base);
                }
                if (pc >= (size_t)interp.base && pc < (size_t)interp.base + interp.buf_size) {
                    rvvm_warn("  @ Interpreter, reloc: %lx)", pc - (size_t)interp.base);
                }
                if (next_fp <= fp) break;
                if (!proc_mem_readable(fp, 8)) {
                    rvvm_warn(" * * * Frame pointer points to inaccessible memory!");
                    break;
                }
                next_fp = fp[-2];
                rvvm_warn("Next FP: %p", next_fp);
                pc = (size_t)fp[-1];
                fp = next_fp;
            } while (true);

            if (proc_mem_readable((void*)pc_al, 32)) {
                rvvm_warn("Instruction bytes around PC:");
                for (size_t i=0; i<32; ++i) {
                    printf("%02x", *(uint8_t*)(pc_al + i));
                }
                printf("\n");
                for (size_t i=0; i<32; ++i) {
                    printf("%s", (pc_al + i == pc) ? "^ " : "  ");
                }
                printf("\n");
            } else {
                rvvm_warn(" * * * PC points to inaccessible memory!");
            }

            /* A fault in any guest thread must fail the process, not return
             * through jump_start() and report a successful command. */
            fflush(stdout);
            _Exit(EXIT_FAILURE);
        }
    }

    uint64_t exit_mask = UINT64_MAX;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &exit_mask, NULL, 8);
    user_sig.cpu = NULL;
    current_user_hart = NULL;
    user_sig.pending = 0;
    if (user_vm_pi_owned) atomic_sub_uint32(&user_vm_pi_users, user_vm_pi_owned);
    bool process_thread = thread->process_thread;
    user_ptrace_destroy();
    user_fd_table_leave();
    user_signal_process_release(thread->signals);
    user_signal_process = NULL;
    rvvm_free_user_thread(cpu);
    rvvm_user_thread_put(thread);
    uint64_t lifetime = atomic_load_uint64(&user_thread_lifetime);
    while (!atomic_cas_uint64_loop(&user_thread_lifetime, &lifetime,
        ((uint64_t)(uint32_t)exit_status << 32) | ((uint32_t)lifetime - 1))) {}
    user_reap_notify();
    // The initial/fork-surviving host thread must retain guest SYS_exit status.
    if (process_thread) syscall(SYS_exit, exit_status);
    return NULL;
}

// Jump into _start after setting up the context
static void jump_start(void* entry, void* stack_top)
{
#ifdef RVVM_USER_TEST_RISCV
    register size_t a0 __asm__("a0") = (size_t) entry;
    register size_t sp __asm__("sp") = (size_t) stack_top;

    __asm__ __volatile__(
        "jr a0;"
        :
        : "r" (a0), "r" (sp)
        :
    );
#elif defined(RVVM_USER_TEST_X86)
    register size_t rax __asm__("rax") = (size_t) entry;
    register size_t rsp __asm__("rsp") = (size_t) stack_top;
    register size_t rdx __asm__("rdx") = (size_t) &exit; // Why do we even need to pass this?

    __asm__ __volatile__(
        "jmp *%0;"
        :
        : "r" (rax), "r" (rsp), "r" (rdx)
        :
    );
#else
    userland = rvvm_create_userland("rv64");
    rvvm_user_thread_t* thread = safe_new_obj(rvvm_user_thread_t);
    thread->cpu = rvvm_create_user_thread(userland);
    thread->refs = 1;
    thread->process_thread = true;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, NULL, &thread->signal_mask, 8);

    rvvm_write_cpu_reg(thread->cpu, RVVM_REGID_X0 + 2, (size_t)stack_top);
    rvvm_write_cpu_reg(thread->cpu, RVVM_REGID_PC,     (size_t)entry);

    rvvm_user_thread_wrap(thread);

    rvvm_free_machine(userland);
#endif
}

// Describes the executable to be ran
typedef struct {
    // Self explanatory
    size_t argc;
    char** argv;
    char** envp;
    const char* executable;

    size_t base;         // Main ELF base address (relocation)
    size_t entry;        // Main ELF entry point
    size_t interp_base;  // ELF interpreter (aka linker usually) base address
    size_t interp_entry; // ELF interpreter entry point
    size_t phdr;         // Address of ELF PHDR section
    size_t phnum;        // Number of PHDRs
} exec_desc_t;

/*
 * Guest process stack setup routines
 */

static void* stack_put_mem(uint8_t* stack, const void* mem, size_t len)
{
    stack -= len;
    memcpy(stack, mem, len);
    return stack;
}

static void* stack_put_size(void* stack, uapi_size_t val)
{
    return stack_put_mem(stack, &val, sizeof(val));
}

static void* stack_put_str(void* stack, const char* str)
{
    return stack_put_mem(stack, str, rvvm_strlen(str) + 1);
}

#define UAPI_AT_NULL           0
#define UAPI_AT_IGNORE         1
#define UAPI_AT_EXECFD         2
#define UAPI_AT_PHDR           3
#define UAPI_AT_PHENT          4
#define UAPI_AT_PHNUM          5
#define UAPI_AT_PAGESZ         6
#define UAPI_AT_BASE           7
#define UAPI_AT_FLAGS          8
#define UAPI_AT_ENTRY          9
#define UAPI_AT_NOTELF        10
#define UAPI_AT_UID           11
#define UAPI_AT_EUID          12
#define UAPI_AT_GID           13
#define UAPI_AT_EGID          14
#define UAPI_AT_PLATFORM      15
#define UAPI_AT_HWCAP         16
#define UAPI_AT_CLKTCK        17
#define UAPI_AT_SECURE        23
#define UAPI_AT_BASE_PLATFORM 24
#define UAPI_AT_RANDOM        25
#define UAPI_AT_EXECFN        31
#define UAPI_AT_SYSINFO_EHDR  33 // vDSO location; RISC-V specific!

static char* rvvm_user_init_stack(void* stack, exec_desc_t* desc)
{
    /*
     * Stack layout (upside down):
     * 1. argc (guest size_t)
     * 2. string pointers: argv, 0, envp, 0
     * 3. auxv
     * 4. padding
     * 5. random bytes (16)
     * 6. string data: argv, envp
     * 7. string data: execfn
     * 8. null (guest size_t)
     */

    // 8. null
    stack = stack_put_size(stack, 0);

    // 7. string data: execfn
    stack = stack_put_str(stack, desc->executable);
    char* execfn = stack;

    // 6. string data: argv, envp
    size_t envc = 0;
    while (desc->envp[envc]) envc++;

    size_t string_num = desc->argc + envc + 2;
    uapi_size_t* string_ptrs = safe_new_arr(uapi_size_t, string_num);

    for (size_t i = envc; i--;) {
        stack = stack_put_str(stack, desc->envp[i]);
        string_ptrs[desc->argc + 1 + i] = (size_t)stack;
    }

    for (size_t i = desc->argc; i--;) {
        stack = stack_put_str(stack, desc->argv[i]);
        string_ptrs[i] = (size_t)stack;
    }

    // 5. random bytes
    char rng_buf[16] = {0};
    rvvm_randombytes(rng_buf, sizeof(rng_buf));
    stack = stack_put_mem(stack, rng_buf, sizeof(rng_buf));
    char* random_bytes = stack;

    // 4. align to 16 bytes
    stack = (char*)align_size_down((size_t)stack, 16);

    // 3. auxv, then null
    uapi_size_t auxv[] = {
        // TODO: UAPI_AT_EXECFD
        UAPI_AT_PHDR,          desc->phdr,
        UAPI_AT_PHENT,         56,
        UAPI_AT_PHNUM,         desc->phnum,
        UAPI_AT_PAGESZ,        0x1000,
        UAPI_AT_BASE,          desc->interp_base,
        UAPI_AT_FLAGS,         0,
        UAPI_AT_ENTRY,         desc->entry,
        UAPI_AT_UID,           getuid(),
        UAPI_AT_EUID,          getuid(),
        UAPI_AT_GID,           getgid(),
        UAPI_AT_EGID,          getgid(),
        UAPI_AT_PLATFORM,      0,
        UAPI_AT_HWCAP,         USER_CPU_HWCAP,
        UAPI_AT_CLKTCK,        100,
        UAPI_AT_SECURE,        0,
        UAPI_AT_BASE_PLATFORM, 0,
        UAPI_AT_RANDOM,        (size_t)random_bytes,
        UAPI_AT_EXECFN,        (size_t)execfn,
        UAPI_AT_NULL,          0,
    };
    BUILD_ASSERT(sizeof(auxv) <= sizeof(user_cpu_auxv));
    memcpy(user_cpu_auxv, auxv, sizeof(auxv));
    user_cpu_auxv_size = sizeof(auxv);
    stack = stack_put_mem(stack, auxv, sizeof(auxv));

    // 2. string pointers
    stack = stack_put_mem(stack, string_ptrs, sizeof(uapi_size_t) * string_num);
    free(string_ptrs);

    // 1. argc
    stack = stack_put_size(stack, desc->argc);

    return stack;
}

#define STACK_SIZE 0x4000000

extern char** environ;

/*
static char* default_envp[] = {
    "LANG=en_US.UTF-8",
    "TERM=xterm-256color",
    "DISPLAY=:0",
    "XDG_RUNTIME_DIR=/run/user/1000",
    NULL,
};
*/

RVVM_PUBLIC int rvvm_user_linux(int argc, char** argv, char** envp);

RVVM_PUBLIC int rvvm_user_linux_binfmt(const char* executable, int argc, char** argv, char** envp)
{
    user_binfmt_executable = executable;
    return rvvm_user_linux(argc, argv, envp);
}

RVVM_PUBLIC int rvvm_user_linux(int argc, char** argv, char** envp)
{
    if (!user_vma_init(getenv("RVVM_USER_VA_BITS"))) {
        rvvm_error("RVVM_USER_VA_BITS must be 39 or 48");
        return -1;
    }
    const char* executable = user_binfmt_executable ? user_binfmt_executable : argv[0];
    char path_buf[UAPI_PATH_MAX] = {0};
    // Mock/nspawn already establishes credentials; fake root breaks ownership checks.
    const char* binfmt = getenv("RVVM_USER_BINFMT");
    if (user_binfmt_executable || (binfmt && !strcmp(binfmt, "1"))) fake_root = false;
    if (user_binfmt_executable) prefix_path = NULL;
    // Allow overriding/disabling the userland path prefix,
    // empty RVVM_USER_PREFIX passes host paths through unchanged
    const char* env_prefix = getenv("RVVM_USER_PREFIX");
    if (env_prefix) {
        prefix_path = env_prefix[0] ? env_prefix : NULL;
    }
    stacktrace_init();
    user_fault_handler_install();
    user_cpu_init();
    if (!user_exe_init(wrap_path(path_buf, executable))) {
        rvvm_error("Failed to pin guest executable %s", executable);
        return -1;
    }
    /*elf_desc_t elf = {
        .base = NULL,
    };
    elf_desc_t interp = {
        .base = NULL,
    };*/
    rvfile_t* file = rvfile_borrow_posix_fd(user_exe_fd);
    if (!file) {
        // drvfs (WSL) sometimes fails opening big files right after host-side
        // writes, retry a couple of times before giving up
        for (int retry = 0; !file && retry < 10; retry++) {
            sleep_ms(100);
            file = rvopen(wrap_path(path_buf, executable), 0);
        }
    }
    if (!file) {
        rvvm_error("Failed to open ELF file %s (errno %d)", executable, errno);
        return -1;
    }
    bool success = elf_load_file(file, &elf);
    rvclose(file);
    user_exec_handoff_close(executable);
    if (!success) {
        rvvm_error("Failed to load ELF %s (fixed VMA collision?)", executable);
        // Dump the host memory map to find what occupies the guest region
        int maps_fd = open("/proc/self/maps", O_RDONLY);
        if (maps_fd != -1) {
            char chunk[4096];
            ssize_t rd;
            while ((rd = read(maps_fd, chunk, sizeof(chunk))) > 0) {
                if (write(STDERR_FILENO, chunk, rd) != rd) break;
            }
            close(maps_fd);
        }
        return -1;
    }
    rvvm_info("Loaded ELF %s at base %lx, entry %lx,\n%ld PHDRs at %lx",
              executable, (size_t)elf.base, elf.entry, elf.phnum, elf.phdr);

    if (elf.interp_path) {
        rvvm_info("ELF interpreter at %s", elf.interp_path);
        file = rvopen(wrap_path(path_buf, elf.interp_path), 0);
        success = file && elf_load_file(file, &interp);
        rvclose(file);
        if (!success) {
            rvvm_error("Failed to load interpreter %s", elf.interp_path);
            return -1;
        }
        rvvm_info("Loaded interpreter %s at base %lx, entry %lx,\n%ld PHDRs at %lx",
                  elf.interp_path, (size_t)interp.base, interp.entry, interp.phnum, interp.phdr);
    }

    if (envp == NULL) {
        envp = environ;
    }

#ifdef USER_FAULT_META
    user_exec_elf(&elf);
    user_exec_elf(&interp);
    riscv_user_exec_check = user_exec_check;
#endif

    if (prefix_path && (!getcwd(path_buf, sizeof(path_buf)) || !path_wrapped(path_buf))) {
        if (chdir(prefix_path)) {
            rvvm_error("Failed to chdir to userland prefix %s", prefix_path);
        }
    }

    //rvvm_set_loglevel(LOG_INFO);

    exec_desc_t desc = {
        .argc = argc,
        .argv = argv,
        .envp = envp,
        .executable = executable,
        .base = (size_t)elf.base,
        .entry = elf.entry,
        .interp_base = (size_t)interp.base,
        .interp_entry = interp.entry,
        .phdr = elf.phdr,
        .phnum = elf.phnum,
    };

    // A plain anonymous stack can abut writable emulator mappings. Recursion
    // must fault before overwriting those mappings (including signal state).
    size_t stack_guard = 1024 * 1024;
    user_fd_lock();
    uint8_t* stack_mapping = user_vma_map(NULL, STACK_SIZE + 2 * stack_guard, PROT_NONE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    user_fd_unlock();
    if (stack_mapping == MAP_FAILED) return -1;
    uint8_t* stack_buffer = stack_mapping + stack_guard;
    if (mprotect(stack_buffer, STACK_SIZE, PROT_READ | PROT_WRITE)) {
        munmap(stack_mapping, STACK_SIZE + 2 * stack_guard);
        return -1;
    }
#ifdef USER_FAULT_META
    user_exec_update((uintptr_t)stack_buffer, STACK_SIZE, user_exec_stack(&elf));
#endif
    free(elf.phdr_data);
    free(interp.phdr_data);
    void* stack_top = rvvm_user_init_stack(stack_buffer + STACK_SIZE, &desc);

    rvvm_info("Stack top at %p", stack_top);

    if (elf.interp_path) {
        jump_start((void*)interp.entry, stack_top);
    } else {
        jump_start((void*)elf.entry, stack_top);
    }

    munmap(stack_mapping, STACK_SIZE + 2 * stack_guard);
    return 0;
}

#else

#include "utils.h"

RVVM_PUBLIC int rvvm_user_linux(int argc, char** argv, char** envp)
{
    UNUSED(argc); UNUSED(argv); UNUSED(envp);
    rvvm_warn("Userland emulation not available, define RVVM_USER_TEST");
    return -1;
}

#endif
