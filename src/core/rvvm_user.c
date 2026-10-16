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
#include <sys/timex.h>

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
struct user_fake_credentials { int uid, gid; };
static struct user_fake_credentials user_fake_default;
static THREAD_LOCAL struct user_fake_credentials* user_fake_current;
#define fake_uid ((user_fake_current ? user_fake_current : &user_fake_default)->uid)
#define fake_gid ((user_fake_current ? user_fake_current : &user_fake_default)->gid)
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

/* "/proc/<internal pid>[/...]" becomes "/proc/0[/...]": Linux has no PID 0
 * entry, so every path operation fails with its native ENOENT. Reads the
 * guest path fault-safely; returns whether out holds the rewritten path. */
static bool user_internal_task(long pid);
static unsigned user_exe_local_pid(unsigned pid);

/* Whether /proc numbers tasks in an ancestor PID namespace. This depends
 * on the process's PID namespace, fixed for its lifetime. */
static bool user_proc_foreign(void)
{
    static int cached = -1;
    if (cached < 0) {
        char self[32];
        ssize_t n = readlink("/proc/self", self, sizeof(self) - 1);
        if (n > 0) self[n] = 0;
        cached = n > 0 && strtoul(self, NULL, 10) != (unsigned long)getpid();
    }
    return cached > 0;
}
static bool user_internal_proc_path(char* out, const char* path)
{
    static const char prefix[] = "/proc/";
    size_t at = 0;
    for (; prefix[at]; ++at) if (user_peek_byte(path + at) != prefix[at]) return false;
    long pid = 0;
    int byte;
    while ((byte = user_peek_byte(path + at)) >= '0' && byte <= '9' && pid < INT32_MAX) {
        pid = pid * 10 + byte - '0';
        ++at;
    }
    if (byte != 0 && byte != '/') return false;
    if (!user_internal_task(user_proc_foreign() ? (long)user_exe_local_pid(pid) : pid)) return false;
    char tail[UAPI_PATH_MAX];
    if (user_path_copy(tail, path + at, sizeof(tail) - 8) < 0) return false;
    snprintf(out, UAPI_PATH_MAX, "/proc/0%s", tail);
    return true;
}

#include "user_ptrace/user_ptrace.h"
#include "user_ptrace/user_ptrace_events.h"
static uint32_t user_reaper_tid;
static user_fd_mutex_t user_reaper_lock;
static void user_observer_fork_child(void);
static void user_observer_release(bool wait);
static bool user_observer_hidden(pid_t pid, bool reaped);
#include "rvvm_user_signal.h"
#include "rvvm_user_jit_memory.h"
#include "rvvm_user_posix.h"
#include "rvvm_user_ipc.h"
#include "rvvm_user_io_extra.h"
#include "rvvm_user_control_extra.h"
#include "rvvm_user_msg.h"
#include "rvvm_user_lock_memory.h"
#include "rvvm_user_fs_watch.h"
#include "rvvm_user_system_control.h"
#include "rvvm_user_exe.h"
#include "rvvm_user_allocate.h"
#include "rvvm_user_host_delegation.h"
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

#ifdef __linux__
static long rvvm_sys_openat(int dirfd, const char* path, uint32_t flags, unsigned mode)
{
    char snapshot[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
    user_host_path(snapshot, wrapped, &path);
    unsigned host_flags = uapi_open_flags_to_host(flags);
    long special;
    if (user_exe_fast_open(path, host_flags, &special)) return special;
    long fd = (long)errno_ret(USER_SYSCALL(SYS_openat, dirfd, path, host_flags, mode, 0, 0));
    return user_cpu_opened(fd, host_flags, dirfd, path);
}
#endif

#if defined(__linux__) && defined(SYS_openat2)
static rvvm_addr_t rvvm_sys_openat2(int dirfd, const char* path, void* guest_how, size_t size)
{
    BUILD_ASSERT(sizeof(struct open_how) == 24);
    BUILD_ASSERT(offsetof(struct open_how, mode) == 8);
    BUILD_ASSERT(offsetof(struct open_how, resolve) == 16);
    if (size < sizeof(struct open_how)) return -UAPI_EINVAL;
    if (size > (size_t)sysconf(_SC_PAGESIZE)) return -UAPI_E2BIG;

    struct open_how* how = user_runtime_allocate(size);
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
    user_runtime_release(how);
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
    if (user_ptrace_signal(user_sig.cpu, sig, info)) return;
    bool replayed = user_ptrace_restore_signal(info);
    if ((replayed && info->si_code > 0) || user_ptrace_injected(sig, info)) {
        user_signal_capture(sig, info, ucontext);
        user_sig.synchronous = true;
        return;
    }
    if (info->si_code > 0 && user_path_fault(ucontext)) return;
    rvvm_hart_t* fault_cpu = user_sig.cpu;
    ucontext_t* uc = ucontext;
#if defined(__aarch64__)
    uintptr_t host_pc = uc->uc_mcontext.pc;
#else
    uintptr_t host_pc = uc->uc_mcontext.gregs[REG_RIP];
#endif
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
        user_defer_pending();
        user_sig.info = *info;
        user_sig.pending = sig;
        user_sig.synchronous = true;
        user_fault_save_fenv(uc);
        user_fault_armed = 0;
        if (user_native_child_active) {
            user_native_jump_restore(user_native_fault_target);
        }
        siglongjmp(user_fault_resume, 1);
    }
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
    uint32_t unshare_flags, setup_ready;
    int setup_error;
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
static rvvm_user_thread_t* user_reap_threads;
static bool user_reaper_running;
/* Joined before its replacement starts, never detached: a detached thread's
 * exit updates libc state outside rvvm_thread_fork_lock(). */
static rvvm_thread_t* user_reaper_thread;
/* Publish the last guest exit status together with the live count. The
 * internal reaper must not turn a nonzero last-thread exit into success. */
static uint64_t user_thread_lifetime = 1;

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

static void* user_thread_reaper(void* unused)
{
    UNUSED(unused);
    atomic_store_uint32(&user_reaper_tid, gettid());
    rvvm_futex_wake(&user_reaper_tid, 1);
    for (;;) {
        user_fd_mutex_lock(&user_reaper_lock);
        user_reap_finished();
        bool pending = user_reap_threads != NULL;
        uint64_t lifetime = atomic_load_uint64(&user_thread_lifetime);
        if (!pending) {
            user_reaper_running = false;
            atomic_store_uint32(&user_reaper_tid, 0);
            user_fd_mutex_unlock(&user_reaper_lock);
            if (!(uint32_t)lifetime) syscall(SYS_exit, lifetime >> 32);
            return NULL;
        }
        user_fd_mutex_unlock(&user_reaper_lock);
        sleep_ms(1);
    }
}
#include "rvvm_user_memory.h"
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
#define UAPI_CLONE_FILES          0x00000400
#define UAPI_CLONE_SIGHAND        0x00000800
#define UAPI_CLONE_PIDFD          0x00001000
#define UAPI_CLONE_THREAD         0x00010000
#define UAPI_CLONE_VFORK          0x00004000
#define UAPI_CLONE_SETTLS         0x00080000
#define UAPI_CLONE_PARENT_SETTID  0x00100000
#define UAPI_CLONE_CHILD_CLEARTID 0x00200000
#define UAPI_CLONE_CHILD_SETTID   0x01000000

#define UAPI_CLONE_THREAD_FLAGS 0x00050f00 // VM, FS, FILES, SIGHAND, THREAD, SYSVSEM
/* Linux mprotect rejects bits outside READ/WRITE/EXEC/SEM/GROWSDOWN/GROWSUP. */
#define UAPI_PROT_VALID (0x7 | 0x8 | 0x01000000 | 0x02000000)

#define UAPI_CLONE_IGNORED_FLAGS 0x80400000 // IO, DETACHED
#define UAPI_CLONE_OPTIONAL_FLAGS (UAPI_CLONE_SETTLS | UAPI_CLONE_PARENT_SETTID \
    | UAPI_CLONE_CHILD_CLEARTID | UAPI_CLONE_CHILD_SETTID)

static rvvm_hart_t* user_clone_cpu_mode(rvvm_hart_t* parent, bool interpreter)
{
    rvvm_hart_t* cpu = interpreter ? rvvm_create_user_thread_interpreter(userland) : rvvm_create_user_thread(userland);
    if (!cpu) return NULL;
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

static rvvm_hart_t* user_clone_cpu(rvvm_hart_t* parent)
{
    return user_clone_cpu_mode(parent, false);
}

// long sys_clone(unsigned long flags, void *stack, int *parent_tid, unsigned long tls, int *child_tid);
static int rvvm_sys_vfork(rvvm_user_thread_t*, uint32_t, size_t, uint32_t*, size_t, uint32_t*);
#include "rvvm_user_malloc.h"
#include "rvvm_user_fork.h"
#include "rvvm_user_fork_cache.h"

static int rvvm_sys_clone_impl(rvvm_user_thread_t* current, uint32_t flags, size_t stack, uint32_t* parent_tid, size_t tls, uint32_t* child_tid)
{
    rvvm_hart_t* cpu = current->cpu;
    flags &= ~UAPI_CLONE_IGNORED_FLAGS;
    if (flags & UAPI_CLONE_VM) {
        const uint32_t supported = 0xff | UAPI_CLONE_THREAD_FLAGS | UAPI_CLONE_OPTIONAL_FLAGS
            | 0x00008000; // CLONE_PARENT
        const uint32_t required = UAPI_CLONE_VM | UAPI_CLONE_SIGHAND | UAPI_CLONE_THREAD;
        if ((flags & required) != required || (flags & ~supported)) {
            return -UAPI_EINVAL;
        }

        uint32_t separate = (CLONE_FS | CLONE_FILES | CLONE_SYSVSEM) & ~flags;
        uint64_t held = UINT64_MAX, saved_mask;
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &held, &saved_mask, 8);
        if (separate) user_fd_lock();
        user_fd_mutex_lock(&user_reaper_lock);
        if (!user_reaper_running) {
            /* A previous reaper has stopped serving and is returning. */
            if (user_reaper_thread) rvvm_thread_join(user_reaper_thread);
            user_reaper_thread = rvvm_thread_create(user_thread_reaper, NULL);
            if (!user_reaper_thread) {
                user_fd_mutex_unlock(&user_reaper_lock);
                if (separate) user_fd_unlock();
                syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
                return -EAGAIN;
            }
            user_reaper_running = true;
            while (!atomic_load_uint32(&user_reaper_tid))
                rvvm_futex_wait(&user_reaper_tid, 0, RVVM_FUTEX_INFINITE);
        }

        rvvm_user_thread_t* thread = calloc(1, sizeof(*thread));
        if (!thread || !(thread->cpu = user_clone_cpu(cpu))) {
            free(thread);
            user_fd_mutex_unlock(&user_reaper_lock);
            if (separate) user_fd_unlock();
            syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
            return -EAGAIN;
        }

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
        thread->fd_table = (separate & CLONE_FILES)
            ? user_fd_table_copy(user_fd_table()) : user_fd_table_retain();
        if (!thread->fd_table) {
            user_signal_process_release(thread->signals);
            rvvm_free_user_thread(thread->cpu);
            free(thread);
            user_fd_mutex_unlock(&user_reaper_lock);
            if (separate) user_fd_unlock();
            syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
            return -EAGAIN;
        }
        thread->unshare_flags = separate;
        thread->ptrace_state = user_ptrace_prepare(thread->cpu, user_cpu_auxv, user_cpu_auxv_size, thread->signal_mask);
        atomic_add_uint64(&user_thread_lifetime, 1);
        // Guest stacks are separate mappings; native execution needs no 8 MiB stack.
        rvvm_thread_t* host_thread = rvvm_thread_create_ex(rvvm_user_thread_wrap, thread, 256 * 1024);
        syscall(SYS_rt_sigprocmask, SIG_SETMASK, &saved_mask, NULL, 8);
        if (!host_thread) {
            user_fd_mutex_unlock(&user_reaper_lock);
            if (separate) user_fd_unlock();
            atomic_sub_uint64(&user_thread_lifetime, 1);
            user_signal_process_release(thread->signals);
            user_fd_table_release(thread->fd_table);
            user_ptrace_cancel(thread->ptrace_state);
            rvvm_free_user_thread(thread->cpu);
            free(thread);
            return -UAPI_EAGAIN;
        }
        if (separate) {
            /* Freeze the source table until Linux has made the child's copy.
             * The child publishes setup before taking any descriptor guard. */
            while (!atomic_load_uint32(&thread->setup_ready))
                rvvm_futex_wait(&thread->setup_ready, 0, RVVM_FUTEX_INFINITE);
            user_fd_unlock();
        }
        thread->host_thread = host_thread;
        thread->reap_next = user_reap_threads;
        user_reap_threads = thread;
        user_fd_mutex_unlock(&user_reaper_lock);

        uint32_t tid = atomic_load_uint32(&thread->tid);
        while (!tid) {
            rvvm_futex_wait(&thread->tid, 0, RVVM_FUTEX_INFINITE);
            tid = atomic_load_uint32(&thread->tid);
        }

        int result = thread->setup_error ? thread->setup_error : (int)tid;
        rvvm_user_thread_put(thread);
        return result;
    } else {
        const uint32_t namespaces = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET
            | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS;
        const uint32_t supported = 0xff | UAPI_CLONE_OPTIONAL_FLAGS | UAPI_CLONE_PIDFD
            | UAPI_CLONE_FILES | namespaces;
        if (flags & ~supported) return -UAPI_EINVAL;
        if ((flags & UAPI_CLONE_PIDFD) && (flags & UAPI_CLONE_PARENT_SETTID))
            return -EINVAL;
        int publish[2] = {-1, -1};
        user_fd_lock();
        bool shared_files = flags & UAPI_CLONE_FILES;
        user_fd_table_t* source_table = user_fd_table();
        if (shared_files && !user_fd_waits_init(source_table)) { user_fd_unlock(); return -ENOMEM; }
        if (shared_files && (!user_fd_mutex_share(&source_table->guard->lock)
                             || !user_fd_mutex_share(&source_table->lock))) {
            user_fd_unlock();
            return -ENOMEM;
        }
        /* All private-files thread tables retain this guard. Mark before any
         * new mm inherits it, including helpers created by vfork below. */
        atomic_store_uint32(&source_table->guard->escaped, 1);
        struct user_fork_slot* fork_slot = user_fork_cache_prepare(source_table,
            !shared_files);
        user_fd_table_t* child_table = shared_files ? source_table
            : fork_slot ? fork_slot->table : user_fd_table_copy_guard(source_table, true);
        if (!child_table) {
            user_fork_cache_finish(fork_slot, -1);
            user_fd_unlock(); return -ENOMEM;
        }
        // Linux publishes parent_tid before the child can observe shared memory.
        if (!shared_files && (flags & (UAPI_CLONE_PARENT_SETTID | UAPI_CLONE_PIDFD))
            && socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, publish)) {
            int error = -errno;
            if (!fork_slot) user_fd_table_release(child_table);
            user_fork_cache_finish(fork_slot, -1);
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
        user_fd_mutex_lock(&user_reaper_lock);
        rvvm_user_fork_lock();
        user_ptrace_clone(cpu);
        pid_t pid = user_host_fork(flags & 0xff, (shared_files ? CLONE_FILES : 0) | (flags & namespaces));
        int fork_errno = errno;
        user_fork_cache_finish(fork_slot, pid);
        unsigned child_fd_depth = 0;
        if (!pid) {
            /* Other native threads, their join handles and wake queues do
             * not survive host fork. The survivor is now a process thread. */
            user_reap_threads = NULL;
            user_reaper_running = false;
            user_reaper_thread = NULL;
            user_thread_lifetime = 1;
            user_reaper_tid = 0;
            child_fd_depth = user_fd_fork_select(child_table->guard);
            user_fd_guard_default(child_table->guard);
            user_fd_current = child_table;
            current->fd_table = child_table;
            user_ptrace_set_exe_fd_pointer(&child_table->exe_fd);
            user_fd_table_t* initial_table = user_fd_initial;
            user_fd_initial = child_table;
            if (!shared_files) user_fd_table_fork_discard(source_table);
            if (initial_table != source_table) user_fd_table_fork_discard(initial_table);
            rvvm_user_fork_child(cpu);
            user_ptrace_fork(cpu);
            user_exec_fork_child();
            user_observer_fork_child();
            user_exe_process_link_init(false);
        }
        rvvm_user_fork_unlock();
        user_fd_mutex_unlock(&user_reaper_lock);
        if (pid) user_fd_mutex_unlock(&user_exe_lock);
        if (!pid) {
            user_fd_table_fork_child();
            user_fd_table_enter(child_table);
        }
        spin_unlock(&mmap_lock);
        spin_unlock(&brk_lock);
        spin_unlock(&user_action_lock);
        if (pid == 0) {
            /* With CLONE_FILES, acquiring the shared guard is also the
             * publication barrier; socket endpoints would themselves be shared. */
            for (unsigned i = 0; i < child_fd_depth; ++i) user_fd_lock();
            if (publish[0] >= 0) {
                char ready;
                close(publish[0]);
                ssize_t received;
                do { received = read(publish[1], &ready, 1); } while (received < 0 && errno == EINTR);
                close(publish[1]);
                if ((flags & UAPI_CLONE_PIDFD) && received != 1) _exit(127);
            }
            user_fd_unlock();
            /* The surviving thread is the new process's only one. Its TID
             * is the child's own, which CLONE_CHILD_SETTID stores below. */
            current->tid = gettid();
            atomic_store_uint32_relax(&user_signal_process_current()->refs, 1);
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
            user_apply_mask();
        } else {
            if (!shared_files && !fork_slot) user_fd_table_release(child_table);
            int publish_error = 0;
            if (pid > 0 && (flags & UAPI_CLONE_PIDFD)) {
                // The child cannot exit/exec until its pidfd is opened and published.
                int pidfd = syscall(SYS_pidfd_open, pid, 0);
                publish_error = pidfd < 0 ? -errno : uapi_extra_copy(&pidfd, parent_tid, sizeof(pidfd), true);
                if (publish_error && pidfd >= 0) close(pidfd);
                if (publish_error && shared_files) kill(pid, SIGKILL);
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
                pid_t reaped;
                do { reaped = waitpid(pid, NULL, __WALL); } while (reaped < 0 && errno == EINTR);
                if (reaped > 0) user_fork_cache_reaped(reaped);
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
    if (flags & UAPI_CLONE_VFORK) return rvvm_sys_vfork(current, flags, stack, parent_tid, tls, child_tid);
    return rvvm_sys_clone_impl(current, flags, stack, parent_tid, tls, child_tid);
}

#include "user_ptrace/user_ptrace_restart.h"
static bool user_kernel_dispatch(rvvm_hart_t*, long, long[6], long*);
#include "rvvm_user_native_vfork.h"

static int rvvm_sys_vfork(rvvm_user_thread_t* current, uint32_t flags, size_t stack,
                          uint32_t* parent_tid, size_t tls, uint32_t* child_tid)
{
    return user_native_vfork(current, flags, stack, parent_tid, tls, child_tid);
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
    long result;
    if (command == FUTEX_WAIT || command == FUTEX_WAIT_BITSET || command == FUTEX_LOCK_PI
        || command == FUTEX_WAIT_REQUEUE_PI || command == FUTEX_LOCK_PI2)
        result = errno_ret(USER_SYSCALL(SYS_futex, addr, futex_op, val, val2, uaddr2, val3));
    else result = errno_ret(syscall(SYS_futex, addr, futex_op, val, val2, uaddr2, val3));
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

/* An entry of a proc root as getpid() numbers it; a foreign proc (from an
 * ancestor PID namespace) lists NSpid last in each status. */
static unsigned user_proc_entry_local(int dirfd, unsigned pid)
{
    char path[32], text[1024];
    snprintf(path, sizeof(path), "%u/status", pid);
    int status = openat(dirfd, path, O_RDONLY | O_CLOEXEC);
    if (status < 0) return 0;
    ssize_t n = read(status, text, sizeof(text) - 1);
    close(status);
    if (n <= 0) return 0;
    text[n] = 0;
    char* line = strstr(text, "\nNSpid:");
    if (!line) return pid;
    unsigned local = pid;
    for (char* at = line + 7;;) {
        while (*at == ' ' || *at == '\t') ++at;
        if (*at < '0' || *at > '9') break;
        local = strtoul(at, &at, 10);
    }
    return local;
}

static int64_t rvvm_sys_getdents64(int fd, void* dirp, size_t size)
{
    char link[64], path[128];
    snprintf(link, sizeof(link), "/proc/thread-self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path) - 1);
    unsigned pid = 0;
    int end = 0;
    if (n >= 0) path[n] = 0;
    bool task_list = n >= 0 && sscanf(path, "/proc/%u/task%n", &pid, &end) == 1 && end && !path[end];
    bool proc_root = false;
    /* The proc root lists internal tasks. Identify it by name and inode 1
     * without statfs, which a FUSE server would see. */
    struct stat st;
    proc_root = !task_list && n >= 5 && !strcmp(path + n - 5, "/proc")
        && !fstat(fd, &st) && S_ISDIR(st.st_mode) && st.st_ino == 1;
    bool foreign = false;
    if (proc_root) {
        char self[32];
        ssize_t length = readlinkat(fd, "self", self, sizeof(self) - 1);
        if (length > 0) self[length] = 0;
        foreign = length > 0 && strtoul(self, NULL, 10) != (unsigned long)getpid();
    }
    if (task_list || proc_root) {
        char buffer[4096];
        user_fd_lock();
        long result;
        do {
            result = errno_ret(syscall(SYS_getdents64, fd, buffer,
                               EVAL_MIN((unsigned int)size, sizeof(buffer))));
            if (result <= 0) break;
            size_t kept = 0;
            for (size_t pos = 0; pos < (size_t)result;) {
                struct uapi_linux_dirent64* entry = (void*)(buffer + pos);
                bool recognized = false;
                unsigned tid = strtoul(entry->d_name, NULL, 10);
                if (proc_root) recognized = tid && user_internal_task(foreign ? user_proc_entry_local(fd, tid) : tid);
                bool visible = proc_root ? !recognized
                    : !tid || user_ptrace_guest_task(pid, tid, &recognized);
                if (visible || !recognized) {
                    memmove(buffer + kept, entry, entry->d_reclen);
                    kept += entry->d_reclen;
                }
                pos += entry->d_reclen;
            }
            if (kept) {
                int error = uapi_extra_copy(buffer, dirp, kept, true);
                result = error ? error : (long)kept;
                break;
            }
        } while (true);
        user_fd_unlock();
        return result;
    }
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

/* RV64 uses the generic Linux mmap flag values, as do the aarch64 and x86_64
 * hosts, except x86's MAP_32BIT and MAP_ABOVE4G, unused bits on RISC-V. Pass
 * the rest to Linux so it applies its own rules: legacy types ignore unknown
 * bits, MAP_SHARED_VALIDATE rejects them, and POPULATE/LOCKED/GROWSDOWN/STACK
 * /SYNC/DROPPABLE and hugetlb sizes take effect. */
#if defined(__x86_64__)
#define UAPI_MAP_HOST_UNSAFE     0x0000C0
#else
#define UAPI_MAP_HOST_UNSAFE     0
#endif

#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

static inline int rvvm_sys_prot(int prot)
{
    int ret = PROT_NONE;
    if (prot & UAPI_PROT_READ)  ret |= PROT_READ;
    if (prot & UAPI_PROT_WRITE) ret |= PROT_WRITE;
    /* The decoder needs readable code; retain X so kernel maps can recover
     * guest execution permissions after an interrupted mapping transaction. */
    if (prot & UAPI_PROT_EXEC) {
        ret |= PROT_READ;
        ret |= PROT_EXEC;
    }
    ret |= prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    return ret;
}

static rvvm_addr_t rvvm_sys_mmap(void* addr, size_t size, int prot, int flags, int fd, uint64_t offset)
{
    rvvm_info("sys_mmap(%lx, %lx, %x, %x, %d, %lx)", (size_t)addr, size, prot, flags, fd, offset);
    int mmap_flags = 0;
#ifndef __linux__
    if (flags & UAPI_MAP_ILLEGAL) {
        return -UAPI_EINVAL;
    }
#endif

    user_fd_lock();
    spin_lock(&mmap_lock);
    if (!user_exec_reserve(2)) {
        spin_unlock(&mmap_lock);
        user_fd_unlock();
        return -ENOMEM;
    }
#ifdef __linux__
    mmap_flags = flags & ~UAPI_MAP_HOST_UNSAFE;
#else
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
        munmap(addr, size);
    }
#endif

#ifdef __linux__
    rvvm_addr_t ret = errno_ret((size_t)user_vma_map(addr, size, rvvm_sys_prot(prot), mmap_flags, fd, offset));
#else
    rvvm_addr_t ret = errno_ret((size_t)mmap(addr, size, rvvm_sys_prot(prot), mmap_flags, fd, offset));
#endif
    if (ret < (rvvm_addr_t)-4095) {
        size_t page = user_vma_map_page(mmap_flags);
        user_exec_update(ret, (size + page - 1) & ~(page - 1), prot & UAPI_PROT_EXEC);
    }
    spin_unlock(&mmap_lock);
    user_fd_unlock();
    return ret;
}

static int rvvm_sys_munmap(void* addr, size_t size)
{
    spin_lock(&mmap_lock);
    if (!user_exec_reserve(2)) { spin_unlock(&mmap_lock); return -ENOMEM; }
#ifdef __linux__
    rvvm_addr_t ret = errno_ret(user_vma_unmap(addr, size));
#else
    rvvm_addr_t ret = errno_ret(munmap(addr, size));
#endif
    if (!ret) user_exec_update((uintptr_t)addr, size, false);
    spin_unlock(&mmap_lock);
    return ret;
}


extern uint64_t __thread_selfid(void);

static int rvvm_sys_gettid(void)
{
#if defined(__APPLE__)
    return __thread_selfid();
#else
    return gettid();
#endif
}

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
#ifdef __linux__
    if (syscall(SYS_getcwd, tmp, sizeof(tmp)) < 0) return last_errno();
#else
    if (!getcwd(tmp, sizeof(tmp))) {
        return last_errno();
    }
#endif
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
    if (user_internal_proc_path(tmp, snapshot)) return errno_ret(readlinkat(dirfd, tmp, buffer, size));
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

#ifdef __linux__
#include "rvvm_user_kernel_dispatch.h"
#endif

static void* rvvm_user_thread_wrap(void* arg)
{
    user_signal_block_all();
    user_host_fork_init();
    rvvm_user_thread_t* thread = arg;
    rvvm_hart_t* cpu = thread->cpu;
    bool running = true;
    int exit_status = 0;

    if (thread->unshare_flags) {
        if (syscall(SYS_unshare, thread->unshare_flags)) {
            thread->setup_error = -errno;
            running = false;
        }
        atomic_store_uint32(&thread->setup_ready, 1);
        rvvm_futex_wake(&thread->setup_ready, 1);
    }
    current_user_hart = cpu;
    user_signal_process = thread->signals;
    user_fd_table_enter(thread->fd_table);
    user_private_signals_restore();
    user_signal_init(cpu, thread->signal_mask);
    if (thread->inherit_signal_stack) user_sig.stack = thread->signal_stack;


    // Set up thread tid, child_tid
    uint32_t tid = rvvm_sys_gettid();
    if (!thread->setup_error && thread->child_settid) {
        (void)uapi_extra_copy(&tid, thread->child_settid, sizeof(tid), true);
    }
    // CLONE_VM shares the parent address space. Write both TID slots before
    // guest execution so the parent cannot overwrite an already-cleared TID.
    if (!thread->setup_error && thread->parent_settid)
        (void)uapi_extra_copy(&tid, thread->parent_settid, sizeof(tid), true);
    if (thread->setup_error) thread->child_cleartid = NULL;
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
        cause = user_ptrace_run(cpu);
        user_fault_armed = 0;
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
            long kernel_args[] = {a0, a1, a2, a3, a4, a5};
            user_exe_filter_args(a7, kernel_args);
            a0 = kernel_args[0]; a1 = kernel_args[1]; a2 = kernel_args[2];
            a3 = kernel_args[3]; a4 = kernel_args[4]; a5 = kernel_args[5];
            bool memory_mutation = a7 == 196 || a7 == 197 || a7 == 214 || a7 == 215
                                || a7 == 216 || a7 == 222 || a7 == 226 || a7 == 233;
#ifdef __linux__
            long kernel_result;
            if (user_kernel_dispatch(cpu, a7, kernel_args, &kernel_result)) a0 = kernel_result;
            else
#endif
            switch (a7) {
                case 128: // restart_syscall: preserve a traced timed wait's original deadline
                    a0 = user_ptrace_restart_syscall();
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
                case 97: // unshare
                    /* A user namespace needs a single-threaded caller, and
                     * the VFORK workers prepared for a new PID namespace are
                     * threads: enter the user namespace first. If the PID
                     * step then fails, the user namespace stays entered. */
                    if ((a0 & CLONE_NEWPID) && (a0 & CLONE_NEWUSER)) {
                        a0 = user_fd_unshare(a0 & ~CLONE_NEWPID);
                        if (a0) break;
                        user_observer_namespace(CLONE_NEWPID);
                        a0 = user_fd_unshare(CLONE_NEWPID);
                        break;
                    }
                    user_observer_namespace(a0);
                    a0 = user_fd_unshare(a0);
                    break;
                case 281: // execveat: the kernel handles ELF/script dispatch through binfmt
                    user_observer_release(true);
                    a0 = user_binfmt_executable || getenv("RVVM_USER_BINFMT")
                       ? user_execveat(a0, to_str(a1), to_ptr(a2), to_ptr(a3),
                           uapi_translate_flags(a4, uapi_path_flags, STATIC_ARRAY_SIZE(uapi_path_flags), true))
                       : -UAPI_ENOSYS;
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
#ifndef __linux__
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
#endif
                case 57: // close
                    a0 = user_exe_close(a0);
                    break;
                case 93: // exit
                    user_ptrace_exit(cpu);
                    exit_status = a0;
                    running = false;
                    break;
                case 94: // exit_group
                    user_ptrace_exit(cpu);
                    user_observer_release(false);
                    _Exit(a0);
                    break;
                case 96: // set_tid_address
                    thread->child_cleartid = to_ptr(a0);
                    a0 = thread->process_thread
                        ? syscall(SYS_set_tid_address, a0) : rvvm_sys_gettid();
                    break;
                case 139: // rt_sigreturn restores a0 and PC itself
                    user_rt_sigreturn(cpu);
                    user_ptrace_syscall_end(cpu);
                    continue;
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
                    a0 = user_mremap(a0, a1, a2, a3, a4);
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
                    user_observer_release(true);
                    /* With binfmt registered, the kernel handles scripts and
                     * redispatches RISC-V ELF files to this interpreter. */
                    if (user_binfmt_executable || getenv("RVVM_USER_BINFMT")) {
                        a0 = user_execve(to_str(a0), to_ptr(a1), to_ptr(a2));
                        break;
                    }
                    a0 = user_exec_interpreter(to_str(a0), to_ptr(a1), to_ptr(a2));
                    break;
                }
                case 222: // mmap
                    a0 = rvvm_sys_mmap(to_ptr(a0), a1, a2, a3, a4, a5);
                    break;
                case 226: // mprotect
                    rvvm_info("sys_mprotect(%lx, %lx, %x)", a0, a1, a2);
                    user_fd_lock();
                    spin_lock(&mmap_lock);
                    {
                        uintptr_t start = a0;
                        size_t size = a1;
                        rvvm_addr_t ret;
                        if (!user_exec_reserve(2)) ret = -ENOMEM; else
                        if (a2 & ~UAPI_PROT_VALID) ret = -EINVAL;
                        else if (user_vma_protect_span(&start, &size, a2)) ret = last_errno();
                        else {
                            ret = errno_ret(mprotect(to_ptr(a0), a1, rvvm_sys_prot(a2)));
                            if (!ret) user_exec_update(start, size, a2 & UAPI_PROT_EXEC);
                            else if (ret != (rvvm_addr_t)-EINVAL)
                                user_exec_partial(start, size, rvvm_sys_prot(a2), a2 & UAPI_PROT_EXEC);
                        }
                        a0 = ret;
                    }
                    spin_unlock(&mmap_lock);
                    user_fd_unlock();
                    break;
#ifdef __linux__
                case 233: // madvise
                    rvvm_info("sys_madvise(%lx, %lx, %lx)", a0, a1, a2);
                    a0 = errno_ret(madvise(to_ptr(a0), a1, a2));
                    break;
#endif
#ifndef __linux__
                case 258: // riscv_hwprobe
                    a0 = user_cpu_hwprobe(to_ptr(a0), a1, a2, to_ptr(a3), (unsigned int)a4);
                    break;
#endif
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
                case 277: // Guest filters cannot safely constrain the emulator's host syscalls.
                    a0 = -UAPI_ENOSYS;
                    break;
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
#ifndef SYS_openat2
                case 437: // openat2
                    a0 = -UAPI_ENOSYS;
                    break;
#endif
                default:
#ifndef __riscv
                    rvvm_error("Unknown syscall %ld!", a7);
                    a0 = -UAPI_ENOSYS;
#else
                    a0 = errno_ret(syscall(a7, a0, a1, a2, a3, a4, a5));
#endif
                    break;
            }
            if (memory_mutation || a7 == 164 || a7 == 261) rvvm_user_jit_pressure(cpu);
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
                /* Direct writes, as everywhere after startup: see the libc
                 * rule in rvvm_user_fork.h. */
                char line[2 * 32 + 2];
                for (size_t i=0; i<32; ++i) {
                    snprintf(line + 2 * i, 3, "%02x", *(uint8_t*)(pc_al + i));
                }
                line[64] = '\n';
                (void)!write(STDOUT_FILENO, line, 65);
                for (size_t i=0; i<32; ++i) {
                    memcpy(line + 2 * i, (pc_al + i == pc) ? "^ " : "  ", 2);
                }
                (void)!write(STDOUT_FILENO, line, 65);
            } else {
                rvvm_warn(" * * * PC points to inaccessible memory!");
            }

            /* A fault in any guest thread must fail the process, not return
             * through jump_start() and report a successful command. */
            _Exit(EXIT_FAILURE);
        }
    }

    uint64_t exit_mask = UINT64_MAX;
    syscall(SYS_rt_sigprocmask, SIG_SETMASK, &exit_mask, NULL, 8);
    user_sig.cpu = NULL;
    current_user_hart = NULL;
    user_sig.pending = 0;
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
    /* A retiring native helper may still be inside pthread cleanup. Once
     * the last guest exits, it must not replace the process's exit status. */
    if ((uint32_t)lifetime == 1) syscall(SYS_exit_group, exit_status);
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
#if defined(__linux__) && defined(USE_JIT)
    userland->user_memory_probe = user_jit_memory_probe;
#endif
    rvvm_user_thread_t* thread = safe_new_obj(rvvm_user_thread_t);
    thread->cpu = rvvm_create_user_thread(userland);
    if (!thread->cpu) rvvm_fatal("Cannot allocate initial guest CPU");
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
    // Omit optional platform strings: LD_SHOW_AUXV dereferences present entries.
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
        UAPI_AT_HWCAP,         USER_CPU_HWCAP,
        UAPI_AT_CLKTCK,        100,
        UAPI_AT_SECURE,        0,
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

    user_exec_elf(&elf);
    user_exec_elf(&interp);
    riscv_user_exec_check = user_exec_check;

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
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    user_fd_unlock();
    if (stack_mapping == MAP_FAILED) return -1;
    uint8_t* stack_buffer = stack_mapping + stack_guard;
    if (mprotect(stack_buffer, STACK_SIZE, PROT_READ | PROT_WRITE)) {
        munmap(stack_mapping, STACK_SIZE + 2 * stack_guard);
        return -1;
    }
    if (user_exec_stack(&elf)) user_exec_protect(stack_buffer, STACK_SIZE, PROT_READ | PROT_WRITE, true);
    user_exec_update((uintptr_t)stack_buffer, STACK_SIZE, user_exec_stack(&elf));
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
