/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_CPU_H
#define RVVM_USER_CPU_H

#include <linux/magic.h>
#include <linux/memfd.h>
#include <sys/sysmacros.h>

// A conservative guest contract, not the host's ISA or every experimental decoder.
#ifdef USE_FPU
#define USER_CPU_ISA "rv64imafdc_zicsr_zifencei"
#define USER_CPU_HWCAP UINT64_C(0x112d)
#define USER_CPU_EXT0 UINT64_C(3) // FD, C
#define USER_CPU_MODALIAS "cpu:type:riscv:feature:,0000,0002,0003,0005,0008,000C,0028,0029\n"
#else
#define USER_CPU_ISA "rv64imac_zicsr_zifencei"
#define USER_CPU_HWCAP UINT64_C(0x1105)
#define USER_CPU_EXT0 UINT64_C(2)
#define USER_CPU_MODALIAS "cpu:type:riscv:feature:,0000,0002,0008,000C,0028,0029\n"
#endif

static uint64_t user_cpu_auxv[64];
static size_t user_cpu_auxv_size;
static dev_t user_cpu_proc_device, user_cpu_sys_device;
static bool user_cpu_have_proc, user_cpu_have_sys;

static void user_cpu_init(void)
{
    // Initialize before guest threads/forks; no lazy-init lock can survive a fork.
    struct stat root;
    if (!stat("/proc", &root) && user_fs_type(root.st_dev) == PROC_SUPER_MAGIC) {
        user_cpu_proc_device = root.st_dev; user_cpu_have_proc = true;
    }
    if (!stat("/sys", &root) && user_fs_type(root.st_dev) == SYSFS_MAGIC) {
        user_cpu_sys_device = root.st_dev; user_cpu_have_sys = true;
    }
}

// Read Linux's online CPU IDs, not sched_getaffinity: pinning a thread does not
// remove CPUs from /proc/cpuinfo or from the hwprobe syscall's online-CPU set.
static int user_cpu_online_inner(unsigned char** mask, size_t* size)
{
    struct user_proc_reader file;
    if (!user_proc_open(&file, "/proc/stat")) return -errno;
    unsigned char* bits = user_runtime_allocate(128);
    size_t bytes = 128;
    char line[256];
    bool found = false;
    int result = 0;
    if (!bits) { user_proc_close(&file); return -ENOMEM; }
    memset(bits, 0, bytes);
    while (user_proc_line(&file, line, sizeof(line))) {
        if (strncmp(line, "cpu", 3) || line[3] < '0' || line[3] > '9') continue;
        uint64_t cpu = 0;
        for (const char* digit = line + 3; *digit >= '0' && *digit <= '9'; ++digit) {
            cpu = cpu * 10 + *digit - '0';
            if (cpu >= 1024 * 1024) break;
        }
        if (cpu >= 1024 * 1024) { result = -EOVERFLOW; break; }
        if (cpu / 8 >= bytes) {
            size_t next = ((size_t)cpu / 64 + 1) * 8;
            unsigned char* grown = user_runtime_allocate(next);
            if (!grown) { result = -ENOMEM; break; }
            memcpy(grown, bits, bytes);
            memset(grown + bytes, 0, next - bytes);
            user_runtime_release(bits);
            bits = grown; bytes = next;
        }
        bits[cpu / 8] |= 1U << (cpu % 8);
        found = true;
    }
    if (file.error) result = -EIO;
    user_proc_close(&file);
    if (!found && !result) result = -ENODEV;
    if (result) { user_runtime_release(bits); return result; }
    *mask = bits; *size = bytes;
    return 0;
}

static int user_cpu_online(unsigned char** mask, size_t* size)
{
    user_fd_lock();
    int result = user_cpu_online_inner(mask, size);
    user_fd_unlock();
    return result;
}

struct user_hwprobe { int64_t key; uint64_t value; };

static bool user_cpu_key(struct user_hwprobe* pair)
{
    switch (pair->key) {
        case 0: case 1: case 2: pair->value = 0; break; // Unknown vendor/architecture/implementation IDs.
        case 3: pair->value = 1; break; // IMA base behavior.
        case 4: pair->value = USER_CPU_EXT0; break;
        case 5: case 9: pair->value = 0; break; // No measured misalignment performance claim.
        case 6: pair->value = 0; break; // No Zicboz block size.
        default: pair->key = -1; pair->value = 0; return false;
    }
    return true;
}

static long user_cpu_hwprobe(void* pairs, size_t count, size_t size, void* cpus, unsigned flags)
{
    if (flags > 1 || (flags && (!size || !cpus))) return -EINVAL;
    if (count > (UINTPTR_MAX - (uintptr_t)pairs) / sizeof(struct user_hwprobe)) return -EFAULT;
    unsigned char* online = NULL;
    size_t bytes = 0;
    int error = 0;
    bool all = !flags && !size && !cpus;
    if (!all) {
        error = user_cpu_online(&online, &bytes);
        if (error) return error;
    }
    size_t used = size < bytes ? size : bytes;
    unsigned char* selected = user_runtime_allocate(bytes ? bytes : 1);
    if (!selected) { user_runtime_release(online); return -ENOMEM; }
    memset(selected, 0, bytes ? bytes : 1);
    if (size || cpus) {
        error = uapi_extra_copy(selected, cpus, used, false);
        if (error) goto out;
    }
    bool empty = true, any = false;
    for (size_t i = 0; i < bytes; i++) if (selected[i]) empty = false;
    if (flags && empty) memcpy(selected, online, bytes);
    for (size_t i = 0; i < bytes; i++) {
        selected[i] &= online[i];
        if (selected[i]) any = true;
    }
    if (!flags && !all && !any) { error = -EINVAL; goto out; }
    for (size_t i = 0; i < count; i++) {
        struct user_hwprobe input = {0}, value;
        void* entry = (void*)((uintptr_t)pairs + i * sizeof(input));
        error = uapi_extra_copy(&input, entry, flags ? sizeof(input) : sizeof(input.key), false);
        if (error) goto out;
        value = input;
        bool known = user_cpu_key(&value);
        if (!flags || !known) {
            error = uapi_extra_copy(&value, entry, sizeof(value), true);
            if (error) goto out;
        }
        if (flags) {
            bool bitmap = input.key == 3 || input.key == 4 || input.key == 5;
            bool match = bitmap ? (value.value & input.value) == input.value : value.value == input.value;
            if (!known || !match) memset(selected, 0, bytes);
        }
    }
    if (flags) error = uapi_extra_copy(selected, cpus, used, true);
out:
    user_runtime_release(selected); user_runtime_release(online);
    return error;
}

static bool user_cpu_path_below(const char* path, const char* base)
{
    size_t length = strlen(base);
    return !strncmp(path, base, length) && (!path[length] || path[length] == '/');
}

static bool user_cpu_self_auxv(const char* path)
{
    unsigned pid, tid;
    int end = 0;
    if (sscanf(path, "/proc/%u/auxv%n", &pid, &end) == 1 && end && !path[end])
        return pid == (unsigned)getpid() || pid == (unsigned)syscall(SYS_gettid);
    end = 0;
    if (sscanf(path, "/proc/%u/task/%u/auxv%n", &pid, &tid, &end) == 2 && end && !path[end])
        return pid == (unsigned)getpid();
    return false;
}

static long user_cpu_view_write(int fd, const void* data, size_t size)
{
    for (size_t pos = 0; pos < size;) {
        long written = USER_SYSCALL(SYS_write, fd, (const char*)data + pos, size - pos, 0, 0, 0);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return written < 0 ? -errno : -EIO;
        pos += written;
    }
    return 0;
}

// Classify the resolved descriptor, after Linux has checked pathname, permissions,
// symlinks, dirfd and openat2 resolve flags. Native opens in RVVM itself bypass this.
static long user_cpu_open_special_inner(long fd, unsigned long flags, dev_t device)
{
    char descriptor[64], path[4096];
    snprintf(descriptor, sizeof(descriptor), "/proc/thread-self/fd/%ld", fd);
    ssize_t length = readlink(descriptor, path, sizeof(path) - 1);
    if (length < 0 || length == sizeof(path) - 1) return fd;
    path[length] = 0;
    if (!user_cpu_path_below(path, "/proc") && !user_cpu_path_below(path, "/sys")) return fd;
    long type;
    if (user_cpu_have_proc && device == user_cpu_proc_device) type = PROC_SUPER_MAGIC;
    else if (user_cpu_have_sys && device == user_cpu_sys_device) type = SYSFS_MAGIC;
    else type = user_fs_type(device);
    if (type != PROC_SUPER_MAGIC && type != SYSFS_MAGIC) return fd;
    const char* cpu = "/sys/devices/system/cpu";
    bool cpu_tree = user_cpu_path_below(path, cpu);
    const char* registers = strstr(path, "/regs");
    const char* caps = strstr(path, "/caps");
    bool hidden = (cpu_tree && ((registers && (!registers[5] || registers[5] == '/'))
                              || (caps && (!caps[5] || caps[5] == '/'))))
        || user_cpu_path_below(path, "/sys/firmware/devicetree")
        || !strcmp(path, "/sys/firmware/fdt")
        || user_cpu_path_below(path, "/sys/firmware/dmi/tables");
    if (hidden) { close(fd); return -ENOENT; }
    bool info = !strcmp(path, "/proc/cpuinfo");
    bool auxv = type == PROC_SUPER_MAGIC && user_cpu_self_auxv(path);
    uint64_t remote_auxv[64];
    const uint64_t* auxv_data = user_cpu_auxv;
    size_t auxv_size = user_cpu_auxv_size;
    if (!auxv && type == PROC_SUPER_MAGIC) {
        pid_t pid = user_ptrace_proc_pid(path, "auxv");
        size_t bytes = sizeof(remote_auxv);
        if (pid && user_ptrace_remote_auxv(pid, remote_auxv, &bytes) && bytes <= sizeof(remote_auxv)) {
            auxv = true;
            auxv_data = remote_auxv;
            auxv_size = bytes;
        }
    }
    unsigned cpu_id;
    int end = 0;
    bool uevent = sscanf(path, "/sys/devices/system/cpu/cpu%u/uevent%n", &cpu_id, &end) == 1
                  && end && !path[end];
    uevent |= !strcmp(path, "/sys/devices/system/cpu/uevent");
    end = 0;
    bool modalias = !strcmp(path, "/sys/devices/system/cpu/modalias")
        || (sscanf(path, "/sys/devices/system/cpu/cpu%u/modalias%n", &cpu_id, &end) == 1
            && end && !path[end]);
    if (!info && !auxv && !uevent && !modalias) return fd;
    if (flags & O_PATH) return fd;
    if ((flags & O_ACCMODE) != O_RDONLY) { close(fd); return -EACCES; }

    unsigned char* online = NULL;
    size_t bytes = 0;
    int result = 0, backing = -1, reader = -1;
    if (info) {
        result = user_cpu_online(&online, &bytes);
        if (result) goto done;
    }
    backing = syscall(SYS_memfd_create, "rvvm-cpu-view", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (backing < 0) { result = -errno; goto done; }
    if (info) {
        for (size_t i = 0; i < bytes * 8; i++) if (online[i / 8] & (1U << (i % 8))) {
            char row[512];
            int size = snprintf(row, sizeof(row),
                "processor\t: %zu\nhart\t\t: %zu\nisa\t\t: %s\n"
                "hart isa\t: %s\nuarch\t\t: rvvm\nmvendorid\t: 0x0\n"
                "marchid\t\t: 0x0\nmimpid\t\t: 0x0\n\n", i, i, USER_CPU_ISA, USER_CPU_ISA);
            if (size < 0 || (size_t)size >= sizeof(row)) { result = -EOVERFLOW; break; }
            result = user_cpu_view_write(backing, row, size);
            if (result) break;
        }
    } else if (auxv) {
        result = user_cpu_view_write(backing, auxv_data, auxv_size);
    } else {
        const char prefix[] = "DRIVER=processor\nMODALIAS=";
        if (uevent) result = user_cpu_view_write(backing, prefix, sizeof(prefix) - 1);
        if (!result) result = user_cpu_view_write(backing, USER_CPU_MODALIAS, sizeof(USER_CPU_MODALIAS) - 1);
    }
    if (result) goto done;
    if (fchmod(backing, 0444) || fcntl(backing, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) { result = -errno; goto done; }
    snprintf(descriptor, sizeof(descriptor), "/proc/thread-self/fd/%d", backing);
    reader = open(descriptor, O_RDONLY | (flags & (O_CLOEXEC | O_NONBLOCK)));
    if (reader < 0 || dup3(reader, fd, flags & O_CLOEXEC) < 0) result = -errno;
done:
    user_runtime_release(online);
    if (backing >= 0) close(backing);
    if (reader >= 0) close(reader);
    if (result) { close(fd); return result; }
    return fd;
}

static no_inline long user_cpu_open_special(long fd, unsigned long flags, dev_t device)
{
    user_fd_lock();
    long result = user_cpu_open_special_inner(fd, flags, device);
    user_fd_unlock();
    return result;
}

static no_inline long user_cpu_open_executable(long fd, unsigned long flags, int dirfd,
                                              const char* path, const struct stat* st)
{
    // The open can succeed while another thread revokes access to its pathname.
    // Never let a failed classification expose the host interpreter instead.
    char snapshot[UAPI_PATH_MAX];
    long copied = user_path_copy(snapshot, path, sizeof(snapshot));
    if (copied < 0) { close(fd); return copied; }
    if (user_exe_link(dirfd, snapshot)) return user_exe_opened(fd, flags, st);
    char descriptor[64];
    if (user_ptrace_proc_exe(dirfd, snapshot, descriptor, sizeof(descriptor))) {
        user_fd_lock();
        long replacement = errno_ret(open(descriptor, flags & ~O_NOFOLLOW));
        close(fd);
        user_fd_unlock();
        return replacement;
    }
    return fd;
}

static inline long user_cpu_opened(long fd, unsigned long flags, int dirfd, const char* path)
{
    if (fd < 0 || (flags & O_ACCMODE) == O_WRONLY) return fd;
    // Keep the large synthetic-file frame off ordinary opens. The descriptor
    // check must remain: a path outside proc/sysfs may be a symlink into either.
    struct stat st;
#if defined(__linux__) && defined(__aarch64__) && defined(__AARCH64EL__)
    if (uapi_stat_syscall(SYS_fstat, fd, (long)&st, 0, 0)) return fd;
#else
    if (fstat(fd, &st)) return fd;
#endif
    if (st.st_dev == user_host_exe.st_dev && st.st_ino == user_host_exe.st_ino) {
        return user_cpu_open_executable(fd, flags, dirfd, path, &st);
    }
    if ((!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) || major(st.st_dev)) return fd;
    return user_cpu_open_special(fd, flags, st.st_dev);
}

#endif
