/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/lsm.h>
#include <linux/mount.h>
#include <linux/reboot.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_lsm_set_self_attr
#define SYS_lsm_set_self_attr 460
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __func__, __LINE__, #x, errno); return 1; } } while (0)
#define SKIP(s) do { fprintf(stderr, "prerequisite: %s\n", s); return 77; } while (0)

/* Removing effective capabilities is irreversible for these short probes.
 * In particular, no reboot call below can reach a valid reboot operation. */
static int no_capabilities(void)
{
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2] = {{0}, {0}};
    CHECK(!syscall(SYS_capset, &h, d));
    CHECK(!syscall(SYS_capget, &h, d));
    CHECK(!d[0].effective && !d[1].effective);
    return 0;
}
static int privileged_errors(unsigned nr, uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3)
{
    CHECK(!no_capabilities());
    errno = 0;
    long ret = syscall(nr, a0, a1, a2, a3);
    if (ret < 0 && errno == ENOSYS) SKIP("host syscall/configuration unavailable");
    CHECK(ret == -1 && errno == EPERM);
    return 0;
}
static int vhangup_permission(void) { return privileged_errors(SYS_vhangup, 0, 0, 0, 0); }
static int vhangup_private_pty(void)
{
    /* The runner starts a new session; take only a newly allocated private
     * PTY as its controlling terminal, never an inherited terminal. */
    CHECK(getsid(0) == getpid() || setsid() >= 0);
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC); CHECK(master >= 0);
    CHECK(!grantpt(master) && !unlockpt(master));
    char* path = ptsname(master); CHECK(path);
    int slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC); CHECK(slave >= 0);
    CHECK(!ioctl(slave, TIOCSCTTY, 0));
    CHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR);
    if (syscall(SYS_vhangup)) {
        if (errno == EPERM) SKIP("CAP_SYS_TTY_CONFIG unavailable");
        return 1;
    }
    char c; CHECK(read(slave, &c, 1) == 0);
    close(slave); close(master); return 0;
}
static int accounting_permission(void) { return privileged_errors(SYS_acct, (uintptr_t)"accounting", 0, 0, 0); }
static int module_permission(void) { return privileged_errors(SYS_delete_module, (uintptr_t)"rvvm_no_such_module", O_NONBLOCK, 0, 0); }
static int reboot_rejected(void)
{
    /* Deliberately invalid magic AND no CAP_SYS_BOOT, even under sudo. */
    return privileged_errors(SYS_reboot, 0, 0, LINUX_REBOOT_CMD_RESTART, 0);
}
static int time_permission(void)
{
    struct timeval tv = {.tv_sec = 1};
    return privileged_errors(SYS_settimeofday, (uintptr_t)&tv, 0, 0, 0);
}
static int swapon_permission(void) { return privileged_errors(SYS_swapon, (uintptr_t)"rvvm_no_such_swap", 0, 0, 0); }
static int swapoff_permission(void) { return privileged_errors(SYS_swapoff, (uintptr_t)"rvvm_no_such_swap", 0, 0, 0); }
static int permission_before_path(void)
{
    CHECK(!no_capabilities());
    const unsigned calls[] = {SYS_acct, SYS_swapon, SYS_swapoff, SYS_pivot_root};
    for (unsigned i = 0; i < sizeof(calls)/sizeof(*calls); ++i) {
        errno = 0; long ret = syscall(calls[i], (void*)1, (void*)1, 0, 0);
        if (ret < 0 && errno == ENOSYS && calls[i] == SYS_acct) continue;
        CHECK(ret == -1 && errno == EPERM);
    }
    return 0;
}
static int lsm_set_errors(void)
{
    struct lsm_ctx ctx = {.id = LSM_ID_SELINUX, .len = sizeof(ctx)};
    long ret = syscall(SYS_lsm_set_self_attr, LSM_ATTR_CURRENT, &ctx, sizeof(ctx), UINT32_MAX);
    if (ret < 0 && errno == ENOSYS) SKIP("host LSM setting syscall unavailable");
    CHECK(ret == -1 && errno == EINVAL);
    return 0;
}
static int namespace_setup(void)
{
    if (unshare(CLONE_NEWNS)) {
        if (errno == EPERM || errno == ENOSYS) return 77;
        return 1;
    }
    CHECK(!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    return 0;
}
static int mounts_setup(void)
{
    int ret = namespace_setup();
    if (ret) return ret;
    CHECK(!mkdir("mnt", 0700)); CHECK(!mkdir("other", 0700));
    CHECK(!mount("none", "mnt", "tmpfs", 0, "size=1m"));
    return 0;
}
#define MOUNTS() do { int r = mounts_setup(); if (r == 77) SKIP("private mount namespace denied"); CHECK(!r); } while (0)
static int open_tree_clone(void)
{
    MOUNTS();
    int fd = syscall(SYS_open_tree, AT_FDCWD, "mnt", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    if (fd < 0 && errno == ENOSYS) SKIP("host open_tree unavailable");
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    struct stat a, b; CHECK(!stat("mnt", &a) && !fstat(fd, &b));
    CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
    close(fd); return 0;
}
static int move_mount_clone(void)
{
    MOUNTS();
    int fd = syscall(SYS_open_tree, AT_FDCWD, "mnt", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    CHECK(fd >= 0);
    long ret = syscall(SYS_move_mount, fd, "", AT_FDCWD, "other", MOVE_MOUNT_F_EMPTY_PATH);
    if (ret < 0 && errno == ENOSYS) { close(fd); SKIP("host move_mount unavailable"); }
    CHECK(!ret);
    struct stat a, b; CHECK(!stat("mnt", &a) && !stat("other", &b));
    CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
    close(fd); return 0;
}
static int new_context(void)
{
    return syscall(SYS_fsopen, "tmpfs", FSOPEN_CLOEXEC);
}
static int fsopen_context(void)
{
    MOUNTS(); int fd = new_context();
    if (fd < 0 && errno == ENOSYS) SKIP("host fsopen unavailable");
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    close(fd);
    errno = 0; CHECK(syscall(SYS_fsopen, (void*)1, 0) == -1 && errno == EFAULT);
    return 0;
}
static int fsconfig_parameters(void)
{
    MOUNTS(); int fd = new_context(); CHECK(fd >= 0);
    CHECK(!syscall(SYS_fsconfig, fd, FSCONFIG_SET_STRING, "size", "1048576", 0));
    errno = 0; CHECK(syscall(SYS_fsconfig, fd, FSCONFIG_SET_STRING, "size", (void*)1, 0) == -1 && errno == EFAULT);
    errno = 0; CHECK(syscall(SYS_fsconfig, fd, FSCONFIG_SET_FD, "source", NULL, 1024) == -1 && errno == EBADF);
    errno = 0; CHECK(syscall(SYS_fsconfig, 1024, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1 && errno == EBADF);
    errno = 0; CHECK(syscall(SYS_fsconfig, 1024, UINT32_MAX, NULL, NULL, 0) == -1 && errno == EOPNOTSUPP);
    CHECK(!syscall(SYS_fsconfig, fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0));
    close(fd); return 0;
}
static int fsmount_context(void)
{
    MOUNTS(); int fd = new_context(); CHECK(fd >= 0);
    CHECK(!syscall(SYS_fsconfig, fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0));
    int mfd = syscall(SYS_fsmount, fd, FSMOUNT_CLOEXEC, 0);
    CHECK(mfd >= 0 && fcntl(mfd, F_GETFD) == FD_CLOEXEC);
    CHECK(!syscall(SYS_move_mount, mfd, "", AT_FDCWD, "other", MOVE_MOUNT_F_EMPTY_PATH));
    int file = open("other/test", O_CREAT | O_RDWR, 0600); CHECK(file >= 0);
    CHECK(write(file, "data", 4) == 4); close(file); close(mfd); close(fd);
    return 0;
}
static int fspick_context(void)
{
    MOUNTS(); int fd = syscall(SYS_fspick, AT_FDCWD, "mnt", FSPICK_CLOEXEC);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK(!syscall(SYS_fsconfig, fd, FSCONFIG_SET_STRING, "size", "2097152", 0));
    CHECK(!syscall(SYS_fsconfig, fd, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0));
    close(fd); return 0;
}
static int mount_attributes(void)
{
    MOUNTS();
    struct mount_attr attr = {.attr_set = MOUNT_ATTR_RDONLY};
    long ret = syscall(SYS_mount_setattr, AT_FDCWD, "mnt", 0, &attr, sizeof(attr));
    if (ret < 0 && errno == ENOSYS) SKIP("host mount_setattr unavailable");
    CHECK(!ret);
    errno = 0; CHECK(open("mnt/test", O_CREAT | O_RDWR, 0600) == -1 && errno == EROFS);
    attr.attr_set = 0; attr.attr_clr = MOUNT_ATTR_RDONLY;
    CHECK(!syscall(SYS_mount_setattr, AT_FDCWD, "mnt", 0, &attr, sizeof(attr)));
    int fd = open("mnt/test", O_CREAT | O_RDWR, 0600); CHECK(fd >= 0); close(fd);
    return 0;
}
static int mount_attribute_errors(void)
{
    MOUNTS();
    struct { struct mount_attr attr; uint64_t tail; } request = {
        .attr = {.attr_set = MOUNT_ATTR_IDMAP, .userns_fd = 1024},
    };
    long ret = syscall(SYS_mount_setattr, AT_FDCWD, "mnt", 0, &request, sizeof(request.attr));
    if (ret < 0 && errno == ENOSYS) SKIP("host mount_setattr unavailable");
    CHECK(ret == -1 && errno == EBADF);
    request.attr.userns_fd = 64; errno = 0;
    CHECK(syscall(SYS_mount_setattr, AT_FDCWD, "mnt", 0, &request, sizeof(request.attr)) == -1 && errno == EBADF);
    request.tail = 1; errno = 0;
    CHECK(syscall(SYS_mount_setattr, AT_FDCWD, "mnt", 0, &request, sizeof(request)) == -1 && errno == E2BIG);
    memset(&request, 0, sizeof(request));
    CHECK(!syscall(SYS_mount_setattr, 1024, (void*)1, 0, &request, sizeof(request)));
    errno = 0;
    CHECK(syscall(SYS_mount_setattr, AT_FDCWD, (void*)1, UINT32_MAX, &request, sizeof(request)) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(syscall(SYS_mount_setattr, AT_FDCWD, "mnt", 0, (void*)1, sizeof(request.attr)) == -1 && errno == EFAULT);
    return 0;
}
static int pivot_root_private(void)
{
    MOUNTS(); CHECK(!mkdir("mnt/old", 0700));
    struct stat expected, actual; CHECK(!stat("mnt", &expected));
    CHECK(!syscall(SYS_pivot_root, "mnt", "mnt/old"));
    CHECK(!chdir("/") && !stat("/", &actual));
    CHECK(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino);
    return 0;
}
static int setns_uts(void)
{
    int fd = open("/proc/self/ns/uts", O_RDONLY | O_CLOEXEC); CHECK(fd >= 0);
    struct utsname before, after; CHECK(!uname(&before));
    if (unshare(CLONE_NEWUTS)) { close(fd); if (errno == EPERM || errno == ENOSYS) SKIP("UTS namespaces denied"); return 1; }
    CHECK(!sethostname("rvvm-private", 12));
    CHECK(!syscall(SYS_setns, fd, CLONE_NEWUTS)); CHECK(!uname(&after));
    CHECK(!strcmp(before.nodename, after.nodename)); close(fd);
    errno = 0; CHECK(syscall(SYS_setns, 1024, 0) == -1 && errno == EBADF);
    return 0;
}
static int descriptor_errors(void)
{
    const int closed[] = {64, 1024};
    for (unsigned i = 0; i < sizeof(closed)/sizeof(*closed); ++i) {
        int fd = closed[i]; CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
        errno = 0; CHECK(syscall(SYS_fsconfig, fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) == -1 && errno == EBADF);
        errno = 0; long ret = syscall(SYS_fsmount, fd, 0, 0);
        if (ret < 0 && errno == EPERM) SKIP("mount capability unavailable");
        CHECK(ret == -1 && errno == EBADF);
        errno = 0; CHECK(syscall(SYS_setns, fd, 0) == -1 && errno == EBADF);
        errno = 0; CHECK(syscall(SYS_open_tree, fd, "", AT_EMPTY_PATH) == -1 && errno == EBADF);
        errno = 0; CHECK(syscall(SYS_fspick, fd, "", FSPICK_EMPTY_PATH) == -1 && errno == EBADF);
        errno = 0; CHECK(syscall(SYS_move_mount, fd, "", AT_FDCWD, ".", MOVE_MOUNT_F_EMPTY_PATH) == -1 && errno == EBADF);
    }
    return 0;
}
static int relocated_descriptors(void)
{
    MOUNTS();
    int file = open("file", O_CREAT | O_RDWR, 0600); CHECK(file >= 0);
    CHECK(dup2(file, 64) == 64);
    CHECK(dup2(file, 1024) == 1024);
    close(file); close(64); close(1024);
    int context = new_context(); CHECK(context >= 0 && dup2(context, 1024) == 1024);
    CHECK(dup2(context, 64) == 64);
    CHECK(!syscall(SYS_fsconfig, 64, FSCONFIG_SET_STRING, "size", "1048576", 0));
    CHECK(!syscall(SYS_fsconfig, 1024, FSCONFIG_CMD_CREATE, NULL, NULL, 0));
    int mfd = syscall(SYS_fsmount, 1024, FSMOUNT_CLOEXEC, 0); CHECK(mfd >= 0);
    close(mfd); close(context); close(64); close(1024);
    return 0;
}
static struct { const char* name; int (*run)(void); } cases[] = {
    {"vhangup-permission", vhangup_permission}, {"vhangup-private-pty", vhangup_private_pty},
    {"accounting-permission", accounting_permission},
    {"module-permission", module_permission}, {"reboot-rejected", reboot_rejected},
    {"time-permission", time_permission}, {"swapon-permission", swapon_permission},
    {"swapoff-permission", swapoff_permission}, {"lsm-set-errors", lsm_set_errors},
    {"permission-before-path", permission_before_path},
    {"open-tree-clone", open_tree_clone}, {"move-mount-clone", move_mount_clone},
    {"fsopen-context", fsopen_context}, {"fsconfig-parameters", fsconfig_parameters},
    {"fsmount-context", fsmount_context}, {"fspick-context", fspick_context},
    {"mount-attributes", mount_attributes}, {"mount-attribute-errors", mount_attribute_errors},
    {"pivot-root-private", pivot_root_private},
    {"setns-uts", setns_uts},
    {"descriptor-errors", descriptor_errors},
    {"relocated-descriptors", relocated_descriptors},
};
int main(int argc, char** argv)
{
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) puts(cases[i].name);
        return 0;
    }
    if (argc == 2) for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i)
        if (!strcmp(argv[1], cases[i].name)) {
            struct rlimit limit;
            CHECK(!getrlimit(RLIMIT_NOFILE, &limit));
            if (limit.rlim_cur <= 1024) {
                if (limit.rlim_max <= 1024) SKIP("hard descriptor limit below probe requirement");
                limit.rlim_cur = 1025;
                CHECK(!setrlimit(RLIMIT_NOFILE, &limit));
            }
            return cases[i].run();
        }
    return 2;
}
