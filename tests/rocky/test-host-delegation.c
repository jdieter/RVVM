/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <linux/lsm.h>
#include <linux/mount.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/quota.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Recent syscall numbers are shared by the supported LP64 Linux hosts. */
#ifndef SYS_quotactl_fd
#define SYS_quotactl_fd 443
#endif
#ifndef SYS_statmount
#define SYS_statmount 457
#endif
#ifndef SYS_listmount
#define SYS_listmount 458
#endif
#ifndef SYS_lsm_get_self_attr
#define SYS_lsm_get_self_attr 459
#endif
#ifndef SYS_lsm_list_modules
#define SYS_lsm_list_modules 461
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d)\n", __func__, __LINE__, #x, errno); return 1; } } while (0)
#define SKIP(s) do { fprintf(stderr, "prerequisite: %s\n", s); return 77; } while (0)
static int unavailable(void) { return errno == ENOSYS || errno == EPERM || errno == EACCES; }
static long key(void)
{
    return syscall(SYS_add_key, "user", "rvvm-host-delegation", "payload", 7, KEY_SPEC_THREAD_KEYRING);
}
static int add_key_payload(void)
{
    long id = key();
    if (id < 0 && unavailable()) SKIP("host keys denied/unavailable");
    CHECK(id > 0);
    char data[16] = {0};
    long n = syscall(SYS_keyctl, KEYCTL_READ, id, data, sizeof(data), 0);
    int saved = errno; syscall(SYS_keyctl, KEYCTL_REVOKE, id, 0, 0, 0); errno = saved;
    CHECK(n == 7 && !memcmp(data, "payload", 7)); return 0;
}
static int request_existing_key(void)
{
    long id = key();
    if (id < 0 && unavailable()) SKIP("host keys denied/unavailable");
    CHECK(id > 0);
    long found = syscall(SYS_request_key, "user", "rvvm-host-delegation", NULL, 0);
    int saved = errno; syscall(SYS_keyctl, KEYCTL_REVOKE, id, 0, 0, 0); errno = saved;
    CHECK(found == id); return 0;
}
static int keyctl_commands(void)
{
    long id = syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_THREAD_KEYRING, 1, 0, 0);
    if (id < 0 && unavailable()) SKIP("host keys denied/unavailable");
    CHECK(id > 0);
    errno = 0; CHECK(syscall(SYS_keyctl, UINT32_MAX, 0, 0, 0, 0) == -1 && errno == EOPNOTSUPP);
    return 0;
}
static int keyctl_buffer_fault(void)
{
    long id = key();
    if (id < 0 && unavailable()) SKIP("host keys denied/unavailable");
    CHECK(id > 0);
    errno = 0;
    long ret = syscall(SYS_keyctl, KEYCTL_READ, id, (void*)1024, 7, 0);
    int saved = errno; syscall(SYS_keyctl, KEYCTL_REVOKE, id, 0, 0, 0); errno = saved;
    CHECK(ret == -1 && errno == EFAULT); return 0;
}
static int keyctl_watch_descriptor(void)
{
    /* This descriptor is closed in the guest, regardless of any hidden pin. */
    CHECK(fcntl(1024, F_GETFD) == -1 && errno == EBADF);
    long id = syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_THREAD_KEYRING, 1, 0, 0);
    if (id < 0 && unavailable()) SKIP("host keys denied/unavailable");
    CHECK(id > 0);
    errno = 0;
    long ret = syscall(SYS_keyctl, KEYCTL_WATCH_KEY, id, -1, 0, 0);
    if (ret < 0 && (unavailable() || errno == EOPNOTSUPP)) SKIP("host key watches unavailable");
    CHECK(ret == -1);
    int expected = errno;
    errno = 0; ret = syscall(SYS_keyctl, KEYCTL_WATCH_KEY, id, 1024, 0, 0);
    CHECK(ret == -1 && errno == expected); return 0;
}
static int quota_path_query(void)
{
    unsigned format;
    errno = 0;
    long ret = syscall(SYS_quotactl, QCMD(Q_GETFMT, USRQUOTA), "/rvvm-no-such-block-device", 0, &format);
    if (ret < 0 && unavailable()) SKIP("host quota query denied/unavailable");
    CHECK(ret == -1 && errno == ENOENT);
    errno = 0;
    CHECK(syscall(SYS_quotactl, QCMD(Q_GETFMT, USRQUOTA), (void*)1, 0, &format) == -1 && errno == EFAULT);
    char longpath[4097]; memset(longpath, 'x', sizeof(longpath)); longpath[0] = '/'; longpath[4096] = 0;
    errno = 0;
    CHECK(syscall(SYS_quotactl, QCMD(Q_GETFMT, USRQUOTA), longpath, 0, &format) == -1 && errno == ENAMETOOLONG);
    return 0;
}
static int quota_fd_query(void)
{
    unsigned format;
    const int fds[] = {-1, 64, 1024};
    for (unsigned i = 0; i < sizeof(fds)/sizeof(*fds); ++i) {
        CHECK(fcntl(fds[i], F_GETFD) == -1 && errno == EBADF);
        errno = 0;
        long ret = syscall(SYS_quotactl_fd, fds[i], QCMD(Q_GETFMT, USRQUOTA), 0, &format);
        if (ret < 0 && errno == ENOSYS) SKIP("host quotactl_fd unavailable");
        CHECK(ret == -1 && errno == EBADF);
    }
    return 0;
}
static int list_mounts(void)
{
    struct mnt_id_req req = {.size = MNT_ID_REQ_SIZE_VER0, .mnt_id = LSMT_ROOT};
    uint64_t ids[64];
    long n = syscall(SYS_listmount, &req, ids, 64, 0);
    if (n < 0 && unavailable()) SKIP("host listmount denied/unavailable");
    CHECK(n > 0 && n <= 64);
    for (long i = 0; i < n; ++i) { CHECK(ids[i]); for (long j = 0; j < i; ++j) CHECK(ids[i] != ids[j]); }
    return 0;
}
static int stat_mount(void)
{
    struct mnt_id_req req = {.size = MNT_ID_REQ_SIZE_VER0, .mnt_id = LSMT_ROOT};
    uint64_t id;
    long n = syscall(SYS_listmount, &req, &id, 1, 0);
    if (n < 0 && unavailable()) SKIP("host mount queries denied/unavailable");
    CHECK(n == 1);
    req.mnt_id = id; req.param = STATMOUNT_MNT_BASIC;
    struct statmount result;
    CHECK(!syscall(SYS_statmount, &req, &result, sizeof(result), 0));
    CHECK((result.mask & STATMOUNT_MNT_BASIC) && result.mnt_id == id && result.mnt_id_old);
    errno = 0;
    CHECK(syscall(SYS_statmount, &req, (void*)1, sizeof(result), 0) == -1 && errno == EFAULT);
    return 0;
}
static int lsm_modules(void)
{
    uint64_t ids[64]; uint32_t size = sizeof(ids);
    long n = syscall(SYS_lsm_list_modules, ids, &size, 0);
    if (n < 0 && unavailable()) SKIP("host LSM interface denied/unavailable");
    CHECK(n > 0 && n <= 64 && size == (uint32_t)n * sizeof(uint64_t));
    for (long i = 0; i < n; ++i) CHECK(ids[i] >= LSM_ID_CAPABILITY);
    errno = 0;
    CHECK(syscall(SYS_lsm_list_modules, ids, &size, UINT32_MAX) == -1 && errno == EINVAL);
    return 0;
}
static int lsm_current(void)
{
    union { struct lsm_ctx alignment; char data[4096]; } buffer;
    uint32_t size = sizeof(buffer);
    long n = syscall(SYS_lsm_get_self_attr, LSM_ATTR_CURRENT, &buffer, &size, 0);
    if (n < 0 && unavailable()) SKIP("host LSM contexts denied/unavailable");
    CHECK(n >= 0 && size <= sizeof(buffer));
    size_t off = 0;
    for (long i = 0; i < n; ++i) {
        CHECK(size - off >= sizeof(struct lsm_ctx));
        struct lsm_ctx* ctx = (void*)(buffer.data + off);
        CHECK(ctx->len >= sizeof(*ctx) && ctx->len <= size - off);
        CHECK(ctx->ctx_len <= ctx->len - sizeof(*ctx) && ctx->id >= LSM_ID_CAPABILITY);
        off += ctx->len;
    }
    errno = 0;
    CHECK(syscall(SYS_lsm_get_self_attr, LSM_ATTR_CURRENT, &buffer, &size, UINT32_MAX) == -1 && errno == EINVAL);
    return 0;
}
static struct { const char* name; int (*run)(void); } cases[] = {
    {"add-key-payload", add_key_payload}, {"request-existing-key", request_existing_key},
    {"keyctl-commands", keyctl_commands}, {"quota-path-query", quota_path_query},
    {"keyctl-buffer-fault", keyctl_buffer_fault}, {"keyctl-watch-descriptor", keyctl_watch_descriptor},
    {"quota-fd-query", quota_fd_query}, {"list-mounts", list_mounts},
    {"stat-mount", stat_mount}, {"lsm-modules", lsm_modules}, {"lsm-current", lsm_current},
};
int main(int argc, char** argv)
{
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i) puts(cases[i].name);
        return 0;
    }
    if (argc == 2) for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); ++i)
        if (!strcmp(argv[1], cases[i].name)) return cases[i].run();
    return 2;
}
