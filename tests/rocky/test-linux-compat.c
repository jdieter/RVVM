/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/futex.h>
#include <linux/io_uring.h>
#include <linux/landlock.h>
#include <linux/rseq.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Each named case runs in its own process. Failed assertions never turn an
 * unimplemented interface into a pass; 77 means a native prerequisite is absent. */
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s (errno=%d: %s)\n", \
    __func__, __LINE__, #x, errno, strerror(errno)); return 1; } } while (0)
#define SKIP(s) do { fprintf(stderr, "prerequisite: %s\n", s); return 77; } while (0)
static int unsupported(void) { return errno == ENOSYS || errno == EPERM || errno == EOPNOTSUPP; }
static int reaped(pid_t pid)
{
    int status;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}
static int tempfile(void)
{
    char path[] = "/tmp/rvvm-compat.XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0) unlink(path);
    return fd;
}
static int clone3_fork(void)
{
    struct clone_args args = {.exit_signal = SIGCHLD};
    pid_t pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0 && unsupported()) SKIP("host clone3 unavailable");
    CHECK(pid >= 0);
    if (!pid) _exit(0);
    return reaped(pid);
}
static void handler(int signo) { (void)signo; }
static int clone3_clear_sighand(void)
{
    CHECK(signal(SIGUSR1, handler) != SIG_ERR);
    struct clone_args args = {.flags = CLONE_CLEAR_SIGHAND, .exit_signal = SIGCHLD};
    pid_t pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0 && unsupported()) SKIP("host clone3 unavailable");
    CHECK(pid >= 0);
    if (!pid) { struct sigaction sa; _exit(sigaction(SIGUSR1, NULL, &sa) || sa.sa_handler != SIG_DFL); }
    return reaped(pid);
}
static int clone3_pidfd(void)
{
    int fd = -1;
    struct clone_args args = {.flags = CLONE_PIDFD, .pidfd = (uintptr_t)&fd, .exit_signal = SIGCHLD};
    pid_t pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0 && unsupported()) SKIP("host clone3 unavailable");
    CHECK(pid >= 0);
    if (!pid) _exit(0);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) >= 0);
    CHECK(!reaped(pid)); close(fd); return 0;
}
static int clone3_size(void)
{
    struct clone_args args = {0};
    errno = 0;
    CHECK(syscall(SYS_clone3, &args, 1) == -1);
    if (errno == ENOSYS) SKIP("host clone3 unavailable");
    CHECK(errno == EINVAL);
    return 0;
}
static int clone_child(void* p) { *(int*)p = 42; return 0; }
static int clone_fs_child(void* p) { (void)p; umask(0077); return 0; }
static int clone_modes(int flags, int fs)
{
    int* value = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(value != MAP_FAILED && stack != MAP_FAILED);
    umask(0022);
    pid_t pid = clone(fs ? clone_fs_child : clone_child, (char*)stack + 65536, flags | SIGCHLD, value);
    CHECK(pid >= 0 && !reaped(pid));
    if (fs) CHECK(umask(0022) == 0077);
    else CHECK(*value == 42);
    return 0;
}
static int clone_vm_process(void) { return clone_modes(CLONE_VM, 0); }
static int clone_fs_process(void) { return clone_modes(CLONE_FS, 1); }
static int sem_child(void* arg)
{
    struct sembuf op = {0, 1, SEM_UNDO};
    return semop(*(int*)arg, &op, 1) != 0;
}
static int clone_sysvsem(void)
{
    int sem = semget(IPC_PRIVATE, 1, 0600);
    if (sem < 0 && unsupported()) SKIP("host SysV semaphores unavailable");
    CHECK(sem >= 0);
    void* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) { semctl(sem, 0, IPC_RMID); CHECK(0); }
    pid_t pid = clone(sem_child, (char*)stack + 65536, CLONE_SYSVSEM | SIGCHLD, &sem);
    int result = pid < 0 ? 1 : reaped(pid);
    int value = semctl(sem, 0, GETVAL); CHECK(!semctl(sem, 0, IPC_RMID));
    CHECK(!result && value == 1); return 0;
}
static int clone_parent(void)
{
    pid_t parent = getpid();
    pid_t middle = fork(); CHECK(middle >= 0);
    if (!middle) {
        pid_t child = syscall(SYS_clone, CLONE_PARENT | SIGCHLD, 0, 0, 0, 0);
        if (!child) _exit(getppid() != parent);
        _exit(child < 0);
    }
    CHECK(!reaped(middle));
    int status; CHECK(waitpid(-1, &status, 0) > 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0); return 0;
}
static int vfork_nested_child(void* unused)
{
    (void)unused;
    pid_t pid = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (!pid) syscall(SYS_exit, 0);
    return pid < 0 ? 1 : reaped(pid);
}
static int vfork_private_child(void* unused)
{
    (void)unused; int word = 0;
    return syscall(SYS_futex, &word, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) < 0;
}
static int vfork_pi_child(void* unused)
{
    (void)unused; int word = 0;
    if (syscall(SYS_futex, &word, FUTEX_LOCK_PI, 0, 0, 0, 0)) return 1;
    return syscall(SYS_futex, &word, FUTEX_UNLOCK_PI, 0, 0, 0, 0) != 0;
}
static int vfork_case(int (*fn)(void*))
{
    void* stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED);
    pid_t pid = clone(fn, (char*)stack + 65536, CLONE_VM | CLONE_VFORK | SIGCHLD, NULL);
    CHECK(pid >= 0); return reaped(pid);
}
static int vfork_nested(void) { return vfork_case(vfork_nested_child); }
static int vfork_private(void) { return vfork_case(vfork_private_child); }
static int vfork_pi(void) { return vfork_case(vfork_pi_child); }
static int proc_exe_stat(void)
{
    int fd = open("/proc/self/exe", O_RDONLY); CHECK(fd >= 0);
    struct stat a, b; CHECK(!fstat(fd, &a) && !stat("/proc/self/exe", &b));
    CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size);
    close(fd); return 0;
}
static int proc_exe_statx(void)
{
    int fd = open("/proc/self/exe", O_RDONLY); CHECK(fd >= 0);
    struct stat a; struct statx b; CHECK(!fstat(fd, &a));
    CHECK(!statx(AT_FDCWD, "/proc/self/exe", 0, STATX_BASIC_STATS, &b));
    CHECK(a.st_ino == b.stx_ino && a.st_size == (off_t)b.stx_size);
    close(fd); return 0;
}
static void* finished_thread(void* p) { return p; }
static int proc_task_view(void)
{
    /* After joining its only thread, the guest must not see a native reaper. */
    pthread_t thread; CHECK(!pthread_create(&thread, NULL, finished_thread, NULL));
    CHECK(!pthread_join(thread, NULL));
    int fd = open("/proc/self/status", O_RDONLY); CHECK(fd >= 0);
    char buf[8192]; ssize_t n = read(fd, buf, sizeof(buf) - 1); CHECK(n > 0); buf[n] = 0;
    char* line = strstr(buf, "Threads:"); CHECK(line && atoi(line + 8) == 1);
    close(fd); return 0;
}
static int mmap_shared_validate(void)
{
    int fd = tempfile(); CHECK(fd >= 0 && !ftruncate(fd, 4096));
    char* map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE, fd, 0);
    CHECK(map != MAP_FAILED); *map = 'Q'; char c = 0;
    CHECK(pread(fd, &c, 1, 0) == 1 && c == 'Q'); return 0;
}
static int mmap_validate_unknown(void)
{
    int fd = tempfile(); CHECK(fd >= 0 && !ftruncate(fd, 4096));
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_SHARED_VALIDATE | 0x200000, fd, 0) == MAP_FAILED);
    CHECK(errno == EOPNOTSUPP); return 0;
}
static int mmap_populate(void)
{
    size_t page = sysconf(_SC_PAGESIZE); unsigned char resident[8] = {0};
    void* map = mmap(NULL, page * 8, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    CHECK(map != MAP_FAILED && !mincore(map, page * 8, resident));
    for (int i = 0; i < 8; ++i) CHECK(resident[i] & 1);
    return 0;
}
static int mapping_flag(const char* flag, int flags)
{
    size_t page = sysconf(_SC_PAGESIZE);
    void* map = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | flags, -1, 0);
    if (map == MAP_FAILED && (errno == EPERM || errno == EAGAIN)) SKIP("host mapping privilege/limit");
    CHECK(map != MAP_FAILED);
    FILE* f = fopen("/proc/self/smaps", "re"); CHECK(f);
    char* line = NULL; size_t cap = 0; int selected = 0, found = 0;
    while (getline(&line, &cap, f) >= 0) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) selected = (uintptr_t)map >= start && (uintptr_t)map < end;
        if (selected && !strncmp(line, "VmFlags:", 8)) { found = strstr(line + 8, flag) != NULL; break; }
    }
    free(line); fclose(f); CHECK(found); return 0;
}
static int mmap_locked(void) { return mapping_flag(" lo ", MAP_LOCKED); }
static int mmap_growsdown(void) { return mapping_flag(" gd ", MAP_GROWSDOWN); }
static int memory_budget(void)
{
    struct rlimit limit = {64 * 1024 * 1024, 64 * 1024 * 1024};
    CHECK(!setrlimit(RLIMIT_AS, &limit));
    void* map = mmap(NULL, 32 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(map != MAP_FAILED); memset(map, 1, 32 * 1024 * 1024); return 0;
}
static int filesystem_id(int group)
{
    if (geteuid() != 0) SKIP("root required to change filesystem identity");
    /* Permit directory traversal so the file's identity decides access. */
    CHECK(!chmod(".", 0755));
    char path[] = "./fsidentity.XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0);
    uid_t uid = setfsuid(-1); gid_t gid = setfsgid(-1);
    if (group) {
        CHECK(!fchown(fd, 60000, 60001) && !fchmod(fd, 0640)); close(fd);
        setfsuid(60002); CHECK(setfsuid(-1) == 60002);
        setfsgid(60001); CHECK(setfsgid(-1) == 60001);
        fd = open(path, O_RDONLY); CHECK(fd >= 0); close(fd);
        setfsgid(gid); errno = 0;
        CHECK(open(path, O_RDONLY) == -1 && errno == EACCES);
        setfsuid(uid);
    } else {
        close(fd); setfsuid(60002); CHECK(setfsuid(-1) == 60002);
        errno = 0; CHECK(open(path, O_RDONLY) == -1 && errno == EACCES);
        setfsuid(uid); fd = open(path, O_RDONLY); CHECK(fd >= 0); close(fd);
    }
    CHECK(!unlink(path));
    return 0;
}
static int fsuid_change(void) { return filesystem_id(0); }
static int fsgid_change(void) { return filesystem_id(1); }
static int seccomp_filter(int via_prctl)
{
    struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {4, insns};
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    int ret = via_prctl ? prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)
                        : syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &filter);
    if (ret && (errno == ENOSYS || errno == EINVAL)) SKIP("host seccomp unavailable");
    CHECK(!ret); errno = 0; CHECK(syscall(SYS_getpid) == -1 && errno == EACCES);
    CHECK(syscall(SYS_getppid) > 0); return 0;
}
static int seccomp_syscall(void) { return seccomp_filter(0); }
static int seccomp_prctl(void) { return seccomp_filter(1); }
static int landlock_deny(void)
{
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0 && unsupported()) SKIP("host Landlock unavailable");
    CHECK(abi > 0);
    char path[] = "/tmp/rvvm-landlock.XXXXXX";
    int file = mkstemp(path); CHECK(file >= 0); close(file);
    /* The runner gives each case a disposable working directory. */
    CHECK(!unlink(path));
    snprintf(path, sizeof(path), "./landlock-denied");
    struct landlock_ruleset_attr attr = {.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE};
    int rules = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0); CHECK(rules >= 0);
    CHECK(!mkdir("allowed", 0700));
    int directory = open("allowed", O_PATH | O_DIRECTORY); CHECK(directory >= 0);
    struct landlock_path_beneath_attr rule = {.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE, .parent_fd = directory};
    CHECK(!syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH, &rule, 0)); close(directory);
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    CHECK(!syscall(SYS_landlock_restrict_self, rules, 0)); close(rules);
    errno = 0; CHECK(open(path, O_WRONLY | O_CREAT, 0600) == -1 && errno == EACCES);
    file = open("allowed/file", O_WRONLY | O_CREAT, 0600); CHECK(file >= 0);
    CHECK(write(file, "ok", 2) == 2); close(file); return 0;
}
static int rseq_register(void)
{
    static struct rseq area __attribute__((aligned(32)));
    /* Probe the original ABI, not optional fields added by newer headers. */
    int ret = syscall(SYS_rseq, &area, 32, 0, 0x53053053);
    if (ret && errno == ENOSYS) SKIP("host rseq unavailable");
    CHECK(!ret); CHECK(area.cpu_id < 1024 * 1024);
    CHECK(!syscall(SYS_rseq, &area, 32, RSEQ_FLAG_UNREGISTER, 0x53053053)); return 0;
}
static int io_uring_nop(void)
{
    struct io_uring_params p = {0};
    int fd = syscall(SYS_io_uring_setup, 2, &p);
    if (fd < 0 && unsupported()) SKIP("host io_uring unavailable");
    CHECK(fd >= 0);
    struct io_uring_probe* probe = calloc(1, sizeof(*probe) + 32 * sizeof(struct io_uring_probe_op)); CHECK(probe);
    CHECK(!syscall(SYS_io_uring_register, fd, IORING_REGISTER_PROBE, probe, 32));
    CHECK(probe->ops_len && probe->ops[IORING_OP_NOP].flags & IO_URING_OP_SUPPORTED); free(probe);
    size_t a = p.sq_off.array + p.sq_entries * sizeof(unsigned), b = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    size_t size = a > b ? a : b;
    char* sq = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_SQ_RING);
    CHECK(sq != MAP_FAILED);
    char* cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq : mmap(NULL, b, PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_CQ_RING);
    struct io_uring_sqe* entry = mmap(NULL, p.sq_entries * sizeof(*entry), PROT_READ | PROT_WRITE, MAP_SHARED, fd, IORING_OFF_SQES);
    CHECK(cq != MAP_FAILED && entry != MAP_FAILED);
    entry[0].opcode = IORING_OP_NOP; entry[0].user_data = 0x12345678;
    *(unsigned*)(sq + p.sq_off.array) = 0;
    __atomic_store_n((unsigned*)(sq + p.sq_off.tail), 1, __ATOMIC_RELEASE);
    CHECK(syscall(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) == 1);
    CHECK(__atomic_load_n((unsigned*)(cq + p.cq_off.tail), __ATOMIC_ACQUIRE) == 1);
    struct io_uring_cqe* result = (void*)(cq + p.cq_off.cqes);
    CHECK(result->res == 0 && result->user_data == 0x12345678); return 0;
}
static int ptrace_syscall_info(void)
{
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) { if (ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(77); raise(SIGSTOP); syscall(SYS_getpid); _exit(0); }
    int status; CHECK(waitpid(pid, &status, 0) == pid);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77) SKIP("host tracing denied");
    CHECK(WIFSTOPPED(status));
    CHECK(!ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD));
    CHECK(!ptrace(PTRACE_SYSCALL, pid, 0, 0)); CHECK(waitpid(pid, &status, 0) == pid);
    struct __ptrace_syscall_info info = {0};
    long n = ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info);
    int saved = errno;
    int valid = n > 0 && info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr == SYS_getpid;
#if defined(__riscv)
    valid &= info.arch == AUDIT_ARCH_RISCV64;
#elif defined(__aarch64__)
    valid &= info.arch == AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    valid &= info.arch == AUDIT_ARCH_X86_64;
#endif
    if (valid) {
        valid = !ptrace(PTRACE_SYSCALL, pid, 0, 0) && waitpid(pid, &status, 0) == pid;
        if (valid) {
            n = ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info);
            valid = n > 0 && info.op == PTRACE_SYSCALL_INFO_EXIT && info.exit.rval == pid && !info.exit.is_error;
        }
    }
    kill(pid, SIGKILL); waitpid(pid, &status, 0); errno = saved;
    CHECK(valid); return 0;
}
static int ioctl_pipe_bytes(void)
{
    int fds[2], n = -1; CHECK(!pipe(fds));
    CHECK(write(fds[1], "abc", 3) == 3);
    CHECK(!ioctl(fds[0], FIONREAD, &n) && n == 3);
    errno = 0; CHECK(syscall(SYS_ioctl, fds[0], FIONREAD, (void*)1) == -1 && errno == EFAULT);
    close(fds[0]); close(fds[1]); return 0;
}
static int syscall_bad_buffer(void)
{
    int fd = tempfile(); CHECK(fd >= 0);
    CHECK(write(fd, "abc", 3) == 3 && lseek(fd, 0, SEEK_SET) == 0);
    errno = 0; CHECK(syscall(SYS_read, fd, (void*)1, 3) == -1 && errno == EFAULT);
    close(fd); return 0;
}
static volatile sig_atomic_t signal_seen;
static uintptr_t alt_low, alt_high;
static void alt_handler(int signo)
{
    char local;
    signal_seen = signo == SIGUSR1 && (uintptr_t)&local >= alt_low && (uintptr_t)&local < alt_high;
}
static int signal_altstack(void)
{
    stack_t stack = {.ss_sp = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), .ss_size = 65536};
    CHECK(stack.ss_sp != MAP_FAILED && !sigaltstack(&stack, NULL));
    alt_low = (uintptr_t)stack.ss_sp; alt_high = alt_low + stack.ss_size;
    struct sigaction sa = {.sa_handler = alt_handler, .sa_flags = SA_ONSTACK};
    sigemptyset(&sa.sa_mask); CHECK(!sigaction(SIGUSR1, &sa, NULL));
    CHECK(!raise(SIGUSR1) && signal_seen); return 0;
}
static unsigned atomic_value;
static void* atomic_worker(void* unused)
{
    (void)unused;
    for (unsigned i = 0; i < 10000; ++i) __atomic_fetch_add(&atomic_value, 1, __ATOMIC_SEQ_CST);
    return NULL;
}
static int atomic_threads(void)
{
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; ++i) CHECK(!pthread_create(&threads[i], NULL, atomic_worker, NULL));
    for (unsigned i = 0; i < 4; ++i) CHECK(!pthread_join(threads[i], NULL));
    CHECK(atomic_value == 40000); return 0;
}
static int guest_core(void)
{
    FILE* pattern = fopen("/proc/sys/kernel/core_pattern", "re"); CHECK(pattern);
    char name[256]; CHECK(fgets(name, sizeof(name), pattern)); fclose(pattern);
    name[strcspn(name, "\n")] = 0;
    const char collector[] = "|/usr/lib/systemd/systemd-coredump ";
    int collected = !strncmp(name, collector, sizeof(collector) - 1);
    if (collected && access("/usr/bin/coredumpctl", X_OK)) SKIP("coredumpctl unavailable");
    if (!collected && strcmp(name, "core") && strcmp(name, "core.%p"))
        SKIP("unsupported core pattern/collector");
    struct rlimit limit; CHECK(!getrlimit(RLIMIT_CORE, &limit));
    if (!limit.rlim_max) SKIP("hard core limit is zero");
    limit.rlim_cur = limit.rlim_max < 16 * 1024 * 1024 ? limit.rlim_max : 16 * 1024 * 1024;
    CHECK(!setrlimit(RLIMIT_CORE, &limit));
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) { signal(SIGSEGV, SIG_DFL); raise(SIGSEGV); _exit(1); }
    int status; CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
    char path[256];
    if (collected) {
        snprintf(path, sizeof(path), "core.collected");
        char number[32]; snprintf(number, sizeof(number), "%d", pid);
        int available = 0;
        for (unsigned attempt = 0; attempt < 10 && !available; ++attempt) {
            pid_t reader = fork(); CHECK(reader >= 0);
            if (!reader) {
                int null = open("/dev/null", O_WRONLY);
                if (null >= 0) { dup2(null, 1); dup2(null, 2); }
                execl("/usr/bin/coredumpctl", "coredumpctl", "--quiet", "--no-pager",
                      "--output=core.collected", "dump", number, (char*)NULL);
                _exit(127);
            }
            CHECK(waitpid(reader, &status, 0) == reader);
            available = WIFEXITED(status) && WEXITSTATUS(status) == 0;
            if (!available) usleep(200000);
        }
        if (!available) SKIP("collector did not retain an accessible core");
    } else if (!strcmp(name, "core.%p")) snprintf(path, sizeof(path), "core.%d", pid);
    else snprintf(path, sizeof(path), "core");
    int fd = open(path, O_RDONLY); CHECK(fd >= 0);
    Elf64_Ehdr header; CHECK(read(fd, &header, sizeof(header)) == sizeof(header));
    close(fd); CHECK(!memcmp(header.e_ident, ELFMAG, SELFMAG) && header.e_type == ET_CORE);
#if defined(__riscv)
    CHECK(header.e_machine == EM_RISCV);
#elif defined(__aarch64__)
    CHECK(header.e_machine == EM_AARCH64);
#elif defined(__x86_64__)
    CHECK(header.e_machine == EM_X86_64);
#endif
    return 0;
}
struct test { const char* name; int (*fn)(void); };
static struct test tests[] = {
    {"clone3-fork", clone3_fork}, {"clone3-clear-sighand", clone3_clear_sighand},
    {"clone3-pidfd", clone3_pidfd}, {"clone3-size", clone3_size},
    {"clone-vm-process", clone_vm_process}, {"clone-fs-process", clone_fs_process},
    {"clone-sysvsem", clone_sysvsem},
    {"clone-parent", clone_parent}, {"vfork-nested", vfork_nested},
    {"vfork-private-futex", vfork_private}, {"vfork-pi-futex", vfork_pi},
    {"proc-exe-stat", proc_exe_stat}, {"proc-exe-statx", proc_exe_statx},
    {"proc-task-view", proc_task_view}, {"mmap-shared-validate", mmap_shared_validate},
    {"mmap-validate-unknown", mmap_validate_unknown}, {"mmap-populate", mmap_populate},
    {"mmap-locked", mmap_locked}, {"mmap-growsdown", mmap_growsdown},
    {"memory-budget", memory_budget}, {"fsuid-change", fsuid_change}, {"fsgid-change", fsgid_change},
    {"seccomp-syscall", seccomp_syscall}, {"seccomp-prctl", seccomp_prctl},
    {"landlock-deny", landlock_deny}, {"rseq-register", rseq_register},
    {"io-uring-nop", io_uring_nop}, {"ptrace-syscall-info", ptrace_syscall_info},
    {"ioctl-pipe-bytes", ioctl_pipe_bytes}, {"syscall-bad-buffer", syscall_bad_buffer},
    {"signal-altstack", signal_altstack}, {"atomic-threads", atomic_threads},
    {"guest-core", guest_core},
};
int main(int argc, char** argv)
{
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (size_t i = 0; i < sizeof(tests)/sizeof(*tests); ++i) puts(tests[i].name);
        return 0;
    }
    if (argc == 2) for (size_t i = 0; i < sizeof(tests)/sizeof(*tests); ++i)
        if (!strcmp(argv[1], tests[i].name)) return tests[i].fn();
    fprintf(stderr, "usage: %s --list|CASE\n", argv[0]); return 2;
}
