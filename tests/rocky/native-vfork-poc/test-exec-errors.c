/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* A failed exec must return its real errno to the still-shared child.
 * Successful cases exercise the emulator handoff instead of only faccessat. */
struct attempt {
    const char *path;
    char **argv, **env;
    int fd, flags, use_at;
    volatile int result, error, marker;
};

static int child(void *opaque)
{
    struct attempt *a = opaque;
    a->marker = 123;
    a->result = a->use_at
        ? syscall(SYS_execveat, a->fd, a->path, a->argv, a->env, a->flags)
        : syscall(SYS_execve, a->path, a->argv, a->env);
    a->error = errno;
    a->marker = 456;
    syscall(SYS_exit_group, 117);
    __builtin_unreachable();
}

static void check(const char *name, struct attempt a, int expected_errno,
                  int expected_exit)
{
    size_t size = 256 * 1024;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) { perror("stack"); exit(1); }
    pid_t pid = clone(child, (char *)stack + size,
                      CLONE_VM | CLONE_VFORK | SIGCHLD, &a);
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) != pid) {
        perror("clone/wait"); exit(1);
    }
    int ok = WIFEXITED(status) && WEXITSTATUS(status) == expected_exit
        && a.marker == (expected_errno ? 456 : 123);
    if (expected_errno) ok &= a.result == -1 && a.error == expected_errno;
    printf("%s %s status=%d errno=%d marker=%d\n",
           ok ? "PASS" : "FAIL", name, status, a.error, a.marker);
    munmap(stack, size);
    if (!ok) exit(1);
}

static void file(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    size_t len = strlen(text);
    if (fd < 0 || write(fd, text, len) != (ssize_t)len || close(fd)) {
        perror("fixture"); exit(1);
    }
}

int main(int argc, char **args)
{
    if (argc > 1 && !strcmp(args[1], "--exec-probe")) {
        const char *value = getenv("RVVM_VFORK_EXEC_CHECK");
        return !strcmp(args[0], "custom-name") && value && !strcmp(value, "keep") ? 53 : 54;
    }
    char tmp[] = "/tmp/rvvm-exec-errors-XXXXXX";
    if (!mkdtemp(tmp)) { perror("mkdtemp"); return 1; }
    char invalid[256], denied[256], missing_interp[256], script[256];
    snprintf(invalid, sizeof(invalid), "%s/invalid", tmp);
    snprintf(denied, sizeof(denied), "%s/denied", tmp);
    snprintf(missing_interp, sizeof(missing_interp), "%s/missing-interp", tmp);
    snprintf(script, sizeof(script), "%s/script", tmp);
    file(invalid, "not an executable\n", 0700);
    file(denied, "#!/bin/sh\nexit 42\n", 0600);
    file(missing_interp, "#!/no/such/rvvm-interpreter\n", 0700);
    file(script, "#!/bin/sh\nexit 42\n", 0700);
    char *argv[] = { "exec-test", NULL }, *env[] = { NULL };
    struct attempt a = { .path = "/bin/true", .argv = argv, .env = env };
    a.path = "/no/such/rvvm-executable";
    check("missing path", a, ENOENT, 117);
    a.path = tmp; check("directory", a, EACCES, 117);
    a.path = denied; check("nonexecutable", a, EACCES, 117);
    a.path = invalid; check("invalid executable", a, ENOEXEC, 117);
    a.path = missing_interp; check("missing script interpreter", a, ENOENT, 117);
    a.path = (void *)1; check("invalid path pointer", a, EFAULT, 117);
    a.path = "/bin/true";
    a.argv = (void *)1; check("invalid argv pointer", a, EFAULT, 117);
    a.argv = argv;
    a.env = (void *)1; check("invalid env pointer", a, EFAULT, 117);
    a.env = env; check("normal executable", a, 0, 0);
    a.argv = NULL; a.env = NULL; check("NULL argv and env", a, 0, 0);
    char *many[1101];
    for (size_t i = 0; i < 1100; ++i) many[i] = "x";
    many[1100] = NULL;
    a.argv = many; a.env = env; check("1100 arguments", a, 0, 0);
    a.argv = argv; a.path = script; check("script", a, 0, 42);
    char *probe_args[] = { "custom-name", "--exec-probe", NULL };
    char *probe_env[] = { "RVVM_VFORK_EXEC_CHECK=keep", NULL };
    a.path = "/proc/self/exe"; a.argv = probe_args; a.env = probe_env;
    check("self exec preserves argv0 and environment", a, 0, 53);
    a.argv = argv; a.env = env;
    a.use_at = 1; a.path = ""; a.flags = AT_EMPTY_PATH;
    a.fd = open("/bin/true", O_PATH | O_CLOEXEC);
    if (a.fd < 0) { perror("open true"); return 1; }
    check("execveat empty path", a, 0, 0);
    close(a.fd);
    a.fd = -1; check("execveat invalid fd", a, EBADF, 117);
    /* A valid pathname avoids host-dependent empty-path error ordering. */
    a.path = "/bin/true"; a.fd = AT_FDCWD; a.flags = 0x40000000;
    check("execveat invalid flags", a, EINVAL, 117);
    a.path = ""; a.flags = AT_EMPTY_PATH; a.fd = open(script, O_PATH | O_CLOEXEC);
    if (a.fd < 0) { perror("open script"); return 1; }
    check("CLOEXEC script descriptor", a, ENOENT, 117);
    close(a.fd);
    unlink(script); unlink(missing_interp); unlink(denied); unlink(invalid);
    rmdir(tmp);
    puts("PASS native-vfork exec semantics");
    return 0;
}
