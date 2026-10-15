/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static char stack[128 * 1024];

static void executable(int fd)
{
    Elf64_Ehdr header;
    assert(fd >= 0 && read(fd, &header, sizeof(header)) == sizeof(header));
#if defined(__riscv)
    assert(header.e_machine == EM_RISCV);
#elif defined(__aarch64__)
    assert(header.e_machine == EM_AARCH64);
#elif defined(__x86_64__)
    assert(header.e_machine == EM_X86_64);
#endif
    close(fd);
}

static int child(void* unused)
{
    (void)unused;
    executable(open("/proc/self/exe", O_RDONLY | O_CLOEXEC));
    int directory = open("/proc/self", O_PATH | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0);
    executable(openat(directory, "exe", O_RDONLY | O_CLOEXEC));
    close(directory);
    struct open_how how = {.flags = O_RDONLY | O_CLOEXEC};
    executable(syscall(SYS_openat2, AT_FDCWD, "/proc/self/exe", &how, sizeof(how)));
    int fd = open("/proc/cpuinfo", O_RDONLY | O_CLOEXEC);
    char data[4096];
    long count = read(fd, data, sizeof(data) - 1);
    assert(fd >= 0 && count > 0);
    data[count] = 0;
#if defined(__riscv)
    assert(strstr(data, "rv64"));
#endif
    close(fd);
    fd = open("/proc/self/auxv", O_RDONLY | O_CLOEXEC);
    uint64_t values[128];
    count = read(fd, values, sizeof(values));
    assert(fd >= 0 && count > 0 && !(count % 16));
    int found = 0;
    for (long i = 0; i < count / 8; i += 2)
        if (values[i] == AT_PHDR) { assert(values[i + 1] == getauxval(AT_PHDR)); found = 1; }
    assert(found);
    close(fd);
#if defined(__riscv)
    struct {int64_t key; uint64_t value;} pairs[] = {{3, 0}, {999, 0}};
    assert(!syscall(258, pairs, 2, 0, NULL, 0) && pairs[0].value == 1 && pairs[1].key == -1);
    unsigned char cpus[128] = {0};
    pairs[0].value = 1;
    assert(!syscall(258, pairs, 1, sizeof(cpus), cpus, 1));
    found = 0;
    for (unsigned i = 0; i < sizeof(cpus); ++i) found |= cpus[i];
    assert(found);
#endif
    fd = open("/sys/devices/system/cpu/cpu0/uevent", O_RDONLY | O_CLOEXEC);
    assert(fd >= 0);
    count = read(fd, data, sizeof(data) - 1);
    assert(count > 0); data[count] = 0;
#if defined(__riscv)
    assert(strstr(data, "MODALIAS=cpu:type:riscv:"));
#endif
    close(fd);
    fd = open("/sys/devices/system/cpu/cpu0/modalias", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        count = read(fd, data, sizeof(data) - 1);
        assert(count > 0); data[count] = 0;
#if defined(__riscv)
        assert(!strncmp(data, "cpu:type:riscv:", 15));
#endif
        close(fd);
    }
    /* After consuming every slot, this open needs only the slot released
     * below. Resolving a stale parent proc-link inode would need another. */
    struct rlimit limit = {32, 32};
    assert(!setrlimit(RLIMIT_NOFILE, &limit));
    int descriptors[32], used = 0;
    while ((fd = open("/dev/null", O_RDONLY | O_CLOEXEC)) >= 0) {
        assert(used < 32); descriptors[used++] = fd;
    }
    assert(errno == EMFILE && used);
    close(descriptors[--used]);
    executable(open("/proc/self/exe", O_RDONLY | O_CLOEXEC));
    while (used) close(descriptors[--used]);
    _exit(0);
}

int main(int argc, char** argv)
{
    int ordinary = argc == 2 && !strcmp(argv[1], "--ordinary");
    int cow = argc == 2 && !strcmp(argv[1], "--cow-vfork");
    assert(argc == 1 || ordinary || cow);
    alarm(20);
    pid_t pid = ordinary ? fork()
        : clone(child, stack + sizeof(stack), CLONE_VFORK | (cow ? 0 : CLONE_VM) | SIGCHLD, NULL);
    if (!pid) child(NULL);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
    puts("PASS process executable/CPU/auxv views and last-slot executable open");
}
