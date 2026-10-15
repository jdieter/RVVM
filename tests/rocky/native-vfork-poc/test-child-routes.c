/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Syscalls the parent handles must also work in a shared-mm VFORK child
 * before exec: each is issued in the child and compared with the parent's
 * result, or checked through its effect on the shared address space. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

enum { MOUNT, UMOUNT, MINCORE, ACCEPT, SENDMMSG, VM_READ, VM_WRITE, BPF, FCHMODAT2,
       SHMGET, SHMCTL, SHMAT, SHMDT, UNSHARE_FILES, UNSHARE_NS, COUNT };
static const char* names[COUNT] = {"mount", "umount2", "mincore", "accept4", "sendmmsg",
    "process_vm_readv", "process_vm_writev", "bpf", "fchmodat2", "shmget", "shmctl",
    "shmat", "shmdt", "unshare(CLONE_FILES)", "unshare(CLONE_NEWNS)"};

struct results { long value[COUNT]; int error[COUNT]; };
static char stack[256 * 1024];
static int sockets[2], listener;
static char path[64], source[16] = "child-source", target[16];
static void* page;
static void* attached;
static int segment;

static void record(struct results* out, int which, long value)
{
    out->value[which] = value;
    out->error[which] = value < 0 ? errno : 0;
}

/* Calls whose result must match between parent and child. */
static void comparable(struct results* out)
{
    /* Fails for everyone: EPERM unprivileged, ENOENT as root. */
    record(out, MOUNT, mount("none", "/nonexistent-rvvm-route", "tmpfs", 0, NULL));
    record(out, UMOUNT, umount2("/nonexistent-rvvm-route", 0));
    unsigned char resident;
    record(out, MINCORE, mincore(page, sysconf(_SC_PAGESIZE), &resident));
    record(out, ACCEPT, accept4(listener, NULL, NULL, SOCK_CLOEXEC));
    record(out, BPF, syscall(SYS_bpf, 0x7fffffff, NULL, 0));
    record(out, UNSHARE_NS, unshare(CLONE_NEWNS));
}

static int child(void* opaque)
{
    struct results* out = opaque;
    comparable(out);
    struct iovec local = {target, sizeof(target)}, remote = {source, sizeof(source)};
    record(out, VM_READ, process_vm_readv(getpid(), &local, 1, &remote, 1, 0));
    struct iovec write_local = {"child-write", 12}, write_remote = {target, 12};
    record(out, VM_WRITE, process_vm_writev(getpid(), &write_local, 1, &write_remote, 1, 0));
    struct mmsghdr message = {.msg_hdr = {.msg_iov = &(struct iovec){"datagram", 8}, .msg_iovlen = 1}};
    record(out, SENDMMSG, sendmmsg(sockets[0], &message, 1, 0));
    record(out, FCHMODAT2, syscall(SYS_fchmodat2, AT_FDCWD, path, 0640, 0));
    record(out, SHMGET, segment = shmget(IPC_PRIVATE, 65536, IPC_CREAT | 0600));
    struct shmid_ds info;
    record(out, SHMCTL, segment < 0 ? -1 : shmctl(segment, IPC_STAT, &info));
    attached = segment < 0 ? (void*)-1 : shmat(segment, NULL, 0);
    record(out, SHMAT, attached == (void*)-1 ? -1 : 0);
    if (attached != (void*)-1) strcpy(attached, "shared-segment");
    /* Leave a second attachment for the parent to detach. */
    void* second = segment < 0 ? (void*)-1 : shmat(segment, NULL, SHM_RDONLY);
    record(out, SHMDT, second == (void*)-1 ? -1 : shmdt(second));
    record(out, UNSHARE_FILES, unshare(CLONE_FILES));
    _exit(0);
}

int main(void)
{
    alarm(20);
    page = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(page != MAP_FAILED);
    *(volatile char*)page = 1;
    assert(!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets));
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(listener >= 0);
    snprintf(path, sizeof(path), "/tmp/rvvm-child-routes-%d", getpid());
    unlink(path); /* PID namespaces reuse small PIDs across runs. */
    int file = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    assert(file >= 0);
    close(file);

    struct results parent = {0}, shared = {0};
    comparable(&parent);
    pid_t pid = clone(child, stack + sizeof(stack), CLONE_VM | CLONE_VFORK | SIGCHLD, &shared);
    int status;
    assert(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));

    int failures = 0;
    for (int i = 0; i < COUNT; ++i) {
        int compare = i == MOUNT || i == UMOUNT || i == MINCORE || i == ACCEPT || i == BPF
                   || i == UNSHARE_NS;
        int bad = shared.error[i] == ENOSYS
               || (compare && (shared.value[i] != parent.value[i] || shared.error[i] != parent.error[i]))
               || (!compare && shared.value[i] < 0);
        if (bad) {
            fprintf(stderr, "%s: child %ld errno %d, parent %ld errno %d\n", names[i],
                    shared.value[i], shared.error[i], parent.value[i], parent.error[i]);
            ++failures;
        }
    }
    /* Effects of the child's calls are visible to the parent. */
    assert(!memcmp(target, "child-write", 12));
    char datagram[16] = {0};
    assert(recv(sockets[1], datagram, sizeof(datagram), MSG_DONTWAIT) == 8 && !memcmp(datagram, "datagram", 8));
    struct stat st;
    assert(!stat(path, &st) && (st.st_mode & 07777) == 0640);
    assert(attached != (void*)-1 && !strcmp(attached, "shared-segment"));
    assert(!shmdt(attached) && !shmctl(segment, IPC_RMID, NULL));
    unlink(path);
    if (failures) return 1;
    puts("PASS mount/umount2/mincore/accept4/sendmmsg/process_vm/bpf/fchmodat2/shm*/unshare in shared-mm VFORK child");
    return 0;
}
