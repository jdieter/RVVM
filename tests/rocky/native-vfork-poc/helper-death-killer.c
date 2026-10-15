/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native companion for test-helper-death: kills emulator mapping helpers
 * (children of the guest's shared-mm VFORK children) during the guest's
 * targeted phase. A guest thread cannot observe the mmap/munmap windows:
 * emulator mapping locks serialize it with the operation. The guest's phase
 * variables are read with process_vm_readv (same UID, ptrace READ access).
 * Usage: helper-death-killer <guest-pid> <phase-address> <wanted-address> [stop]
 * With stop, helpers are stopped instead of killed. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

static int read_file(const char* path, char* buffer, size_t size)
{
    FILE* file = fopen(path, "re");
    if (!file) return -1;
    size_t n = fread(buffer, 1, size - 1, file);
    fclose(file);
    buffer[n] = 0;
    return (int)n;
}

static int guest_int(pid_t guest, unsigned long address)
{
    int value = -1;
    struct iovec local = {&value, sizeof(value)}, remote = {(void*)address, sizeof(value)};
    return process_vm_readv(guest, &local, 1, &remote, 1, 0) == sizeof(value) ? value : -1;
}

int main(int argc, char** argv)
{
    if (argc != 4 && !(argc == 5 && !strcmp(argv[4], "stop"))) return 2;
    int signal_number = argc == 5 ? SIGSTOP : SIGKILL;
    pid_t guest = atoi(argv[1]);
    unsigned long phase = strtoul(argv[2], NULL, 16), wanted = strtoul(argv[3], NULL, 16);
    unsigned long kills[4] = {0};
    int last_stopped = 0; /* stop each helper once, as job control would */
    char path[128], list[4096], helpers[4096];
    while (!kill(guest, 0)) {
        snprintf(path, sizeof(path), "/proc/%d/task/%d/children", guest, guest);
        if (read_file(path, list, sizeof(list)) <= 0) continue;
        for (char* child = strtok(list, " \n"); child; child = strtok(NULL, " \n")) {
            int pid = atoi(child);
            if (pid == getpid()) continue;
            snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);
            if (read_file(path, helpers, sizeof(helpers)) <= 0) continue;
            int helper = atoi(helpers), current = guest_int(guest, phase);
            if (helper > 0 && current >= 0 && current < 4 && current == guest_int(guest, wanted)
                && !(signal_number == SIGSTOP && helper == last_stopped)
                && !kill(helper, signal_number)) {
                ++kills[current];
                last_stopped = helper;
            }
        }
    }
    fprintf(stderr, "killer: mmap=%lu populate=%lu mprotect=%lu munmap=%lu\n",
            kills[0], kills[1], kills[2], kills[3]);
    return 0;
}
