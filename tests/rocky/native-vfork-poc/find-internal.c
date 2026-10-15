/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native companion for test-internal-hidden: prints the PID of another
 * process sharing the guest's command line (RVVM's observer shares its mm),
 * or 0. Its proc view is unfiltered. Usage: find-internal <guest-pid> */
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static ssize_t cmdline(const char* pid, char* buffer, size_t size)
{
    char path[300];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buffer, size);
    close(fd);
    return n;
}

int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    char guest[4096], other[4096], self[16];
    snprintf(self, sizeof(self), "%d", getpid());
    ssize_t length = cmdline(argv[1], guest, sizeof(guest));
    DIR* proc = opendir("/proc");
    struct dirent* entry;
    while (length > 0 && proc && (entry = readdir(proc))) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;
        if (!strcmp(entry->d_name, argv[1]) || !strcmp(entry->d_name, self)) continue;
        if (cmdline(entry->d_name, other, sizeof(other)) == length && !memcmp(guest, other, length)) {
            printf("%s\n", entry->d_name);
            return 0;
        }
    }
    printf("0\n");
    return 0;
}
