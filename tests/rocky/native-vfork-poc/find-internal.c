/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native companion for test-internal-hidden: prints the PID of another
 * process sharing the guest's command line (RVVM's observer shares its mm),
 * as the guest's own PID namespace numbers it, or 0. Its proc view is
 * unfiltered. Usage: find-internal <guest's /proc/self name> */
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
            /* NSpid lists the guest's namespace number last. */
            char path[300], status[4096];
            snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            ssize_t n = fd < 0 ? -1 : read(fd, status, sizeof(status) - 1);
            if (fd >= 0) close(fd);
            const char* pid = entry->d_name;
            char last[32];
            if (n > 0) {
                status[n] = 0;
                char* line = strstr(status, "\nNSpid:");
                for (char* at = line ? line + 7 : NULL; at;) {
                    while (*at == ' ' || *at == '\t') ++at;
                    if (*at < '0' || *at > '9') break;
                    size_t digits = strspn(at, "0123456789");
                    snprintf(last, sizeof(last), "%.*s", (int)digits, at);
                    pid = last;
                    at += digits;
                }
            }
            printf("%s\n", pid);
            return 0;
        }
    }
    printf("0\n");
    return 0;
}
