/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include "util/user_fd_guard.h"
#include "core/rvvm_user_fs.h"

int main(void)
{
    int pipefd[2];
    assert(!pipe(pipefd));
    char bytes[2048];
    memset(bytes, 'x', sizeof(bytes));
    bytes[sizeof(bytes) - 1] = '\n';
    assert(write(pipefd[1], bytes, sizeof(bytes)) == sizeof(bytes));
    const char* next = "TracerPid:\t123\nlast";
    assert(write(pipefd[1], next, strlen(next)) == (long)strlen(next));
    close(pipefd[1]);
    struct user_proc_reader reader = {.fd = pipefd[0]};
    char line[32];
    assert(user_proc_line(&reader, line, sizeof(line)) && strlen(line) == sizeof(line) - 1);
    assert(user_proc_line(&reader, line, sizeof(line)) && !strcmp(line, "TracerPid:\t123"));
    assert(user_proc_line(&reader, line, sizeof(line)) && !strcmp(line, "last"));
    assert(!user_proc_line(&reader, line, sizeof(line)));
    user_proc_close(&reader);
    const char* paths[] = {"/proc", "/sys"};
    for (unsigned i = 0; i < 2; ++i) {
        struct stat st;
        struct statfs fs;
        assert(!stat(paths[i], &st) && !statfs(paths[i], &fs));
        assert(user_fs_type(st.st_dev) == fs.f_type);
    }
    puts("PASS bounded proc records, split reads/EOF and kernel mount classification");
}
