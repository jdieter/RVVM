/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FS_H
#define RVVM_USER_FS_H

#include <linux/magic.h>
#include <sys/sysmacros.h>

/* fstatfs on a guest FUSE file sends a request to its guest server. Besides
 * changing the filesystem protocol, doing that under our descriptor guard can
 * deadlock the server. Mountinfo identifies the superblock without querying it.
 * Do not cache this fallback: guests can create and replace mounts. */
static long user_fs_type(dev_t device)
{
    user_fd_lock();
    FILE* mounts = fopen("/proc/thread-self/mountinfo", "re");
    long type = 0;
    if (mounts) {
        char* line = NULL;
        size_t capacity = 0;
        while (getline(&line, &capacity, mounts) >= 0) {
            unsigned major_id, minor_id;
            if (sscanf(line, "%*u %*u %u:%u", &major_id, &minor_id) != 2
                || makedev(major_id, minor_id) != device) continue;
            const char* fs = strstr(line, " - ");
            if (fs && !strncmp(fs + 3, "proc ", 5)) type = PROC_SUPER_MAGIC;
            else if (fs && !strncmp(fs + 3, "sysfs ", 6)) type = SYSFS_MAGIC;
            break;
        }
        free(line);
        fclose(mounts);
    }
    user_fd_unlock();
    return type;
}

#endif
