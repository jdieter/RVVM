/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FS_H
#define RVVM_USER_FS_H

#include <linux/magic.h>
#include <sys/sysmacros.h>
#include "util/user_proc_read.h"

/* fstatfs on a guest FUSE file sends a request to its guest server. Besides
 * changing the filesystem protocol, doing that under our descriptor guard can
 * deadlock the server. Mountinfo identifies the superblock without querying it.
 * Do not cache this fallback: guests can create and replace mounts. */
static long user_fs_type(dev_t device)
{
    user_fd_lock();
    struct user_proc_reader mounts;
    long type = 0;
    if (user_proc_open(&mounts, "/proc/thread-self/mountinfo")) {
        unsigned field = 0, separator = 0, length = 0;
        uint64_t major_id = 0, minor_id = 0;
        bool minor = false, valid = true, matched = false;
        char filesystem[6], byte;
        /* Mount paths may be arbitrarily long. Only the third field and the
         * filesystem token after the separator need retained storage. */
        while (user_proc_byte(&mounts, &byte)) {
            if (separator == 3) {
                if (byte == ' ' || byte == '\n') {
                    if (length == 4 && !memcmp(filesystem, "proc", 4)) type = PROC_SUPER_MAGIC;
                    else if (length == 5 && !memcmp(filesystem, "sysfs", 5)) type = SYSFS_MAGIC;
                    break;
                }
                if (length < sizeof(filesystem)) filesystem[length++] = byte;
                continue;
            }
            if (byte == '\n') {
                field = separator = length = 0;
                major_id = minor_id = 0;
                minor = matched = false;
                valid = true;
                continue;
            }
            if (field == 2 && byte != ' ') {
                if (byte == ':' && !minor) minor = true;
                else if (byte >= '0' && byte <= '9') {
                    uint64_t* value = minor ? &minor_id : &major_id;
                    if (*value > (UINT32_MAX - (unsigned)(byte - '0')) / 10) valid = false;
                    else *value = *value * 10 + byte - '0';
                } else valid = false;
            }
            if (byte == ' ') {
                if (field == 2) matched = valid && minor && makedev(major_id, minor_id) == device;
                ++field;
            }
            if (matched) {
                if (separator == 2) separator = byte == ' ' ? 3 : 0;
                else if (separator == 1) separator = byte == '-' ? 2 : byte == ' ';
                else separator = byte == ' ';
            }
        }
        user_proc_close(&mounts);
    }
    user_fd_unlock();
    return type;
}

#endif
