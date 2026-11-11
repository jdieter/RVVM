/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PROC_MAPS_H
#define RVVM_USER_PROC_MAPS_H

static bool user_proc_self_maps(const char* path)
{
    unsigned pid, tid;
    int end = 0;
    if (sscanf(path, "/proc/%u/maps%n", &pid, &end) == 1 && end && !path[end])
        return user_proc_is_self(pid, true);
    end = 0;
    return sscanf(path, "/proc/%u/task/%u/maps%n", &pid, &tid, &end) == 2
        && end && !path[end] && user_proc_is_self(pid, false);
}

/* Valgrind compares this view with its guest mapping registry. Native
 * allocator, JIT and worker-stack growth must not appear as guest mappings. */
static long user_proc_maps_emit(int source, long (*emit)(void*, const char*, size_t), void* output)
{
    struct user_proc_reader reader = {.fd = source, .positional = true};
    char line[4608], row[4864];
    long result = 0;
    user_fd_mutex_lock(&user_vma_owned_lock);
    size_t first_owned = 0;
    while (user_proc_line(&reader, line, sizeof(line))) {
        uintptr_t first, last;
        unsigned long offset, inode;
        char permissions[5], device[32];
        int suffix = 0;
        if (sscanf(line, "%lx-%lx %4s %lx %31s %lu%n", &first, &last,
                   permissions, &offset, device, &inode, &suffix) != 6 || !suffix) {
            result = -EIO;
            break;
        }
        while (first_owned < user_vma_owned_count && user_vma_owned[first_owned].end <= first)
            ++first_owned;
        for (size_t i = first_owned; i < user_vma_owned_count && user_vma_owned[i].start < last; ++i) {
            uintptr_t start = EVAL_MAX(first, user_vma_owned[i].start);
            uintptr_t end = EVAL_MIN(last, user_vma_owned[i].end);
            int size = snprintf(row, sizeof(row), "%lx-%lx %s %08lx %s %lu%s\n",
                                start, end, permissions, offset + (inode ? start - first : 0),
                                device, inode, line + suffix);
            if (size < 0 || (size_t)size >= sizeof(row)) { result = -EOVERFLOW; break; }
            result = emit(output, row, size);
            if (result) break;
        }
        if (result) break;
    }
    if (!result && reader.error) result = -reader.error;
    user_fd_mutex_unlock(&user_vma_owned_lock);
    return result;
}
#endif
