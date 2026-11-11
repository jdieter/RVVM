/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#include "utils.h"
#include <assert.h>
#include "core/rvvm_user_vma.h"

static bool user_proc_is_self(unsigned pid, bool thread)
{
    return pid == (unsigned)getpid() || (thread && pid == (unsigned)syscall(SYS_gettid));
}

static long write_row(void* opaque, const char* data, size_t size)
{
    return write(*(int*)opaque, data, size) == (ssize_t)size ? 0 : -errno;
}

#include "core/rvvm_user_proc_maps.h"

int main(void)
{
    /* A kernel VMA can coalesce native and guest ranges. Keep only the
     * guest fragments, preserving protections and file-offset adjustments. */
    struct user_vma_range ranges[] = {{0x2000, 0x3000}, {0x4000, 0x5000}, {0x9000, 0xb000}};
    user_vma_owned = ranges;
    user_vma_owned_count = sizeof(ranges) / sizeof(*ranges);
    const char text[] = "1000-8000 r--p 00000000 00:00 0\n"
                        "8000-f000 rw-p 00002000 08:01 123 /tmp/guest file\n"
                        "10000-20000 rw-p 00000000 00:00 0 [native]\n";
    int source = memfd_create("kernel-maps", MFD_CLOEXEC);
    int output = memfd_create("guest-maps", MFD_CLOEXEC);
    assert(source >= 0 && output >= 0);
    assert(write(source, text, sizeof(text) - 1) == sizeof(text) - 1);
    assert(lseek(source, 7, SEEK_SET) == 7);
    assert(!user_proc_maps_emit(source, write_row, &output));
    assert(lseek(source, 0, SEEK_CUR) == 7);
    assert(!lseek(output, 0, SEEK_SET));
    FILE* view = fdopen(output, "r");
    char line[256], permissions[5];
    uintptr_t start, end;
    unsigned long offset;
    for (size_t i = 0; i < sizeof(ranges) / sizeof(*ranges); i++) {
        assert(fgets(line, sizeof(line), view));
        assert(sscanf(line, "%lx-%lx %4s %lx", &start, &end, permissions, &offset) == 4);
        assert(start == ranges[i].start && end == ranges[i].end);
        assert(!strcmp(permissions, i == 2 ? "rw-p" : "r--p"));
        assert(offset == (i == 2 ? 0x3000 : 0));
        if (i == 2) assert(strstr(line, "08:01 123 /tmp/guest file\n"));
    }
    assert(!fgets(line, sizeof(line), view));
    fclose(view);
    assert(!ftruncate(source, 0) && !lseek(source, 0, SEEK_SET));
    assert(write(source, "invalid\n", 8) == 8 && !lseek(source, 0, SEEK_SET));
    assert(user_proc_maps_emit(source, write_row, &output) == -EIO);
    close(source);
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/maps", (unsigned)getpid());
    assert(user_proc_self_maps(path) && !user_proc_self_maps("/proc/0/maps"));
    puts("PASS guest maps omit native ranges and preserve clipped file offsets");
}
