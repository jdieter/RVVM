/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_FLAGS_H
#define RVVM_USER_FLAGS_H

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct uapi_flag_map {
    uint32_t guest_mask, guest_value;
    uint32_t host_mask, host_value;
};

/* Read every match from the original input: mapped bits may overlap other
 * source bits. Unmapped bits retain their value for the host to validate. */
static uint32_t uapi_translate_flags(uint32_t flags, const struct uapi_flag_map *map,
                                     size_t count, bool to_host)
{
    uint32_t result = flags;
    uint32_t mapped = 0;
    for (size_t i = 0; i < count; ++i) {
        uint32_t mask = to_host ? map[i].guest_mask : map[i].host_mask;
        uint32_t value = to_host ? map[i].guest_value : map[i].host_value;
        result &= ~mask;
        if (mask && (flags & mask) == value) {
            mapped |= to_host ? map[i].host_value : map[i].guest_value;
        }
    }
    return result | mapped;
}

/* glibc makes O_LARGEFILE zero on 64-bit hosts, but F_GETFL can still return
 * the kernel bit. Account for it so it cannot masquerade as a guest flag. */
#if defined(__aarch64__)
#define UAPI_HOST_LARGEFILE 0400000
#elif defined(__x86_64__) || defined(__riscv) || defined(__loongarch__)
#define UAPI_HOST_LARGEFILE 0100000
#else
#define UAPI_HOST_LARGEFILE O_LARGEFILE
#endif

/* RISC-V Linux constants are fixed; host constants come from host headers. */
#define UAPI_OPEN_FLAG(guest, host) { guest, guest, host, host }
static const struct uapi_flag_map uapi_open_flags[] = {
    { 3, 0, O_ACCMODE, O_RDONLY },
    { 3, 1, O_ACCMODE, O_WRONLY },
    { 3, 2, O_ACCMODE, O_RDWR },
    { 3, 3, O_ACCMODE, O_ACCMODE },
    UAPI_OPEN_FLAG(00000100, O_CREAT),
    UAPI_OPEN_FLAG(00000200, O_EXCL),
    UAPI_OPEN_FLAG(00000400, O_NOCTTY),
    UAPI_OPEN_FLAG(00001000, O_TRUNC),
    UAPI_OPEN_FLAG(00002000, O_APPEND),
    UAPI_OPEN_FLAG(00004000, O_NONBLOCK),
    UAPI_OPEN_FLAG(00010000, O_DSYNC),
    UAPI_OPEN_FLAG(00020000, O_ASYNC),
    UAPI_OPEN_FLAG(00040000, O_DIRECT),
    UAPI_OPEN_FLAG(00100000, UAPI_HOST_LARGEFILE),
    UAPI_OPEN_FLAG(00200000, O_DIRECTORY),
    UAPI_OPEN_FLAG(00400000, O_NOFOLLOW),
    UAPI_OPEN_FLAG(01000000, O_NOATIME),
    UAPI_OPEN_FLAG(02000000, O_CLOEXEC),
    UAPI_OPEN_FLAG(04000000, O_SYNC & ~O_DSYNC),
    UAPI_OPEN_FLAG(010000000, O_PATH),
    UAPI_OPEN_FLAG(020000000, O_TMPFILE & ~O_DIRECTORY),
};
#undef UAPI_OPEN_FLAG
#undef UAPI_HOST_LARGEFILE

// ARM64 swaps the DIRECT/LARGEFILE pair with DIRECTORY/NOFOLLOW. Everything
// else, including unknown bits that Linux must validate, passes through.
#if defined(__aarch64__) && O_ACCMODE == 3 && O_RDONLY == 0 && O_WRONLY == 1 && O_RDWR == 2 \
    && O_CREAT == 00000100 && O_EXCL == 00000200 && O_NOCTTY == 00000400 \
    && O_TRUNC == 00001000 && O_APPEND == 00002000 && O_NONBLOCK == 00004000 \
    && O_DSYNC == 00010000 && O_ASYNC == 00020000 && O_DIRECT == 00200000 \
    && O_DIRECTORY == 00040000 && O_NOFOLLOW == 00100000 && O_NOATIME == 01000000 \
    && O_CLOEXEC == 02000000 && (O_SYNC & ~O_DSYNC) == 04000000 \
    && O_PATH == 010000000 && (O_TMPFILE & ~O_DIRECTORY) == 020000000
#define UAPI_ARM64_OPEN_PERMUTATION 1
static inline uint32_t uapi_open_flags_permute(uint32_t flags)
{
    return (flags & ~0740000U) | ((flags & 0140000U) << 2) | ((flags & 0600000U) >> 2);
}
#endif

static uint32_t uapi_open_flags_to_host(uint32_t flags)
{
#ifdef UAPI_ARM64_OPEN_PERMUTATION
    return uapi_open_flags_permute(flags);
#else
    return uapi_translate_flags(flags, uapi_open_flags,
                                sizeof(uapi_open_flags) / sizeof(uapi_open_flags[0]), true);
#endif
}

static uint32_t uapi_open_flags_to_guest(uint32_t flags)
{
#ifdef UAPI_ARM64_OPEN_PERMUTATION
    return uapi_open_flags_permute(flags);
#else
    return uapi_translate_flags(flags, uapi_open_flags,
                                sizeof(uapi_open_flags) / sizeof(uapi_open_flags[0]), false);
#endif
}

#endif
