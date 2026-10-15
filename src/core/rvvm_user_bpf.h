/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_BPF_H
#define RVVM_USER_BPF_H

#include <linux/bpf.h>

_Static_assert(sizeof(struct bpf_insn) == 8 && sizeof(void*) == 8,
               "BPF forwarding requires the Linux LP64 ABI");
_Static_assert(offsetof(union bpf_attr, pathname) == 0
               && offsetof(union bpf_attr, link_create.attach_type) == 8,
               "BPF pathname layout");

static no_inline long user_bpf(unsigned int command, void* attr, unsigned int size)
{
    /* RV64 and our hosts share the fixed-width, little-endian BPF UAPI.
     * Keep the original user buffer: the kernel validates extensions and
     * pointers, and writes back query counts, test results and verifier sizes.
     * Programs and attachments operate on the running HOST kernel. */
    if (!prefix_path || !*prefix_path)
        return errno_ret(syscall(SYS_bpf, command, attr, size));

    size_t path_offset;
    if (command == BPF_OBJ_PIN || command == BPF_OBJ_GET) {
        path_offset = 0;
    } else if (command == BPF_LINK_CREATE) {
        uint32_t attach_type;
        if (size < 12) return errno_ret(syscall(SYS_bpf, command, attr, size));
        long ret = user_memory_copy(&attach_type, (char*)attr + 8, sizeof(attach_type));
        if (ret < 0) return ret;
        /* BPF_TRACE_UPROBE_MULTI (48), including hosts with older headers.
         * This translates a host executable pathname, not guest probes. */
        if (attach_type != 48) return errno_ret(syscall(SYS_bpf, command, attr, size));
        path_offset = 16;
    } else {
        return errno_ret(syscall(SYS_bpf, command, attr, size));
    }

    /* Linux rejects attributes larger than its page size. Preserve its error
     * handling instead of allocating an unbounded guest-controlled buffer. */
    if (size > (unsigned long)sysconf(_SC_PAGESIZE))
        return errno_ret(syscall(SYS_bpf, command, attr, size));
    size_t bytes = size > path_offset + 8 ? size : path_offset + 8;
    /* Shared-mm VFORK children allocate through their parent worker. */
    unsigned char* snapshot = user_runtime_allocate(bytes);
    if (!snapshot) return -ENOMEM;
    memset(snapshot, 0, bytes);
    long ret = user_memory_copy(snapshot, attr, size);
    uint64_t address = 0;
    if (!ret) memcpy(&address, snapshot + path_offset, sizeof(address));
    char path[UAPI_PATH_MAX], wrapped[UAPI_PATH_MAX];
    if (!ret && address) {
        ret = user_path_copy(path, (const char*)(uintptr_t)address, sizeof(path));
        if (ret >= 0) {
            if (path[0] == '/' && !path_bypass(path)
                && strlen(prefix_path) + (size_t)ret >= sizeof(wrapped)) {
                ret = -ENAMETOOLONG;
            } else {
                address = (uintptr_t)wrap_path(wrapped, path);
                memcpy(snapshot + path_offset, &address, sizeof(address));
                ret = 0;
            }
        }
    }
    /* These commands return a descriptor or status, never modify attr.
     * Preserve the entire extension tail, including nonzero reserved bytes. */
    if (!ret) ret = errno_ret(syscall(SYS_bpf, command, snapshot, address ? bytes : size));
    user_runtime_release(snapshot);
    return ret;
}
#endif
