/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_LOCK_MEMORY_H
#define RVVM_USER_LOCK_MEMORY_H

static long user_lock_memory(unsigned nr, uintptr_t address, uintptr_t length, unsigned flags)
{
    /* Guest mappings share the native address space. Only the caller's explicit
     * range is forwarded: Linux owns page rounding, limits and permissions. */
    switch (nr) {
        case 228: return errno_ret(USER_SYSCALL(SYS_mlock, address, length, 0, 0, 0, 0));
        case 229: return errno_ret(USER_SYSCALL(SYS_munlock, address, length, 0, 0, 0, 0));
        case 284: return errno_ret(USER_SYSCALL(SYS_mlock2, address, length, flags, 0, 0, 0));
        default: return -ENOSYS;
    }
}
#endif
