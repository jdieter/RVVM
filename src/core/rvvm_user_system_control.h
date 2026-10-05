/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_SYSTEM_CONTROL_H
#define RVVM_USER_SYSTEM_CONTROL_H

static long user_system_control(unsigned nr, uintptr_t a0, uintptr_t a1, uintptr_t a2)
{
    if (nr == 162) return errno_ret(syscall(SYS_setdomainname, a0, (int)a1));
    /* READ may block. Keep native capability checks and guest signal delivery;
     * successful destructive commands are implemented but never used by tests. */
    return errno_ret(USER_SYSCALL(SYS_syslog, (int)a0, a1, (int)a2, 0, 0, 0));
}
#endif
