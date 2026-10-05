/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Portions Copyright (C) 2024 LekKit <github.com/LekKit> */
/* Accept both binfmt invocation and RVVM's internal execve restart. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <linux/binfmts.h>
#include "core/rvvm_user.h"

int main(int argc, char **argv)
{
    int first = argc > 1 && strcmp(argv[1], "-user") == 0 ? 2 : 1;
    if (argc <= first) {
        fprintf(stderr, "Usage: %s <guest_elf> [guest args...]\n", argv[0]);
        return 1;
    }
    const char* executable = argv[first];
    /* P registrations retain the original argv[0] after the executable path.
     * AT_FLAGS distinguishes them from direct invocations and old F handlers. */
    if (getauxval(AT_FLAGS) & AT_FLAGS_PRESERVE_ARGV0) first++;
    return rvvm_user_linux_binfmt(executable, argc - first, argv + first, NULL);
}
