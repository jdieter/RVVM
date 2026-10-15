/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <string.h>
#include "core/rvvm_user.h"

/* Exercise the direct public API; rvvm_user_main selects binfmt credentials. */
int main(int argc, char** argv)
{
    int first = argc > 1 && !strcmp(argv[1], "-user") ? 2 : 1;
    assert(argc > first);
    return rvvm_user_linux(argc - first, argv + first, NULL);
}
