/* SPDX-License-Identifier: GPL-3.0-or-later */
/* The guest stack grows into a free range below it, which mappings the host
 * kernel places itself must never take: they fill the highest free hole
 * below the host's mmap_base, top-down. The host's [vdso] lies in that
 * region, so it shows where host mappings start. Require the guest stack's
 * range to lie at least 256 GiB below it, or the vdso to lie below the range
 * (host mappings growing bottom-up, or far below). Run rvvm_user under
 * "setarch -R" on an x86-64 host for a deterministic check: without
 * randomization, mmap_base sits just below the top of the 48-bit window. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) { perror("maps"); return 1; }
    char line[512];
    unsigned long stack_start = 0, stack_end = 0, vdso_start = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) continue;
        if (strstr(line, "[stack]")) { stack_start = start; stack_end = end; }
        if (strstr(line, "[vdso]")) vdso_start = start;
    }
    fclose(maps);
    if (!stack_end || !vdso_start) {
        puts("SKIP no [stack] or [vdso] label in /proc/self/maps");
        return 0;
    }
    printf("stack %#lx-%#lx, vdso %#lx\n", stack_start, stack_end, vdso_start);
    if (vdso_start > stack_end && vdso_start - stack_end < (256UL << 30)) {
        printf("FAIL host mappings start %lu MiB above the guest stack, not 256 GiB\n",
               (vdso_start - stack_end) >> 20);
        return 1;
    }
    puts("PASS the guest stack's growth range lies clear of host-placed mappings");
    return 0;
}
