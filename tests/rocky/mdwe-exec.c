/* SPDX-License-Identifier: GPL-3.0-or-later */
/* mdwe-exec PROGRAM [ARGS...]: run PROGRAM with Linux 6.3+ memory-deny-
 * write-execute, prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN), as systemd's
 * MemoryDenyWriteExecute=yes does where the kernel supports it. The kernel
 * then refuses writable-executable mappings and adding execute permission
 * with EACCES; children and executed programs inherit the restriction.
 *
 * Build it for the host and put it in front of the emulator:
 *   cc -O2 tests/rocky/mdwe-exec.c -o /tmp/mdwe-exec
 *   /tmp/mdwe-exec rvvm_user_x86_64 ./test-exec-refused
 * run-tests.sh does this for test-exec-refused.S. Exits with 77 when the
 * kernel lacks MDWE, so callers can skip. */
#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN 1
#endif

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s PROGRAM [ARGS...]\n", argv[0]);
        return 2;
    }
    if (prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0)) {
        int error = errno;
        perror("prctl(PR_SET_MDWE)");
        return error == EINVAL ? 77 : 2;
    }
    execvp(argv[1], argv + 1);
    perror(argv[1]);
    return 127;
}
