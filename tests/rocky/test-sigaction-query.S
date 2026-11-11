/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Valgrind probes dispositions in order and stops at the first error.
 * Rejecting a SIGKILL query leaves its SIGSEGV handler uninstalled. */
.section .text
.global _start
_start:
    li s0, 9 /* SIGKILL, then SIGSTOP */
next_signal:
    mv a0, s0
    li a1, 0
    la a2, old
    li a3, 8
    li a7, 134
    ecall
    bnez a0, fail
    la t0, old
    ld t1, 0(t0)
    ld t2, 8(t0)
    or t1, t1, t2
    ld t2, 16(t0)
    or t1, t1, t2
    bnez t1, fail

    /* A no-output query succeeds, but an inaccessible output is EFAULT. */
    mv a0, s0
    li a2, 0
    ecall
    bnez a0, fail
    mv a0, s0
    li a2, 1
    ecall
    li t0, -14
    bne a0, t0, fail

    /* Neither default nor caught dispositions may be installed. */
    mv a0, s0
    la a1, action
    li a2, 0
    ecall
    li t0, -22
    bne a0, t0, fail
    la t1, action
    la t2, fail
    sd t2, 0(t1)
    mv a0, s0
    ecall
    bne a0, t0, fail
    sd zero, 0(t1)

    li t0, 19
    beq s0, t0, done
    mv s0, t0
    j next_signal
done:
    li a0, 0
    li a7, 94
    ecall
fail:
    li a0, 1
    li a7, 94
    ecall
.section .bss
.balign 8
action: .zero 24
old: .zero 24
