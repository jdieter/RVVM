/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Go's random fallback needs a real guest filter, without filtering RVVM. */
.section .text
.global _start
_start:
    li a0, 21 /* PR_GET_SECCOMP */
    li a7, 167
    ecall
    bnez a0, fail
    li a0, 38 /* PR_SET_NO_NEW_PRIVS */
    li a1, 1
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 167
    ecall
    bnez a0, fail
    li a0, 1 /* SECCOMP_SET_MODE_FILTER */
    li a1, 0
    la a2, program
    li a7, 277
    ecall
    bnez a0, fail
    /* The filter must be copied rather than retained in guest memory. */
    la t0, error_action
    sw zero, 0(t0)
    la a0, buffer
    li a1, 1
    li a2, 0
    li a7, 278 /* getrandom */
    ecall
    li t0, -38
    bne a0, t0, fail
    li a0, 21
    li a7, 167
    ecall
    li t0, 2
    bne a0, t0, fail
    li a7, 172
    ecall
    blez a0, fail
    /* A second policy through prctl must preserve the first. */
    li a0, 22 /* PR_SET_SECCOMP */
    li a1, 2
    la a2, zero_program
    li a7, 167
    ecall
    bnez a0, fail
    li a7, 172
    ecall
    bnez a0, fail /* ERRNO(0) skips getpid and returns zero. */
    li a7, 278
    ecall
    li t0, -38
    bne a0, t0, fail
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .data
.balign 8
program:
    .half 4
    .zero 6
    .dword filter
filter:
    .half 0x20 /* LD W ABS nr */
    .byte 0, 0
    .word 0
    .half 0x15 /* JEQ getrandom */
    .byte 0, 1
    .word 278
    .half 6
    .byte 0, 0
error_action:
    .word 0x50026 /* ERRNO | ENOSYS */
    .half 6
    .byte 0, 0
    .word 0x7fff0000
zero_program:
    .half 4
    .zero 6
    .dword zero_filter
zero_filter:
    .half 0x20
    .byte 0, 0
    .word 0
    .half 0x15
    .byte 0, 1
    .word 172
    .half 6
    .byte 0, 0
    .word 0x50000
    .half 6
    .byte 0, 0
    .word 0x7fff0000
.section .bss
buffer: .skip 1
