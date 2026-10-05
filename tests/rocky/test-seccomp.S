/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Reject both interfaces without advertising or installing a guest filter. */
.section .text
.global _start
_start:
    la s0, operations
    la s1, operations_end
1:
    lw a0, 0(s0)
    li a1, 0
    li a2, 0
    li a7, 277
    ecall
    li t0, -38
    bne a0, t0, fail
    lw a0, 0(s0)
    li a1, -1
    li a2, -1
    li a7, 277
    ecall
    li t0, -38
    bne a0, t0, fail
    addi s0, s0, 4
    bne s0, s1, 1b
    /* Even a valid allow-all filter must report unsupported. */
    li a0, 1
    li a1, 0
    la a2, program
    li a7, 277
    ecall
    li t0, -38
    bne a0, t0, fail
    li a0, 22
    li a1, 2
    la a2, program
    li a3, 0
    li a4, 0
    li a7, 167
    ecall
    li t0, -22
    bne a0, t0, fail
    /* Query, strict mode, filter mode, and an invalid mode via prctl. */
    li a0, 21
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 167
    ecall
    li t0, -22
    bne a0, t0, fail
    li s0, -1
2:
    li a0, 22
    mv a1, s0
    li a2, -1
    li a7, 167
    ecall
    li t0, -22
    bne a0, t0, fail
    addi s0, s0, 1
    li t0, 3
    bne s0, t0, 2b
    /* Rejection must leave normal syscalls available. */
    li a7, 172
    ecall
    blez a0, fail
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .rodata
.balign 4
operations:
    .word 0, 1, 2, 3, -1
operations_end:
.balign 8
program:
    .half 1
    .zero 6
    .dword filter
filter:
    .half 6 /* BPF_RET | BPF_K */
    .byte 0, 0
    .word 0x7fff0000 /* SECCOMP_RET_ALLOW */
