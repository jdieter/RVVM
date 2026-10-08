/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Recycle fault metadata while the host refuses new address-space mappings. */
.section .text
.global _start
_start:
    li a0, 0
    li a1, 9 /* RLIMIT_AS */
    la a2, limit
    li a3, 0
    li a7, 261
    ecall
    bnez a0, fail
    la s0, value
    li s1, 0
    .rept 20000
    ld t0, 0(s0)
    add s1, s1, t0
    .endr
    li t0, 140000
    bne s1, t0, fail
    li a0, 0
    li a7, 214
    ecall
    mv s0, a0
    li t0, 4096
    add a0, a0, t0
    ecall
    bne a0, s0, fail
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .data
.balign 8
limit: .quad 1, -1
value: .quad 7
