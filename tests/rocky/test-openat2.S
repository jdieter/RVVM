/* SPDX-License-Identifier: GPL-3.0-or-later */
.section .text
.global _start
_start:
    li a0, -100
    li a1, 1
    la a2, how
    li a3, 24
    li a7, 437
    ecall
    li t0, -14
    bne a0, t0, fail
    li a0, 0
    li a7, 94
    ecall
fail:
    li a0, 1
    li a7, 94
    ecall
.section .data
.balign 8
how: .quad 0, 0, 0
