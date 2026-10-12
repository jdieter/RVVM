/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Invalid grow flags and alignment must reach kernel validation first. */
.section .text
.global _start
_start:
    li a0, -1
    li a1, 4096
    li a2, -1
    li a7, 226
    ecall
    li t0, -22
    bne a0, t0, fail
    li a0, 1
    li a1, 4096
    li a2, 0x1000001
    ecall
    bne a0, t0, fail
    li a0, 0
    li a1, 4096
    li a2, 0x3000001
    ecall
    bne a0, t0, fail
    li a0, 1
    li a1, 0
    li a2, 0x1000001
    ecall
    bne a0, t0, fail
    li a0, 0
    li a7, 94
    ecall
fail:
    li a0, 1
    li a7, 94
    ecall
