/* SPDX-License-Identifier: GPL-3.0-or-later */
/* An unsupported huge-page size must reach the kernel, not become ordinary RAM. */
.section .text
.global _start
_start:
    li a0, 0
    li a1, 4096
    li a2, 3
    li a3, 0x04040022
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    li t0, -22
    xor a0, a0, t0
    snez a0, a0
    li a7, 94
    ecall
