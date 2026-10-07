/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest clear_child_tid must follow native kernel robust-list cleanup. */
.section .text
.global _start
_start:
    li a0, 0x01350f00
    la a1, stack_end
    la a2, tid
    li a3, 0
    la a4, tid
    li a7, 220
    ecall
    beqz a0, worker
    bltz a0, fail
    la t0, tid
1:  fence
    lw t1, 0(t0)
    bnez t1, 1b
    la t0, mutex
    lw t1, 0(t0)
    li t2, 0x40000000
    bne t1, t2, fail
    li a0, 0
    j exit
worker:
    li a7, 178
    ecall
    la t0, mutex
    sw a0, 0(t0)
    la a0, head
    li a1, 24
    li a7, 99
    ecall
    bnez a0, fail
    li a0, 0
    li a7, 93
    ecall
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .data
.balign 8
head:
    .dword node, 8, 0
node:
    .dword head
mutex:
    .word 0
tid:
    .word 1
.section .bss
.balign 16
    .space 65536
stack_end:
