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
    /* The main guest can exit while the reaper is retiring. Its status
     * must survive the last native helper's pthread cleanup. */
    li s0, 16
2:
    li a0, 17
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, process
    bltz a0, fail
    mv s1, a0
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s1, fail
    la t0, status
    lw t1, 0(t0)
    li t2, 1792
    bne t1, t2, fail
    addi s0, s0, -1
    bnez s0, 2b
    li a0, 0
    j exit
process:
    la t0, tid
    li t1, 1
    sw t1, 0(t0)
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
3:  fence
    lw t1, 0(t0)
    bnez t1, 3b
    li a0, 7
    li a7, 93
    ecall
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
status:
    .word 0
.section .bss
.balign 16
    .space 65536
stack_end:
