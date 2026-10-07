/* SPDX-License-Identifier: GPL-3.0-or-later */
/* QEMU-compatible rejection must precede child creation and TID publication. */
.section .text
.global _start
_start:
    la s0, invalid_flags
    la s1, invalid_flags_end
1:
    lw a0, 0(s0)
    la a1, child_stack_end
    la a2, sentinel
    li a3, 0
    la a4, sentinel
    li a7, 220
    ecall
    li t0, -22
    bne a0, t0, fail
    la t0, sentinel
    lw t1, 0(t0)
    li t2, 123
    bne t1, t2, fail
    addi s0, s0, 4
    bne s0, s1, 1b
    /* Ignored IO/DETACHED flags must preserve ordinary fork isolation. */
    li a0, 0x80400011
    la a1, child_stack_end
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s0, a0
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s0, fail
    la t0, status
    lw t1, 0(t0)
    bnez t1, fail
    la t0, sentinel
    lw t1, 0(t0)
    li t2, 123
    bne t1, t2, fail
    li a0, 0
    j exit
child:
    la t0, sentinel
    sw zero, 0(t0)
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .data
.balign 4
invalid_flags:
    .word 0x111, 0x711, 0x911, 0x10f00
    .word 0x1500111, 0x51f00, 0x20000011, 0x8011
    .word 0x101011, 0x0, 0x11f00, 0x850f00
invalid_flags_end:
sentinel: .word 123
.section .bss
.balign 16
status: .skip 8
child_stack: .skip 65536
child_stack_end:
