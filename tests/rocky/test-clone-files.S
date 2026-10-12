/* SPDX-License-Identifier: GPL-3.0-or-later */
/* CLONE_FILES shares descriptors, not guest memory. Both unshare and ordinary
 * fork must detach the emulator metadata along with the kernel table. */
.section .text
.global _start
_start:
    li s1, 0
again:
    li a0, -100
    la a1, null_path
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    bltz a0, fail
    mv s0, a0
    li a0, 0x411
    li t0, 2
    bne s1, t0, 1f
    li a0, 17
1:
    li t0, 3
    bne s1, t0, 2f
    li a0, 0x100411
2:
    li t0, 4
    bne s1, t0, 3f
    li a0, 0x1411
3:
    la a1, child_stack_end
    la a2, published
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s2, a0
    li t0, 3
    bne s1, t0, 4f
    la t0, published
    lw t0, 0(t0)
    bne t0, s2, fail
4:
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s2, fail
    la t0, status
    lw t0, 0(t0)
    bnez t0, fail
    la t0, sentinel
    lw t0, 0(t0)
    li t1, 123
    bne t0, t1, fail
    mv a0, s0
    li a1, 1 /* F_GETFD */
    li a2, 0
    li a7, 25
    ecall
    li t0, 1
    beq s1, t0, private
    li t0, 2
    beq s1, t0, private
    li t0, -9
    bne a0, t0, fail
    j next
private:
    bltz a0, fail
    mv a0, s0
    li a7, 57
    ecall
    bnez a0, fail
next:
    li t0, 4
    bne s1, t0, 5f
    la t0, published
    lw a0, 0(t0)
    li a7, 57
    ecall
    bnez a0, fail
5:
    addi s1, s1, 1
    li t0, 5
    bne s1, t0, again
    li a0, 0
    j exit
child:
    la t0, sentinel
    sw zero, 0(t0)
    mv a0, s0
    mv a1, s0
    li a2, 0
    li t0, 1
    bne s1, t0, 6f
    li a2, 2 /* CLOSE_RANGE_UNSHARE */
6:
    li a7, 436
    ecall
    bnez a0, fail
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .rodata
null_path: .asciz "/dev/null"
.section .data
sentinel: .word 123
.section .bss
.balign 16
published: .skip 8
status: .skip 8
child_stack: .skip 65536
child_stack_end:
