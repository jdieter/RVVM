/* SPDX-License-Identifier: GPL-3.0-or-later */
/* /proc/self/cmdline shows the guest's own arguments, and follows them when
 * the guest rewrites them in place, as setproctitle does (Ruby's $0=, the
 * check in TestRubyOptions#test_setproctitle). */
.equ BUFFER_SIZE, 65536
.equ TITLE_SIZE, 12
.section .text
.global _start
_start:
    ld s0, 0(sp)
    beqz s0, fail
    addi s1, sp, 8
    ld s2, 0(s1)
    /* The kernel's arg_end: just past the last argument's NUL. */
    slli t0, s0, 3
    add t0, s1, t0
    ld s3, -8(t0)
1:
    lbu t1, 0(s3)
    addi s3, s3, 1
    bnez t1, 1b
    ld s4, 8(t0)
    sub s5, s3, s2

    /* Unchanged arguments: exactly [arg_start, arg_end). */
    call read_cmdline
    bne a0, s5, fail
    mv a0, s2
    la a1, buffer
    mv a2, s5
    call compare
    bnez a0, fail

    /* A shorter title, padded with NULs: still the whole argument area. */
    la t0, title
    mv t1, s2
2:
    lbu t2, 0(t0)
    sb t2, 0(t1)
    addi t0, t0, 1
    addi t1, t1, 1
    bnez t2, 2b
3:
    bgeu t1, s3, 4f
    sb zero, 0(t1)
    addi t1, t1, 1
    j 3b
4:
    call read_cmdline
    bne a0, s5, fail
    la a0, title
    la a1, buffer
    li a2, TITLE_SIZE
    call compare
    bnez a0, fail

    /* A longer title runs on into the environment's strings, which follow
     * the arguments; the kernel follows it to its NUL. */
    bne s4, s3, pass
    li t0, 'A'
    mv t1, s2
5:
    sb t0, 0(t1)
    addi t1, t1, 1
    bltu t1, s3, 5b
    li t0, 'B'
    sb t0, 0(s3)
    sb zero, 1(s3)
    call read_cmdline
    addi t0, s5, 2
    bne a0, t0, fail
    la t0, buffer
    add t1, t0, s5
    li t2, 'A'
6:
    lbu t3, 0(t0)
    bne t3, t2, fail
    addi t0, t0, 1
    bltu t0, t1, 6b
    lbu t3, 0(t1)
    li t2, 'B'
    bne t3, t2, fail
    lbu t3, 1(t1)
    bnez t3, fail
pass:
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 93
    ecall

/* Returns the length of /proc/self/cmdline, read into buffer, or -1. */
read_cmdline:
    li a0, -100
    la a1, path
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    bltz a0, 3f
    mv t4, a0
    la t5, buffer
    li t6, 0
1:
    mv a0, t4
    add a1, t5, t6
    li a2, BUFFER_SIZE
    sub a2, a2, t6
    beqz a2, 2f
    li a7, 63
    ecall
    bltz a0, 2f
    beqz a0, 4f
    add t6, t6, a0
    j 1b
2:
    li t6, -1
4:
    mv a0, t4
    li a7, 57
    ecall
    mv a0, t6
    ret
3:
    li a0, -1
    ret

/* Compares a2 bytes at a0 and a1; returns zero when they match. */
compare:
    beqz a2, 2f
1:
    lbu t0, 0(a0)
    lbu t1, 0(a1)
    bne t0, t1, 3f
    addi a0, a0, 1
    addi a1, a1, 1
    addi a2, a2, -1
    bnez a2, 1b
2:
    li a0, 0
    ret
3:
    li a0, 1
    ret

.section .rodata
path:
    .asciz "/proc/self/cmdline"
title:
    .asciz "hello world"

.section .bss
buffer:
    .zero BUFFER_SIZE
