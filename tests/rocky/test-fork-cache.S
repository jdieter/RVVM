/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A CLONE_FILES grandchild must retain its guard after its parent is reaped
 * and the original parent repeatedly forks again. */
.section .text
.global _start
_start:
    li a0, 36 /* PR_SET_CHILD_SUBREAPER */
    li a1, 1
    li a7, 167
    ecall
    bnez a0, fail
    la a0, channel
    li a1, 0
    li a7, 59
    ecall
    bnez a0, fail
    li a0, 17
    jal fork
    beqz a0, child
    bltz a0, fail
    jal reap
    li s0, 32
again:
    li a0, 17
    jal fork
    beqz a0, success
    bltz a0, fail
    jal reap
    addi s0, s0, -1
    bnez s0, again
    la t0, channel
    lw a0, 4(t0)
    la a1, byte
    li a2, 1
    li a7, 64
    ecall
    li t0, 1
    bne a0, t0, fail
    li a0, -1
    jal reap
success:
    li a0, 0
    j exit
child:
    li a0, 0x411 /* CLONE_FILES | SIGCHLD */
    jal fork
    bltz a0, fail
    bnez a0, success
    la t0, channel
    lw a0, 0(t0)
    la a1, byte
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, fail
    /* Exercise the surviving shared guard after the cache was retired. */
    li a0, -100
    la a1, null_path
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    bltz a0, fail
    li a7, 57
    ecall
    bnez a0, fail
    j success
fork:
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    ret
reap:
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    blez a0, fail
    la t0, status
    lw t0, 0(t0)
    bnez t0, fail
    ret
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .rodata
null_path: .asciz "/dev/null"
.section .bss
.balign 8
channel: .skip 8
status: .skip 8
byte: .skip 1
