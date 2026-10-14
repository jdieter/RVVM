/* SPDX-License-Identifier: GPL-3.0-or-later */
/* getfd is unsupported regardless of arguments or allocation limits. The
 * other pidfd operations must retain their real kernel behavior. */
.section .text
.global _start
_start:
    li a7,172
    ecall
    li a1,0
    li a7,434
    ecall
    bltz a0,fail
    mv s0,a0
    li a1,0
    li a2,0
    li a3,0
    li a7,424
    ecall
    bnez a0,fail

    mv a0,s0
    li a1,1
    li a2,0
    jal check_getfd
    li a0,-1
    li a1,-1
    li a2,-1
    jal check_getfd
    mv a0,s0
    li a1,64
    li a2,0
    jal check_getfd
    mv a0,s0
    li a1,1024
    li a2,0
    jal check_getfd

    li a0,0
    li a1,7 /* RLIMIT_NOFILE */
    la a2,no_slots
    li a3,0
    li a7,261
    ecall
    bnez a0,fail
    mv a0,s0
    li a1,1
    li a2,0
    jal check_getfd
    li a0,-1
    li a1,1024
    li a2,1
    jal check_getfd
    li a0,0
    j exit
check_getfd:
    li a7,438
    ecall
    li t0,-38
    bne a0,t0,fail
    ret
fail:
    li a0,1
exit:
    li a7,94
    ecall
.section .rodata
.balign 8
no_slots:
    .quad 0,0
