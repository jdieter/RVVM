/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Every object type is unsupported, without inspecting guest arguments. */
.section .text
.global _start
_start:
    li a7,172
    ecall
    mv s0,a0
    li s1,0
types:
    mv a0,s0
    mv a1,s0
    mv a2,s1
    li a3,1
    li a4,1 /* Also an inaccessible KCMP_EPOLL_TFD slot pointer. */
    jal check_kcmp
    addi s1,s1,1
    li t0,8
    blt s1,t0,types
    li a0,-1
    li a1,-1
    li a2,-1
    li a3,-1
    li a4,-1
    jal check_kcmp
    li a0,0
    li a1,7 /* RLIMIT_NOFILE */
    la a2,no_slots
    li a3,0
    li a7,261
    ecall
    bnez a0,fail
    mv a0,s0
    mv a1,s0
    li a2,0
    li a3,64
    li a4,1024
    jal check_kcmp
    li a0,0
    j exit
check_kcmp:
    li a7,272
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
