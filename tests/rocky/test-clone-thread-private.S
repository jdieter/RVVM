/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Minimal Linux thread flags leave files, umask and semaphore undo private. */
.section .text
.global _start
_start:
    la a0, name
    li a1, 0
    li a7, 279
    ecall
    bltz a0, fail
    mv s0, a0
    li a0, 077
    li a7, 166
    ecall
    li a0, 0
    li a1, 1
    li a2, 896 /* IPC_CREAT | 0600 */
    li a7, 190
    ecall
    bltz a0, fail
    mv s1, a0
    li a1, 0
    li a2, 16 /* SETVAL */
    li a3, 1
    li a7, 191
    ecall
    bnez a0, fail
    li a0, 0x01310900
    la a1, stack_end
    la a2, tid
    li a3, 0
    la a4, tid
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    la t0, tid
1:  fence
    lw t1, 0(t0)
    bnez t1, 1b
    mv a0, s0
    li a1, 1 /* F_GETFD */
    li a2, 0
    li a7, 25
    ecall
    bnez a0, fail
    li a0, 077
    li a7, 166
    ecall
    li t0, 077
    bne a0, t0, fail
    mv a0, s1
    li a1, 0
    li a2, 12 /* GETVAL */
    li a3, 0
    li a7, 191
    ecall
    li t0, 1
    bne a0, t0, fail
    mv a0, s1
    li a1, 0
    li a2, 0 /* IPC_RMID */
    li a3, 0
    li a7, 191
    ecall
    bnez a0, fail
    li a0, 0
    j exit
child:
    mv a0, s0
    li a7, 57
    ecall
    bnez a0, fail
    li a0, 022
    li a7, 166
    ecall
    mv a0, s1
    la a1, operation
    li a2, 1
    li a7, 193
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
.balign 4
tid: .word 1
operation: .half 0, -1, 4096 /* SEM_UNDO */
name: .asciz "clone-private"
.section .bss
.balign 16
    .skip 65536
stack_end:
