/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Concurrent private-files threads must never inherit each other's VM peer. */
.section .text
.global _start
_start:
    la a0, ready_pipe
    li a1, 0
    li a7, 59
    ecall
    bnez a0, fail
    la a0, reply_pipe
    ecall
    bnez a0, fail
    li s5, 0
    li a0, 0x01310900
    la a1, thread_stack_end
    la a2, tid
    li a3, 0
    la a4, tid
    li a7, 220
    ecall
    beqz a0, thread
    bltz a0, fail
    la s0, child_stack_a_end
    la s1, result_a
    li s3, 1
    j ready
thread:
    la s0, child_stack_b_end
    la s1, result_b
    li s3, 0
ready:
    la t0, barrier
    li t1, 1
    amoadd.w t2, t1, (t0)
1:
    lw t1, 0(t0)
    li t2, 2
    bne t1, t2, 1b
    li s2, 16
again:
    li a0, 0x4111
    mv a1, s0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s4, a0
    ld a0, 0(s1)
    ld t0, 0(a0)
    li t1, 77
    bne t0, t1, fail
    li a1, 4096
    li a7, 215
    ecall
    bnez a0, fail
    mv a0, s4
    addi a1, s1, 8
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s4, fail
    lw t0, 8(s1)
    bnez t0, fail
    addi s2, s2, -1
    bnez s2, again
    beqz s3, parent_mapping
    /* VFORK without VM must let another parent thread map memory while the
     * child waits for that thread's reply. Holding transition would deadlock. */
    li s5, 1
    li a0, 0x4011
    mv a1, s0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s4, a0
    addi a1, s1, 8
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s4, fail
    lw t0, 8(s1)
    bnez t0, fail
    la t0, tid
2:
    fence
    lw t1, 0(t0)
    bnez t1, 2b
    li a0, 0
    li a7, 94
    ecall
thread_exit:
    li a0, 0
    li a7, 93
    ecall
child:
    bnez s5, private_child
    li a0, 0
    li a1, 4096
    li a2, 3
    li a3, 0x22
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    bltz a0, fail
    li t0, 77
    sd t0, 0(a0)
    sd a0, 0(s1)
    j thread_exit
parent_mapping:
    la t0, ready_pipe
    lw a0, 0(t0)
    la a1, byte
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, fail
    li a0, 0
    li a1, 4096
    li a2, 3
    li a3, 0x22
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    bltz a0, fail
    li a1, 4096
    li a7, 215
    ecall
    bnez a0, fail
    la t0, reply_pipe
    lw a0, 4(t0)
    la a1, byte
    li a2, 1
    li a7, 64
    ecall
    li t0, 1
    bne a0, t0, fail
    j thread_exit
private_child:
    la t0, ready_pipe
    lw a0, 4(t0)
    la a1, byte
    li a2, 1
    li a7, 64
    ecall
    li t0, 1
    bne a0, t0, fail
    la t0, reply_pipe
    lw a0, 0(t0)
    la a1, byte
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, fail
    j thread_exit
fail:
    li a0, 1
    li a7, 94
    ecall
.section .data
.balign 8
tid: .word 1
barrier: .word 0
result_a: .quad 0, 0
result_b: .quad 0, 0
ready_pipe: .word 0, 0
reply_pipe: .word 0, 0
byte: .byte 1
.section .bss
.balign 16
    .skip 65536
thread_stack_end:
    .skip 65536
child_stack_a_end:
    .skip 65536
child_stack_b_end:
