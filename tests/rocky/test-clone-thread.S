/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A forked process owns separate signal actions; its pthread shares them
 * and must retain them after the original process thread exits. No libc needed. */
.section .text
.global _start
_start:
    li s5, 1
    li a0, 10
    la a1, parent_action
    li a2, 0
    li a3, 8
    li a7, 134
    ecall
    bnez a0, fail
    li a0, 0x11
    la a1, child_stack_end
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s0, a0
    li s5, 2
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s0, fail
    la t0, status
    lw t1, 0(t0)
    beqz t1, 2f
    srli a0, t1, 8
    j group_exit
2:
    li s5, 3
    la t0, hits
    lw t1, 0(t0)
    bnez t1, fail
    li a0, 10
    li a1, 0
    li s5, 4
    la a2, old_action
    li a3, 8
    li a7, 134
    ecall
    bnez a0, fail
    la t0, old_action
    ld t1, 0(t0)
    la t2, parent_handler
    bne t1, t2, fail
    li a0, 0
    j group_exit
child:
    li s5, 5
    li a7, 172
    ecall
    la t0, child_pid
    sw a0, 0(t0)
    li a0, 10
    la a1, child_action
    li a2, 0
    li a3, 8
    li a7, 134
    ecall
    bnez a0, fail
    li a0, 0x50f00
    li s5, 6
    la a1, thread_stack_end
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, worker
    bltz a0, fail
    la t0, thread_ready
3:  fence
    lw t1, 0(t0)
    beqz t1, 3b
    la t0, leader_done
    li t1, 1
    sw t1, 0(t0)
    fence
    li a0, 0
    li a7, 93
    ecall
worker:
    li s5, 10
    li a0, 10
    li a1, 0
    la a2, old_action
    li a3, 8
    li a7, 134
    ecall
    bnez a0, fail
    li s5, 11
    la t0, old_action
    ld t1, 0(t0)
    la t2, child_handler
    bne t1, t2, fail
    la t0, thread_ready
    li t1, 1
    sw t1, 0(t0)
    fence
    li s5, 7
    la t0, leader_done
1:  fence
    lw t1, 0(t0)
    beqz t1, 1b
    la a0, delay
    li a1, 0
    li a7, 101
    ecall
    li a0, 10
    la a1, thread_action
    la a2, old_action
    li a3, 8
    li a7, 134
    ecall
    bnez a0, fail
    la t0, old_action
    li s5, 8
    ld t1, 0(t0)
    la t2, child_handler
    bne t1, t2, fail
    li a7, 178
    li s5, 9
    ecall
    mv a1, a0
    la t0, child_pid
    lw a0, 0(t0)
    li a2, 10
    li a7, 131
    ecall
    bnez a0, fail
    la t0, hits
    lw t1, 0(t0)
    li t2, 10
    bne t1, t2, fail
    li a0, 0
    li a7, 93
    ecall
parent_handler:
    li t1, 1
    j store_hits
child_handler:
    li t1, 2
    j store_hits
thread_handler:
    li t1, 10
store_hits:
    la t0, hits
    sw t1, 0(t0)
    ret
fail:
    mv a0, s5
group_exit:
    li a7, 94
    ecall
.section .data
.balign 8
parent_action: .dword parent_handler, 0, 0
child_action: .dword child_handler, 0, 0
thread_action: .dword thread_handler, 0, 0
delay: .dword 0, 20000000
.section .bss
.balign 16
old_action: .skip 24
status: .skip 8
hits: .skip 4
child_pid: .skip 4
leader_done: .skip 4
thread_ready: .skip 4
.balign 16
child_stack: .skip 65536
child_stack_end:
thread_stack: .skip 65536
thread_stack_end:
