/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Child writes and exec errors must be visible before clone returns. */
.section .text
.global _start
_start:
    ld t0, 0(sp)
    li t1, 2
    beq t0, t1, executed
    /* A live kernel PI lock cannot survive temporary futex-key migration. */
    la a0, pi_lock
    li a1, 134 /* FUTEX_LOCK_PI_PRIVATE */
    li a2, 0
    li a3, 0
    li a4, 0
    li a5, 0
    li a7, 98
    ecall
    bnez a0, fail
    li a0, 0x4111
    la a1, child_stack_end
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    li t0, -38 /* Explicitly unsupported with a live PI lock. */
    bne a0, t0, fail
    la a0, pi_lock
    li a1, 135 /* FUTEX_UNLOCK_PI_PRIVATE */
    li a2, 0
    li a7, 98
    ecall
    bnez a0, fail
    ld t0, 8(sp)
    la t1, arguments
    sd t0, 0(t1)
    la a0, pipe_fds
    li a1, 0
    li a7, 59
    ecall
    bnez a0, fail
    la t0, pipe_fds
    lw t0, 0(t0)
    la t1, descriptor_end
    sb zero, 0(t1)
    li t3, 10
1:
    remu t2, t0, t3
    addi t2, t2, 48
    addi t1, t1, -1
    sb t2, 0(t1)
    divu t0, t0, t3
    bnez t0, 1b
    la t0, arguments
    sd t1, 8(t0)
    li a0, 0x01204111 /* VM | VFORK | CHILD_SETTID | CHILD_CLEARTID | SIGCHLD */
    la a1, child_stack_end
    li a2, 0
    li a3, 0
    la a4, child_tid
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s0, a0
    la t0, child_tid
    lw t1, 0(t0)
    bnez t1, fail
    la t0, shared
    ld t1, 0(t0)
    li t2, -2 /* ENOENT */
    bne t1, t2, fail
    la t0, new_mapping
    ld t0, 0(t0)
    ld t1, 0(t0)
    li t2, 88
    bne t1, t2, fail
    la t0, pipe_fds
    lw a0, 4(t0)
    la a1, status
    li a2, 1
    li a7, 64
    ecall
    li t0, 1
    bne a0, t0, fail
    mv a0, s0
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s0, fail
    la t0, status
    lw t1, 0(t0)
    bnez t1, fail
    li a0, 0
    j exit
child:
    la a0, missing
    la a1, missing_arguments
    li a2, 0
    li a7, 221
    ecall
    la t0, shared
    sd a0, 0(t0)
    /* Mapping changes must survive child exec in the suspended parent. */
    li a0, 0
    li a1, 4096
    li a2, 3
    li a3, 0x22
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    bltz a0, fail
    mv s1, a0
    li t0, 77
    sd t0, 0(s1)
    li a1, 4096
    li a2, 8192
    li a3, 1
    li a4, 0
    li a7, 216
    ecall
    bltz a0, fail
    mv s1, a0
    ld t0, 0(s1)
    li t1, 77
    bne t0, t1, fail
    li t0, 4096
    add s2, s1, t0
    sd t1, 0(s2)
    mv a0, s2
    li a1, 4096
    li a2, 4 /* MADV_DONTNEED must discard private anonymous bytes. */
    li a7, 233
    ecall
    bnez a0, fail
    ld t0, 0(s2)
    bnez t0, fail
    li t0, 88
    sd t0, 0(s2)
    mv a0, s1
    li a1, 4096
    li a7, 215
    ecall
    bnez a0, fail
    mv a0, s2
    li a1, 4096
    li a2, 1
    li a7, 226
    ecall
    bnez a0, fail
    la t0, new_mapping
    sd s2, 0(t0)
    la a1, arguments
    ld a0, 0(a1)
    li a2, 0
    li a7, 221
    ecall
    j fail
executed:
    /* If clone waited for exit instead of exec, this read would deadlock. */
    ld t0, 16(sp)
    li a0, 0
    li t2, 10
2:
    lbu t1, 0(t0)
    beqz t1, 3f
    addi t1, t1, -48
    mul a0, a0, t2
    add a0, a0, t1
    addi t0, t0, 1
    j 2b
3:
    la a1, status
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, fail
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .data
.balign 8
pi_lock: .word 0, 0
child_tid: .word 111, 0
shared: .quad 123
new_mapping: .quad 0
arguments: .quad 0, 0, 0
missing_arguments: .quad missing, 0
missing: .asciz "/rvvm-vfork-definitely-missing"
.section .bss
.balign 16
status: .skip 8
pipe_fds: .skip 8
descriptor: .skip 23
descriptor_end: .skip 1
child_stack: .skip 65536
child_stack_end:
