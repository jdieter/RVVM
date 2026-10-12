/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A full guest table must allow vfork close actions; pidfds need a guest slot. */
.section .text
.global _start
_start:
    li a7, 172
    ecall
    mv s0, a0
    li a0, 0
    li a1, 7 /* RLIMIT_NOFILE */
    li a2, 0
    la a3, limits
    li a7, 261
    ecall
    bnez a0, fail
    la t0, limits
    li t1, 24
    sd t1, 0(t0)
    li a0, 0
    li a1, 7
    mv a2, t0
    li a3, 0
    ecall
    bnez a0, fail
fill:
    li a0, -100
    la a1, null_path
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    bgez a0, fill
    li t0, -24
    bne a0, t0, fail
    /* PIDFD allocation must fail before a child is created. */
    li a0, 0x5111
    la a1, child_stack_end
    la a2, pidfd
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    li t0, -24
    bne a0, t0, fail
    li a0, 0x4111
    la a1, child_stack_end
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s1, a0
    jal ra, wait_child
    /* The parent table remains full after the private close actions. */
    li a0, -100
    la a1, null_path
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    li t0, -24
    bne a0, t0, fail
    li a0, 23
    li a7, 57
    ecall
    bnez a0, fail
    li a0, 0x5111
    la a1, child_stack_end
    la a2, pidfd
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s1, a0
    la t0, pidfd
    lw t0, 0(t0)
    li t1, 23
    bne t0, t1, fail
    jal ra, wait_child
    /* Private services must also stay out of __WALL waits. */
    li a0, -1
    la a1, status
    li a2, 0x40000001
    li a3, 0
    li a7, 260
    ecall
    li t0, -10
    bne a0, t0, fail
    li a0, 0
    j exit
wait_child:
    mv a0, s1
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s1, fail
    la t0, status
    lw t0, 0(t0)
    bnez t0, fail
    ret
child:
    li a7, 173
    ecall
    bne a0, s0, fail
    li a0, 0
    li a1, 7
    li a2, 0
    la a3, observed
    li a7, 261
    ecall
    bnez a0, fail
    la t0, observed
    la t1, limits
    ld t2, 0(t0)
    ld t3, 0(t1)
    bne t2, t3, fail
    ld t2, 8(t0)
    ld t3, 8(t1)
    bne t2, t3, fail
    /* Anonymous mappings must work before close actions free a guest slot. */
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
    li a0, 3
    li a1, -1
    li a2, 0
    li a7, 436
    ecall
    bnez a0, fail
    li a0, -100
    la a1, null_path
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    li t0, 3
    bne a0, t0, fail
    la a0, missing_path
    la a1, missing_arguments
    li a2, 0
    li a7, 221
    ecall
    li t0, -2
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
limits: .quad 0, 0
observed: .quad 0, 0
pidfd: .word -1
status: .word 0
missing_arguments: .quad missing_path, 0
null_path: .asciz "/dev/null"
missing_path: .asciz "/rvvm-vfork-definitely-missing"
.section .bss
.balign 16
child_stack: .skip 65536
child_stack_end:
