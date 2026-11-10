/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Blocked signals stay in Linux's queues. Check creation, mask replacement,
 * readiness, signal records, invalid arguments and inherited descriptors in
 * ordinary fork and shared-mm VFORK children. */
.section .text
.global _start
_start:
    /* The optional "exec" mode needs this emulator in a private binfmt
     * namespace. It checks both inherited and close-on-exec descriptors. */
    li s9,0
    ld t0,0(sp)
    li t1,2
    bltu t0,t1,start
    ld t0,16(sp)
    lbu t0,0(t0)
    li t1,'a'
    beq t0,t1,after_exec
    li s9,1
start:
    /* Block SIGURG and SIGUSR1 before they can acquire a disposition. */
    li a0,0 /* SIG_BLOCK */
    la a1,blocked
    li a2,0
    li a3,8
    li a7,135
    ecall
    bnez a0,fail

    li a0,-1
    la a1,urgent
    li a2,8
    li a3,0x80800 /* SFD_CLOEXEC | SFD_NONBLOCK */
    li a7,74
    ecall
    bltz a0,fail
    mv s0,a0
    mv a0,s0
    li a1,1 /* F_GETFD */
    li a7,25
    ecall
    li t0,1
    bne a0,t0,fail
    mv a0,s0
    li a1,3 /* F_GETFL */
    li a7,25
    ecall
    li t0,0x800
    and a0,a0,t0
    beqz a0,fail
    call empty

    /* epoll uses the RV64 (unpacked) event ABI. */
    li a0,0
    li a7,20
    ecall
    bltz a0,fail
    mv s1,a0
    mv a0,s1
    li a1,1 /* EPOLL_CTL_ADD */
    mv a2,s0
    la a3,event
    li a7,21
    ecall
    bnez a0,fail

    li a7,172
    ecall
    mv s2,a0
    li a7,174
    ecall
    mv s3,a0
    mv a0,s2
    li a1,23 /* SIGURG */
    li a7,129
    ecall
    bnez a0,fail
    mv a0,s1
    la a1,events
    li a2,1
    li a3,0
    li a4,0
    li a5,8
    li a7,22
    ecall
    li t0,1
    bne a0,t0,fail
    la t0,events
    lw t1,0(t0)
    andi t1,t1,1
    beqz t1,fail
    ld t1,8(t0)
    li t2,0x1234
    bne t1,t2,fail
    li s4,23
    call receive
    call empty

    /* A thread-directed signal must be visible to that thread's read. */
    li a7,178
    ecall
    mv a1,a0
    mv a0,s2
    li a2,23
    li a7,131
    ecall
    bnez a0,fail
    call receive

    /* Replacing the mask returns the same fd and retains status flags.
     * SIGUSR1 is already queued when it becomes part of the signalfd. */
    mv a0,s2
    li a1,10
    li a7,129
    ecall
    bnez a0,fail
    call empty
    mv a0,s0
    la a1,user
    li a2,8
    li a3,0
    li a7,74
    ecall
    bne a0,s0,fail
    li s4,10
    call receive
    call empty

    /* Error paths, including the private executable pin. That descriptor is
     * normally 1024 (64 with a small limit); /proc must not reveal it. */
    li a0,-1
    la a1,user
    li a2,7
    li a3,0
    li s5,-22
    call error
    li a0,-1
    li a1,1
    li a2,8
    li a3,0
    li s5,-14
    call error
    li a0,-1
    la a1,user
    li a2,8
    li a3,1
    li s5,-22
    call error
    li a0,-2
    la a1,user
    li a2,8
    li a3,0
    li s5,-9
    call error
    mv a0,s1 /* An epoll descriptor is not a signalfd. */
    la a1,user
    li a2,8
    li a3,0
    li s5,-22
    call error
    li a0,1024
    la a1,user
    li a2,8
    li a3,0
    li s5,-9
    call error
    li a0,64
    la a1,user
    li a2,8
    li a3,0
    call error
    mv a0,s0
    la a1,record
    li a2,127
    li a7,63
    ecall
    li t0,-22
    bne a0,t0,fail

    /* A child reads its own signals through the inherited descriptor. */
    li s6,17 /* SIGCHLD: ordinary fork */
    call fork_test
    li s6,0x4111 /* CLONE_VM | CLONE_VFORK | SIGCHLD */
    call fork_test
    call empty
    beqz s9,pass
    mv a0,s0
    li a1,10
    li a2,0
    li a7,24 /* dup3 */
    ecall
    li t0,10
    bne a0,t0,fail
    mv a0,s0
    li a1,11
    li a2,0x80000
    li a7,24
    ecall
    li t0,11
    bne a0,t0,fail
    ld a0,8(sp)
    la a1,exec_argv
    sd a0,0(a1)
    ld t0,0(sp)
    slli t0,t0,3
    add a2,sp,t0
    addi a2,a2,16
    li a7,221
    ecall
    j fail
after_exec:
    li s0,10
    li s4,10
    li a0,11
    li a1,1
    li a7,25
    ecall
    li t0,-9
    bne a0,t0,fail
    call empty
    li a7,174
    ecall
    mv s3,a0
    li a7,172
    ecall
    mv s2,a0
    li a1,10
    li a7,129
    ecall
    bnez a0,fail
    call receive
pass:
    li a0,0
    j exit

fork_test:
    mv s7,ra
    mv a0,s6
    li a1,0
    li a2,0
    li a3,0
    li a4,0
    li a7,220
    ecall
    bltz a0,fail
    beqz a0,child
    mv s8,a0
    la a1,status
    li a2,0
    li a3,0
    li a7,260
    ecall
    bne a0,s8,fail
    la t0,status
    lw t0,0(t0)
    bnez t0,fail
    mv ra,s7
    ret
child:
    li a7,172
    ecall
    mv s2,a0
    li a1,10
    li a7,129
    ecall
    bnez a0,fail
    call receive
    li a0,0
    j exit

receive:
    mv a0,s0
    la a1,record
    li a2,128
    li a7,63
    ecall
    li t0,128
    bne a0,t0,fail
    la t0,record
    lw t1,0(t0)
    bne t1,s4,fail
    lw t1,12(t0)
    bne t1,s2,fail
    lw t1,16(t0)
    bne t1,s3,fail
    ret
empty:
    mv a0,s0
    la a1,record
    li a2,128
    li a7,63
    ecall
    li t0,-11 /* EAGAIN */
    bne a0,t0,fail
    ret
error:
    li a7,74
    ecall
    bne a0,s5,fail
    ret
fail:
    li a0,1
exit:
    li a7,94
    ecall
.section .rodata
.balign 8
blocked: .quad (1 << 22) | (1 << 9)
urgent: .quad 1 << 22
user: .quad 1 << 9
.balign 8
event: .quad 1,0x1234
after: .asciz "after"
.section .data
.balign 8
exec_argv: .quad 0,after,0
.section .bss
.balign 8
record: .zero 128
events: .zero 16
status: .zero 4
