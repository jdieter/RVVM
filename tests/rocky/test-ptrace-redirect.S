/* SPDX-License-Identifier: GPL-3.0-or-later */
/* vgdb redirects sleeping threads to its invoker. SETREGSET must leave the
 * host wait before changing PC, rather than waiting for the sleep to end. */
.section .text
.global _start
_start:
    la a0, pipe
    li a1, 0
    li a7, 59
    ecall
    bnez a0, fail
    li a0, 17
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s0, a0
    la t0, pipe
    lw a0, 0(t0)
    la a1, token
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, kill_fail
    li s1, 100
attach:
    la a0, pause
    li a1, 0
    li a7, 101
    ecall
    li a0, 16 /* PTRACE_ATTACH */
    mv a1, s0
    li a2, 0
    li a3, 0
    li a7, 117
    ecall
    bnez a0, kill_fail
    mv a0, s0
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s0, kill_fail
    li a0, 0x4204 /* PTRACE_GETREGSET */
    mv a1, s0
    li a2, 1 /* NT_PRSTATUS */
    la a3, vector
    li a7, 117
    ecall
    bnez a0, kill_fail
    la t0, registers
    ld t1, 0(t0)
    la t2, after_sleep
    beq t1, t2, redirect
    la t2, sleep_call
    beq t1, t2, redirect
    /* The ready pipe precedes the syscall. Retry if scheduling stopped the
     * child in that small window, so the test actually covers a host wait. */
    li a0, 17 /* PTRACE_DETACH */
    li a2, 0
    li a3, 0
    ecall
    bnez a0, kill_fail
    addi s1, s1, -1
    bnez s1, attach
    j kill_fail
redirect:
    la t1, redirected
    sd t1, 0(t0)
    li a0, 0x4205 /* PTRACE_SETREGSET */
    ecall
    bnez a0, kill_fail
    li a0, 7 /* PTRACE_CONT */
    li a2, 0
    li a3, 0
    ecall
    bnez a0, kill_fail
    li s1, 200
poll:
    mv a0, s0
    la a1, status
    li a2, 1 /* WNOHANG */
    li a3, 0
    li a7, 260
    ecall
    beq a0, s0, done
    bnez a0, kill_fail
    la a0, pause
    li a1, 0
    li a7, 101
    ecall
    addi s1, s1, -1
    bnez s1, poll
kill_fail:
    mv a0, s0
    li a1, 9
    li a7, 129
    ecall
fail:
    li a0, 1
    j exit
done:
    la t0, status
    lw t1, 0(t0)
    li t2, 42 << 8
    bne t1, t2, kill_fail
    li a0, 0
exit:
    li a7, 94
    ecall
child:
    la t0, pipe
    lw a0, 4(t0)
    la a1, token
    li a2, 1
    li a7, 64
    ecall
    li a0, 1 /* CLOCK_MONOTONIC */
    li a1, 0
    la a2, sleep_time
    li a3, 0
    li a7, 115
sleep_call:
    ecall
after_sleep:
    li a0, 2
    j exit
redirected:
    li a0, 42
    j exit
.section .data
.balign 8
pause: .quad 0, 10000000
sleep_time: .quad 600, 0
vector: .quad registers, 256
.section .bss
.balign 8
registers: .zero 256
pipe: .zero 8
status: .zero 8
token: .zero 1
