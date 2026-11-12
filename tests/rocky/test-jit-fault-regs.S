/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fault recovery must preserve every guest register, including a load's old
 * destination, across both live host mappings and spilled canonical values. */
.option norvc
.option norelax
.section .text
.global _start
_start:
    la t0, saved_sp
    sd sp, 0(t0)
    li a0, 11
    la a1, action
    li a2, 0
    li a3, 8
    li a7, 134
    ecall
    bnez a0, fail
again:
    li ra, 257
    li gp, 259
    li tp, 260
    li t0, 261
    li t1, 262
    li t2, 263
    li s0, 264
    li s1, 265
    li a0, 266
    li a1, 267
    li a2, 268
    li a3, 269
    li a4, 270
    li a5, 271
    li a6, 272
    li a7, 273
    li s2, 274
    li s3, 275
    li s4, 276
    li s5, 277
    li s6, 278
    li s7, 279
    li s8, 280
    li s9, 281
    li s10, 282
    li s11, 283
    li t3, 284
    li t4, 285
    li t5, 286
    li t6, 287
dirty_load:
    lw t6, 0(zero)
clean_load:
    lw t0, 0(zero)
    la t0, remaining
    ld t1, 0(t0)
    addi t1, t1, -1
    sd t1, 0(t0)
    bnez t1, again
    li a0, 0
    li a7, 94
    ecall
handler:
    li t0, 11
    bne a0, t0, fail
    addi t0, a2, 176 /* ucontext mcontext: PC, then x1-x31 */
    ld t1, 0(t0)
    la t2, dirty_load
    beq t1, t2, fault_found
    la t2, clean_load
    bne t1, t2, fail
fault_found:
    addi t1, t1, 4
    sd t1, 0(t0)
    li t1, 1
    addi t0, t0, 8
check:
    addi t2, t1, 256
    li t3, 2
    bne t1, t3, expected
    la t3, saved_sp
    ld t2, 0(t3)
expected:
    ld t3, 0(t0)
    bne t2, t3, fail
    addi t0, t0, 8
    addi t1, t1, 1
    li t2, 32
    bne t1, t2, check
    ret
fail:
    li a0, 1
    li a7, 94
    ecall
.section .data
.balign 8
action: .quad handler, 4, 0 /* SA_SIGINFO */
remaining: .quad 1000
saved_sp: .quad 0
