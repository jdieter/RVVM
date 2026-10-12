/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A tiny exact result may round to normal without raising underflow. Check
 * all guest rounding modes, both signs, and preservation of sticky flags. */
.section .text
.global _start
_start:
    li s0, 0
    la s1, expected
    li s2, 0
1:
    csrw frm, s0
    li t0, 16 /* Keep a previously accrued invalid exception. */
    csrw fflags, t0
    li t0, 0x00fff800 /* 0x1.fffp-126 */
    or t0, t0, s2
    fmv.w.x ft0, t0
    li t0, 0x3f000400 /* 0x1.0008p-1 */
    fmv.w.x ft1, t0
    fmul.s ft2, ft0, ft1
    fmv.x.w t0, ft2
    lwu t1, 0(s1)
    or t1, t1, s2
    sext.w t1, t1
    bne t0, t1, fail
    csrr t0, fflags
    lw t1, 4(s1)
    bne t0, t1, fail

    /* The same boundary in double precision. */
    li t0, 0x001ffffffc000000
    slli t1, s2, 32
    or t0, t0, t1
    fmv.d.x ft0, t0
    li t0, 0x3fe0000002000000
    fmv.d.x ft1, t0
    li t0, 16
    csrw fflags, t0
    fmul.d ft2, ft0, ft1
    fmv.x.d t0, ft2
    lwu t1, 0(s1)
    li t2, 0x00800000
    li t3, 0x0010000000000000
    beq t1, t2, 2f
    addi t3, t3, -1
2:
    slli t1, s2, 32
    or t3, t3, t1
    bne t0, t3, fail
    csrr t0, fflags
    lw t1, 4(s1)
    bne t0, t1, fail

    /* Narrow a double just below FLT_MIN, with the same rounding behavior. */
    li t0, 0x380ffffff8000000
    slli t1, s2, 32
    or t0, t0, t1
    fmv.d.x ft0, t0
    li t0, 16
    csrw fflags, t0
    fcvt.s.d ft2, ft0
    fmv.x.w t0, ft2
    lwu t1, 0(s1)
    or t1, t1, s2
    sext.w t1, t1
    bne t0, t1, fail
    csrr t0, fflags
    lw t1, 4(s1)
    bne t0, t1, fail
    addi s1, s1, 8
    addi s0, s0, 1
    li t0, 5
    blt s0, t0, 1b
    bnez s2, done
    li s2, 0x80000000
    li s0, 0
    j 1b
done:
    csrw fcsr, zero
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .rodata
.balign 8
expected:
    .word 0x00800000, 17 /* Positive: RNE, RTZ, RDN, RUP, RMM. */
    .word 0x007fffff, 19
    .word 0x007fffff, 19
    .word 0x00800000, 17
    .word 0x00800000, 17
    .word 0x00800000, 17 /* Negative: directed modes exchange their roles. */
    .word 0x007fffff, 19
    .word 0x00800000, 17
    .word 0x007fffff, 19
    .word 0x00800000, 17
