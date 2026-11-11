/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Text filtering must keep the real proc descriptor and its mapping ioctl.
 * Check partial/vector reads, shared offsets, rewind and positional reads. */
.section .text
.global _start
_start:
    li a0, -100
    la a1, path
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    bltz a0, fail
    mv s0, a0
    la a1, fs
    li a7, 44 /* fstatfs */
    ecall
    bnez a0, fail
    la t0, fs
    ld t0, 0(t0)
    li t1, 0x9fa0 /* PROC_SUPER_MAGIC, never a memfd */
    bne t0, t1, fail

    mv a0, s0
    la a1, first
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, fail
    mv a0, s0
    la a1, again
    li a2, 1
    li a3, 0
    li a7, 67
    ecall
    bne a0, t0, fail
    la t0, first
    lbu t0, 0(t0)
    la t1, again
    lbu t1, 0(t1)
    bne t0, t1, fail
    mv a0, s0
    li a1, 0
    li a2, 1
    li a7, 62
    ecall
    li t0, 1
    bne a0, t0, fail /* pread must not advance the shared offset */

    mv a0, s0
    li a7, 23 /* dup */
    ecall
    bltz a0, fail
    mv s1, a0
    la a1, vectors
    li a2, 2
    li a7, 65
    ecall
    li t0, 7
    bne a0, t0, fail
    mv a0, s0
    li a1, 0
    li a2, 1
    li a7, 62
    ecall
    li t0, 8
    bne a0, t0, fail
    mv a0, s1
    la a1, vectors
    li a2, 2
    li a3, 0
    li a4, 0
    li a7, 69 /* preadv */
    ecall
    li t0, 7
    bne a0, t0, fail
    mv a0, s0
    li a1, 0
    li a2, 1
    li a7, 62
    ecall
    li t0, 8
    bne a0, t0, fail
    mv a0, s1
    li a1, 1 /* inaccessible guest buffer */
    li a2, 1
    li a7, 63
    ecall
    li t0, -14
    bne a0, t0, fail
    mv a0, s0
    li a1, 0
    li a2, 1
    li a7, 62
    ecall
    li t0, 8
    bne a0, t0, fail /* failed read must not consume bytes */

    mv a0, s1
    li a1, 0
    li a2, 0
    li a7, 62
    ecall
    bnez a0, fail
    mv a0, s0
    la a1, again
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, fail
    la t0, first
    lbu t0, 0(t0)
    la t1, again
    lbu t1, 0(t1)
    bne t0, t1, fail

    mv a0, s0
    li a1, 0xc0686611 /* PROCMAP_QUERY, sizeof(struct procmap_query)=104 */
    la a2, query
    li a7, 29
    ecall
    li t0, -25 /* Older kernels lack the ioctl; fstatfs still checks identity. */
    beq a0, t0, done
    bnez a0, fail
    la t0, query
    ld t1, 24(t0) /* vma_start <= _start < vma_end */
    la t2, _start
    bgtu t1, t2, fail
    ld t1, 32(t0)
    bleu t1, t2, fail
    ld t1, 40(t0)
    andi t1, t1, 4 /* executable */
    beqz t1, fail
done:
    li a0, 0
    li a7, 94
    ecall
fail:
    li a0, 1
    li a7, 94
    ecall
.section .rodata
path: .asciz "/proc/self/maps"
.section .data
.balign 8
query: .quad 104, 0, _start
    .zero 80
vectors: .quad part1, 3, part2, 4
.section .bss
first: .zero 1
again: .zero 1
part1: .zero 3
part2: .zero 4
.balign 8
fs: .zero 120
