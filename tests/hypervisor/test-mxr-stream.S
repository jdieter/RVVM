.option norvc
.section .text
.global _start
_start:
    la t0, fail
    csrw mtvec, t0
    li t0, -1
    csrw pmpaddr0, t0
    li t0, 15
    csrw pmpcfg0, t0
    li t0, 1 << 21
    csrw medeleg, t0
    la t0, hs_entry
    csrw mepc, t0
    li t0, (2 << 34) | (2 << 32) | (1 << 11)
    csrw mstatus, t0
    mret
hs_entry:
    li s0, 0
    la t0, hs_trap
    csrw stvec, t0
    li t0, 1 << 19
    csrs sstatus, t0
    li t0, 1 << 8
    csrw hstatus, t0
    la t0, groot
    srli t0, t0, 12
    li t1, 8 << 60
    or t0, t0, t1
    csrw hgatp, t0
    li t0, (8 << 60) | 1
    csrw vsatp, t0
    hfence.gvma
    li a1, 0x2000
    hlv.d a0, (a1)
    j fail
hs_trap:
    li s0, 1
    csrr t0, scause
    li t1, 21
    bne t0, t1, fail
    li s0, 2
    csrr t0, htval
    li t1, 0x400
    bne t0, t1, fail
    li s0, 3
    csrr t0, htinst
    li t1, 0x3000
    bne t0, t1, fail
    li a0, 'P'
    call putchar
    li a0, 'A'
    call putchar
    li a0, 'S'
    call putchar
    call putchar
    j finish
fail:
    addi a0, s0, '0'
    call putchar
    li a0, 'F'
    call putchar
    li a0, 'A'
    call putchar
    li a0, 'I'
    call putchar
    li a0, 'L'
    call putchar
finish:
    li a0, 10
    call putchar
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
    j finish
putchar:
    li t0, 0x10000000
    sb a0, 0(t0)
    ret
.org 0x1000
    /* VS root's 1 GiB leaf: guest VA 0 maps guest physical 0. */
    .quad 0xCF
.balign 16384
groot:
    /* G root's X-only 1 GiB leaf maps GPA 0 to host physical 0x80000000. */
    .quad (0x80000000 >> 12 << 10) | 0xD9
    .zero 16376
