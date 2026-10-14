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
    li t0, (1 << 22) | (1 << 10) | (1 << 1)
    csrw medeleg, t0
    la t0, hs_entry
    csrw mepc, t0
    li t0, (2 << 34) | (2 << 32) | (1 << 11)
    csrw mstatus, t0
    mret
hs_entry:
    la t0, hs_trap
    csrw stvec, t0
    li t0, 0x123
    csrw sscratch, t0
    li t0, 0x456
    csrw vsscratch, t0
    la t0, vs_entry
    csrw sepc, t0
    li t0, (1 << 7) | (1 << 8)
    csrw hstatus, t0
    li t0, (2 << 32) | (1 << 8)
    csrw sstatus, t0
    li s0, 0
    sret
vs_entry:
    csrr t0, sscratch
    li t1, 0x456
    bne t0, t1, fail
    csrr t0, hstatus
    csrr t0, sscratch
    li t1, 0x456
    bne t0, t1, fail
    ecall
    j fail
vu_entry:
    csrr t0, sstatus
    sret
    j fail
hs_trap:
    csrr t0, sscratch
    li t1, 0x123
    bne t0, t1, fail
    csrr t0, hstatus
    andi t0, t0, 0x80
    li t1, 0x80
    bne t0, t1, fail
    csrr t0, scause
    li t1, 4
    beq s0, t1, check_walk_access
    li t1, 2
    bgeu s0, t1, check_vu
    bnez s0, check_ecall
    li t1, 22
    bne t0, t1, fail
    addi s0, s0, 1
    csrr t0, sepc
    addi t0, t0, 4
    csrw sepc, t0
    sret
check_ecall:
    li t1, 10
    bne t0, t1, fail
    csrr t0, hstatus
    andi t0, t0, 0x100
    beqz t0, fail
    li s0, 2
    la t0, vu_entry
    csrw sepc, t0
    li t0, 1 << 8
    csrc sstatus, t0
    sret
check_vu:
    li t1, 22
    bne t0, t1, fail
    csrr t0, hstatus
    andi t0, t0, 0x100
    bnez t0, fail
    li t0, 3
    beq s0, t0, start_walk_access
    li s0, 3
    csrr t0, sepc
    addi t0, t0, 4
    csrw sepc, t0
    sret
start_walk_access:
    li s0, 4
    li t0, (8 << 60) | (0x90000000 >> 12)
    csrw hgatp, t0
    hfence.gvma
    la t0, vs_entry
    csrw sepc, t0
    li t0, 1 << 8
    csrs sstatus, t0
    sret
check_walk_access:
    li t1, 1
    bne t0, t1, fail
    j pass
pass:
    li t0, 0x10000000
    li t1, 'P'
    sb t1, 0(t0)
    li t1, 'A'
    sb t1, 0(t0)
    li t1, 'S'
    sb t1, 0(t0)
    sb t1, 0(t0)
    li t1, 10
    sb t1, 0(t0)
    j finish
fail:
    li t0, 0x10000000
    addi t1, s0, '0'
    sb t1, 0(t0)
    csrr t1, scause
    addi t1, t1, '0'
    sb t1, 0(t0)
    csrr t1, hstatus
    srli t1, t1, 7
    andi t1, t1, 1
    addi t1, t1, '0'
    sb t1, 0(t0)
    li t1, 'F'
    sb t1, 0(t0)
    li t1, 'A'
    sb t1, 0(t0)
    li t1, 'I'
    sb t1, 0(t0)
    li t1, 'L'
    sb t1, 0(t0)
    li t1, 10
    sb t1, 0(t0)
finish:
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
    j finish
