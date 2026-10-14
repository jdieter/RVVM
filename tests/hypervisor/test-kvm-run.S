/* Linux RISC-V process: execute an inner supervisor payload through real KVM. */
.option norvc
.section .text
.global _start
_start:
    li a0, -100
    la a1, device
    li a2, 2
    li a3, 0
    li a7, 56
    ecall
    bltz a0, fail
    mv s0, a0
    li a1, 0xae00
    li a2, 0
    li a7, 29
    ecall
    li t0, 12
    bne a0, t0, fail
    mv a0, s0
    li a1, 0xae01
    li a2, 0
    li a7, 29
    ecall
    bltz a0, fail
    mv s1, a0
    mv a0, s0
    li a1, 0xae04
    li a2, 0
    li a7, 29
    ecall
    blez a0, fail
    mv s2, a0
    li a0, 0
    li a1, 4096
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    bltz a0, fail
    mv s3, a0
    la t0, inner
    la t1, inner_end
    mv t2, s3
copy:
    lbu t3, 0(t0)
    sb t3, 0(t2)
    addi t0, t0, 1
    addi t2, t2, 1
    bltu t0, t1, copy
    la a2, region
    sd s3, 24(a2)
    mv a0, s1
    li a1, 0x4020ae46
    li a7, 29
    ecall
    bnez a0, fail
    mv a0, s1
    li a1, 0xae41
    li a2, 0
    li a7, 29
    ecall
    bltz a0, fail
    mv s4, a0
    li a0, 0
    mv a1, s2
    li a2, 3
    li a3, 1
    mv a4, s4
    li a5, 0
    li a7, 222
    ecall
    bltz a0, fail
    mv s5, a0
    mv a0, s4
    li a1, 0x4010aeac
    la a2, pc_reg
    li a7, 29
    ecall
    bnez a0, fail
    mv a0, s4
    li a1, 0x4010aeac
    la a2, mode_reg
    li a7, 29
    ecall
    bnez a0, fail
    mv a0, s4
    li a1, 0xae80
    li a2, 0
    li a7, 29
    ecall
    bnez a0, fail
    lw t0, 8(s5)
    li t1, 6
    bne t0, t1, fail
    ld t0, 32(s5)
    li t1, 0x10000000
    bne t0, t1, fail
    lbu t0, 40(s5)
    li t1, 'P'
    bne t0, t1, fail
    lw t0, 48(s5)
    li t1, 1
    bne t0, t1, fail
    lbu t0, 52(s5)
    bne t0, t1, fail
    mv a0, s4
    li a1, 0xae80
    li a2, 0
    li a7, 29
    ecall
    bnez a0, fail
    lw t0, 8(s5)
    li t1, 24
    bne t0, t1, fail
    li a0, 1
    la a1, success
    li a2, 9
    li a7, 64
    ecall
    li a0, 0
    li a7, 93
    ecall
fail:
    li a0, 1
    la a1, failure
    li a2, 9
    li a7, 64
    ecall
    li a0, 1
    li a7, 93
    ecall
inner:
    li t0, 0x10000000
    li t1, 'P'
    sb t1, 0(t0)
    li a0, 0
    li a1, 0
    li a6, 0
    li a7, 0x53525354
    ecall
    j inner
inner_end:
.section .data
.balign 8
region:
    .word 0, 0
    .quad 0x80000000, 4096, 0
pc_reg:
    .quad 0x8030000002000000, pc_value
mode_reg:
    .quad 0x8030000002000020, mode_value
pc_value:
    .quad 0x80000000
mode_value:
    .quad 1
device:
    .asciz "/dev/kvm"
success:
    .ascii "PASS KVM\n"
failure:
    .ascii "FAIL KVM\n"
