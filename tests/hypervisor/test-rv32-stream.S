.option norvc
.section .text
.global _start
_start:
    la t0, fail
    csrw mtvec, t0
    csrr t0, misa
    andi t1, t0, 128
    bnez t1, fail
    srli t0, t0, 30
    li t1, 1
    bne t0, t1, fail
    la t2, pass_text
    j print
fail:
    la t2, fail_text
print:
    li t0, 0x10000000
next:
    lbu t1, 0(t2)
    beqz t1, finish
    sb t1, 0(t0)
    addi t2, t2, 1
    j next
finish:
    li t0, 0x100000
    li t1, 0x5555
    sw t1, 0(t0)
    j finish
pass_text: .asciz "PASS\n"
fail_text: .asciz "FAIL\n"
