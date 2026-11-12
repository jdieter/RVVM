/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A parent must see its child's guest executable before ptrace attachment. */
.section .text
.global _start
_start:
    ld s3, 0(sp)
    li a0, -100
    la a1, self_exe
    la a2, own_path
    li a3, 4096
    li a7, 78
    ecall
    blez a0, fail
    mv s1, a0
    la a0, pipe
    li a1, 0
    li a7, 59
    ecall
    bnez a0, fail
    li a0, 17
    li t0, 2
    bleu s3, t0, 6f
    ori a0, a0, 0x400 /* CLONE_FILES */
6:
    li a1, 0
    li a2, 0
    li a3, 0
    li a4, 0
    li a7, 220
    ecall
    beqz a0, child
    bltz a0, fail
    mv s0, a0
    la t0, digits_end
    mv t1, s0
    li t2, 10
1:
    remu t3, t1, t2
    addi t3, t3, 48
    addi t0, t0, -1
    sb t3, 0(t0)
    divu t1, t1, t2
    bnez t1, 1b
    la t1, child_exe
    addi t1, t1, 6
    la t2, digits_end
2:
    lbu t3, 0(t0)
    sb t3, 0(t1)
    addi t0, t0, 1
    addi t1, t1, 1
    bne t0, t2, 2b
    la t0, exe_suffix
3:
    lbu t3, 0(t0)
    sb t3, 0(t1)
    addi t0, t0, 1
    addi t1, t1, 1
    bnez t3, 3b
    /* The host tracer sets NOFILE=64, placing the hidden pin at fd 63.
     * Relocate the parent's pin while the child cannot initialize: private
     * forks retain the old pin, whereas CLONE_FILES must see the new pin. */
    li t0, 1
    bleu s3, t0, 7f
    li a0, 1
    li a1, 63
    li a2, 0
    li a7, 24
    ecall
    bltz a0, fail
7:
    li a0, -100
    la a1, child_exe
    la a2, child_path
    li a3, 4096
    li a7, 78
    ecall
    bne a0, s1, fail
    la t0, own_path
    la t1, child_path
4:
    lbu t2, 0(t0)
    lbu t3, 0(t1)
    bne t2, t3, fail
    addi t0, t0, 1
    addi t1, t1, 1
    addi s1, s1, -1
    bnez s1, 4b
    li a0, -100
    la a1, child_exe
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    bltz a0, fail
    mv s2, a0
    la a1, elf_header
    li a2, 20
    li a7, 63
    ecall
    li t0, 20
    bne a0, t0, fail
    la t0, elf_header
    lw t1, 0(t0)
    li t2, 0x464c457f
    bne t1, t2, fail
    lhu t1, 18(t0)
    li t2, 243
    bne t1, t2, fail
    mv a0, s2
    li a7, 57
    ecall
    /* The host regression tracer keeps the child stopped until this byte,
     * so these proc reads must work before any child-side initialization. */
    li t0, 1
    bleu s3, t0, 5f
    li a0, 1
    la a1, token
    li a2, 1
    li a7, 64
    ecall
    li t0, 1
    bne a0, t0, fail
5:
    la t0, pipe
    lw a0, 4(t0)
    la a1, token
    li a2, 1
    li a7, 64
    ecall
    li t0, 1
    bne a0, t0, fail
    mv a0, s0
    la a1, status
    li a2, 0
    li a3, 0
    li a7, 260
    ecall
    bne a0, s0, fail
    la t0, status
    lw t1, 0(t0)
    bnez t1, fail
    li a0, 0
    j exit
child:
    li t0, 2
    bgtu s3, t0, 8f
    /* Close the writer so a failing parent cannot leave an orphan waiting. */
    la t0, pipe
    lw a0, 4(t0)
    li a7, 57
    ecall
8:
    la t0, pipe
    lw a0, 0(t0)
    la a1, token
    li a2, 1
    li a7, 63
    ecall
    li t0, 1
    bne a0, t0, fail
    li a0, 0
    j exit
fail:
    li a0, 1
exit:
    li a7, 94
    ecall
.section .data
self_exe: .asciz "/proc/self/exe"
exe_suffix: .asciz "/exe"
child_exe: .ascii "/proc/"
    .skip 32
.section .bss
.balign 8
pipe: .skip 8
status: .skip 8
elf_header: .skip 24
token: .skip 1
digits: .skip 16
digits_end:
own_path: .skip 4096
child_path: .skip 4096
