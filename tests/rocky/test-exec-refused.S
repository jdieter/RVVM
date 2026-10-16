/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Guest execute permission must not depend on host EXEC, which the host may
 * refuse. run-tests.sh runs this under mdwe-exec, and with a file of code on
 * a noexec tmpfs as the argument. An anonymous RWX mapping and an RW mapping
 * made RX run code written into them. With a file argument, so do a private
 * READ|EXEC mapping of it and a READ mapping made READ|EXEC. Exits with 0, or
 * with the number of the step that failed. */
.section .text
.global _start
_start:
    ld s0, 0(sp)
    ld s1, 16(sp)
    /* 1-2: anonymous RWX mmap, as a guest JIT makes it. */
    li s11, 1
    li a0, 0
    li a1, 4096
    li a2, 7
    li a3, 0x22
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    li t0, -4096
    bgeu a0, t0, fail
    mv s2, a0
    jal store_code
    li s11, 2
    jal run_code
    /* 3-5: RW mmap, then mprotect to RX. */
    li s11, 3
    li a0, 0
    li a1, 4096
    li a2, 3
    li a3, 0x22
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    li t0, -4096
    bgeu a0, t0, fail
    mv s2, a0
    jal store_code
    li s11, 4
    mv a0, s2
    li a1, 4096
    li a2, 5
    li a7, 226
    ecall
    bnez a0, fail
    li s11, 5
    jal run_code
    li t0, 2
    blt s0, t0, pass
    /* 6-8: open the code file and map it READ|EXEC. */
    li s11, 6
    li a0, -100
    mv a1, s1
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
    bltz a0, fail
    mv s3, a0
    li s11, 7
    li a0, 0
    li a1, 4096
    li a2, 5
    li a3, 2
    mv a4, s3
    li a5, 0
    li a7, 222
    ecall
    li t0, -4096
    bgeu a0, t0, fail
    mv s2, a0
    li s11, 8
    jal run_code
    /* 9-11: map it READ, then mprotect to READ|EXEC. */
    li s11, 9
    li a0, 0
    li a1, 4096
    li a2, 1
    li a3, 2
    mv a4, s3
    li a5, 0
    li a7, 222
    ecall
    li t0, -4096
    bgeu a0, t0, fail
    mv s2, a0
    li s11, 10
    li a1, 4096
    li a2, 5
    li a7, 226
    ecall
    bnez a0, fail
    li s11, 11
    jal run_code
pass:
    li a0, 0
    li a7, 94
    ecall
fail:
    mv a0, s11
    li a7, 94
    ecall

/* Write "li a0, 42; ret" at s2. */
store_code:
    li t1, 0x02a00513
    sw t1, 0(s2)
    li t1, 0x00008067
    sw t1, 4(s2)
    ret

/* Call the code at s2; it must return 42. */
run_code:
    mv s4, ra
    fence.i
    li a0, 0
    jalr s2
    li t0, 42
    bne a0, t0, fail
    jr s4
