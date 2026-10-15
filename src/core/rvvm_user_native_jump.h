/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_NATIVE_JUMP_H
#define RVVM_USER_NATIVE_JUMP_H

/* Child faults must not unwind the suspended lender's libc cleanup stack. */
struct user_native_jump { uint64_t registers[32]; };
extern int user_native_jump_save(struct user_native_jump*) __attribute__((returns_twice));
extern void user_native_jump_restore(struct user_native_jump*) __attribute__((noreturn));
static THREAD_LOCAL struct user_native_jump* user_native_fault_target;

#if defined(__aarch64__)
__asm__(".text\n.balign 4\n.global user_native_jump_save\n.hidden user_native_jump_save\n"
        "user_native_jump_save:\nbti c\n"
        "stp x19,x20,[x0]\nstp x21,x22,[x0,#16]\nstp x23,x24,[x0,#32]\n"
        "stp x25,x26,[x0,#48]\nstp x27,x28,[x0,#64]\nstp x29,x30,[x0,#80]\n"
        "mov x1,sp\nstr x1,[x0,#96]\n"
        "stp d8,d9,[x0,#104]\nstp d10,d11,[x0,#120]\n"
        "stp d12,d13,[x0,#136]\nstp d14,d15,[x0,#152]\nmov x0,0\nret\n"
        ".global user_native_jump_restore\n.hidden user_native_jump_restore\n"
        "user_native_jump_restore:\nbti c\n"
        "ldp x19,x20,[x0]\nldp x21,x22,[x0,#16]\nldp x23,x24,[x0,#32]\n"
        "ldp x25,x26,[x0,#48]\nldp x27,x28,[x0,#64]\nldp x29,x30,[x0,#80]\n"
        "ldr x1,[x0,#96]\nmov sp,x1\n"
        "ldp d8,d9,[x0,#104]\nldp d10,d11,[x0,#120]\n"
        "ldp d12,d13,[x0,#136]\nldp d14,d15,[x0,#152]\nmov x0,1\nret\n");
#elif defined(__x86_64__)
/* With a CET shadow stack, the saved SSP is the one after save returns;
 * restore pops back to it, at most 255 entries per incsspq, as longjmp
 * does. Without one, rdsspq leaves zero and incsspq is a NOP. */
__asm__(".text\n.global user_native_jump_save\n.hidden user_native_jump_save\n"
        "user_native_jump_save:\nendbr64\nmov %rbx,0(%rdi)\nmov %rbp,8(%rdi)\n"
        "mov %r12,16(%rdi)\nmov %r13,24(%rdi)\nmov %r14,32(%rdi)\nmov %r15,40(%rdi)\n"
        "lea 8(%rsp),%rax\nmov %rax,48(%rdi)\nmov (%rsp),%rax\nmov %rax,56(%rdi)\n"
        "xor %eax,%eax\nrdsspq %rax\ntest %rax,%rax\njz 1f\nadd $8,%rax\n"
        "1:\nmov %rax,64(%rdi)\nxor %eax,%eax\nret\n"
        ".global user_native_jump_restore\n.hidden user_native_jump_restore\n"
        "user_native_jump_restore:\nendbr64\nmov 64(%rdi),%rcx\ntest %rcx,%rcx\njz 3f\n"
        "xor %eax,%eax\nrdsspq %rax\nsub %rax,%rcx\nshr $3,%rcx\n"
        "2:\ncmp $255,%rcx\njbe 2f\nmov $255,%eax\nincsspq %rax\nsub $255,%rcx\njmp 2b\n"
        "2:\nincsspq %rcx\n"
        "3:\nmov 0(%rdi),%rbx\nmov 8(%rdi),%rbp\n"
        "mov 16(%rdi),%r12\nmov 24(%rdi),%r13\nmov 32(%rdi),%r14\nmov 40(%rdi),%r15\n"
        "mov 48(%rdi),%rsp\nmov 56(%rdi),%rdx\nmov $1,%eax\nnotrack jmp *%rdx\n");
#else
#error "Native vfork needs a host fault-jump primitive"
#endif
#endif
