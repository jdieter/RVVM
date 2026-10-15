/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PATH_H
#define RVVM_USER_PATH_H

#include <ucontext.h>

// Snapshot a guest pathname without a syscall or an unchecked C dereference.
// Only faults in this leaf routine become EFAULT; other native faults retain
// their usual handling. Byte loads never cross an unreadable page past NUL.
extern long user_path_copy(char*, const char*, size_t);
extern char user_path_begin[], user_path_end[], user_path_abort[];
#if defined(__aarch64__)
__asm__(".text\n.balign 4\n.global user_path_copy\n.hidden user_path_copy\n"
        "user_path_copy:\n mov x3,0\n"
        ".global user_path_begin\n.hidden user_path_begin\nuser_path_begin:\n"
        "ldrb w4,[x1,x3]\n strb w4,[x0,x3]\n add x3,x3,1\n"
        "cbz w4,1f\n cmp x3,x2\n b.lo user_path_begin\n"
        ".global user_path_end\n.hidden user_path_end\nuser_path_end:\n"
        "mov x0,-36\n ret\n1: sub x0,x3,1\n ret\n"
        ".global user_path_abort\n.hidden user_path_abort\nuser_path_abort:\n"
        "mov x0,-14\n ret\n");
#elif defined(__x86_64__)
__asm__(".text\n.global user_path_copy\n.hidden user_path_copy\n"
        "user_path_copy:\n xor %ecx,%ecx\n"
        ".global user_path_begin\n.hidden user_path_begin\nuser_path_begin:\n"
        "movzbl (%rsi,%rcx),%eax\n movb %al,(%rdi,%rcx)\n inc %rcx\n"
        "test %al,%al\n jz 1f\n cmp %rdx,%rcx\n jb user_path_begin\n"
        ".global user_path_end\n.hidden user_path_end\nuser_path_end:\n"
        "mov $-36,%rax\n ret\n1: lea -1(%rcx),%rax\n ret\n"
        ".global user_path_abort\n.hidden user_path_abort\nuser_path_abort:\n"
        "mov $-14,%rax\n ret\n");
#endif

// Fixed-size copies for sparse signal frames. Both ends may fault; only this
// leaf's memory instructions recover. Never touch bytes beyond the given span.
extern long user_memory_copy(void*, const void*, size_t);
extern char user_copy_begin[], user_copy_end[], user_copy_abort[];
#if defined(__aarch64__)
__asm__(".text\n.balign 4\n.global user_memory_copy\n.hidden user_memory_copy\n"
        "user_memory_copy:\n"
        ".global user_copy_begin\n.hidden user_copy_begin\nuser_copy_begin:\n"
        "cmp x2,8\n b.lo 2f\n1: ldr x3,[x1],8\n str x3,[x0],8\n"
        "sub x2,x2,8\n cmp x2,8\n b.hs 1b\n"
        "2: cbz x2,4f\n3: ldrb w3,[x1],1\n strb w3,[x0],1\n"
        "subs x2,x2,1\n b.ne 3b\n4:\n"
        ".global user_copy_end\n.hidden user_copy_end\nuser_copy_end:\n"
        "mov x0,0\n ret\n"
        ".global user_copy_abort\n.hidden user_copy_abort\nuser_copy_abort:\n"
        "mov x0,-14\n ret\n");
#elif defined(__x86_64__)
__asm__(".text\n.global user_memory_copy\n.hidden user_memory_copy\n"
        "user_memory_copy:\n mov %rdx,%rcx\n"
        ".global user_copy_begin\n.hidden user_copy_begin\nuser_copy_begin:\n"
        "rep movsb\n"
        ".global user_copy_end\n.hidden user_copy_end\nuser_copy_end:\n"
        "xor %eax,%eax\n ret\n"
        ".global user_copy_abort\n.hidden user_copy_abort\nuser_copy_abort:\n"
        "mov $-14,%rax\n ret\n");
#endif

#include "rvvm_user_path_match.h"

static bool user_path_fault(void* context)
{
    ucontext_t* uc = context;
#if defined(__aarch64__)
    uintptr_t pc = uc->uc_mcontext.pc;
    if (pc >= (uintptr_t)user_path_begin && pc < (uintptr_t)user_path_end)
        uc->uc_mcontext.pc = (uintptr_t)user_path_abort;
    else if (pc >= (uintptr_t)user_copy_begin && pc < (uintptr_t)user_copy_end)
        uc->uc_mcontext.pc = (uintptr_t)user_copy_abort;
    else if (pc >= (uintptr_t)user_match_begin && pc < (uintptr_t)user_match_end)
        uc->uc_mcontext.pc = (uintptr_t)user_match_abort;
    else if (pc >= (uintptr_t)user_peek_begin && pc < (uintptr_t)user_peek_end)
        uc->uc_mcontext.pc = (uintptr_t)user_peek_abort;
    else return false;
#elif defined(__x86_64__)
    uintptr_t pc = uc->uc_mcontext.gregs[REG_RIP];
    if (pc >= (uintptr_t)user_path_begin && pc < (uintptr_t)user_path_end)
        uc->uc_mcontext.gregs[REG_RIP] = (uintptr_t)user_path_abort;
    else if (pc >= (uintptr_t)user_copy_begin && pc < (uintptr_t)user_copy_end)
        uc->uc_mcontext.gregs[REG_RIP] = (uintptr_t)user_copy_abort;
    else if (pc >= (uintptr_t)user_match_begin && pc < (uintptr_t)user_match_end)
        uc->uc_mcontext.gregs[REG_RIP] = (uintptr_t)user_match_abort;
    else if (pc >= (uintptr_t)user_peek_begin && pc < (uintptr_t)user_peek_end)
        uc->uc_mcontext.gregs[REG_RIP] = (uintptr_t)user_peek_abort;
    else return false;
#endif
    return true;
}
#endif
