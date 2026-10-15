/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_PATH_MATCH_H
#define RVVM_USER_PATH_MATCH_H

// Read only through the first mismatch or NUL, including at guest page ends.
extern bool user_path_match(const char*, const char*);
extern char user_match_begin[], user_match_end[], user_match_abort[];
/* Fault-safe read of one guest byte: the byte, or -1 on a fault. */
extern int user_peek_byte(const char*);
extern char user_peek_begin[], user_peek_end[], user_peek_abort[];
#if defined(__aarch64__)
__asm__(".text\n.balign 4\n.global user_path_match\n.hidden user_path_match\n"
        "user_path_match:\n"
        ".global user_match_begin\n.hidden user_match_begin\nuser_match_begin:\n"
        "ldrb w2,[x0],1\n ldrb w3,[x1],1\n cmp w2,w3\n b.ne user_match_abort\n"
        "cbnz w2,user_match_begin\n"
        ".global user_match_end\n.hidden user_match_end\nuser_match_end:\n"
        "mov w0,1\n ret\n"
        ".global user_match_abort\n.hidden user_match_abort\nuser_match_abort:\n"
        "mov w0,0\n ret\n");
__asm__(".text\n.balign 4\n.global user_peek_byte\n.hidden user_peek_byte\n"
        "user_peek_byte:\n"
        ".global user_peek_begin\n.hidden user_peek_begin\nuser_peek_begin:\n"
        "ldrb w0,[x0]\n"
        ".global user_peek_end\n.hidden user_peek_end\nuser_peek_end:\n"
        "ret\n"
        ".global user_peek_abort\n.hidden user_peek_abort\nuser_peek_abort:\n"
        "mov w0,-1\n ret\n");
#elif defined(__x86_64__)
__asm__(".text\n.global user_path_match\n.hidden user_path_match\n"
        "user_path_match:\n"
        ".global user_match_begin\n.hidden user_match_begin\nuser_match_begin:\n"
        "movzbl (%rdi),%eax\n cmpb (%rsi),%al\n jne user_match_abort\n"
        "inc %rdi\n inc %rsi\n test %al,%al\n jnz user_match_begin\n"
        ".global user_match_end\n.hidden user_match_end\nuser_match_end:\n"
        "mov $1,%eax\n ret\n"
        ".global user_match_abort\n.hidden user_match_abort\nuser_match_abort:\n"
        "xor %eax,%eax\n ret\n");
__asm__(".text\n.global user_peek_byte\n.hidden user_peek_byte\n"
        "user_peek_byte:\n"
        ".global user_peek_begin\n.hidden user_peek_begin\nuser_peek_begin:\n"
        "movzbl (%rdi),%eax\n"
        ".global user_peek_end\n.hidden user_peek_end\nuser_peek_end:\n"
        "ret\n"
        ".global user_peek_abort\n.hidden user_peek_abort\nuser_peek_abort:\n"
        "mov $-1,%eax\n ret\n");
#endif
#endif
