/* SPDX-License-Identifier: MPL-2.0 */
#ifndef RISCV_USER_ACCESS_H
#define RISCV_USER_ACCESS_H

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
static inline bool riscv_user_lse_available(void)
{
    static unsigned detected;
    unsigned value = __atomic_load_n(&detected, __ATOMIC_RELAXED);
    if (!value) {
        value = getauxval(AT_HWCAP) & (1UL << 8) ? 2 : 1; // HWCAP_ATOMICS
        __atomic_store_n(&detected, value, __ATOMIC_RELAXED);
    }
    return value == 2;
}
#elif defined(__aarch64__)
static inline bool riscv_user_lse_available(void) { return false; }
#endif

/* Each entry identifies only a guest memory instruction. The memory clobber
 * commits canonical interpreter state before the host can take a fault. */
#define USER_ACCESS_SITE ".pushsection rvvm_user_access,\"aw\"\n.balign 8\n.quad 1b\n.popsection\n"
#if defined(__x86_64__)
#define USER_LOAD8 "movzbl (%1),%k0"
#define USER_LOAD16 "movzwl (%1),%k0"
#define USER_LOAD32 "movl (%1),%k0"
#define USER_LOAD64 "movq (%1),%0"
#define USER_STORE8 "movb %b1,(%0)"
#define USER_STORE16 "movw %w1,(%0)"
#define USER_STORE32 "movl %k1,(%0)"
#define USER_STORE64 "movq %1,(%0)"
#elif defined(__aarch64__)
#define USER_LOAD8 "ldrb %w0,[%1]"
#define USER_LOAD16 "ldrh %w0,[%1]"
#define USER_LOAD32 "ldr %w0,[%1]"
#define USER_LOAD64 "ldr %0,[%1]"
#define USER_STORE8 "strb %w1,[%0]"
#define USER_STORE16 "strh %w1,[%0]"
#define USER_STORE32 "str %w1,[%0]"
#define USER_STORE64 "str %1,[%0]"
#endif
#define USER_ACCESS(bits) \
static forceinline uint##bits##_t riscv_user_fault_load##bits(const void* ptr) \
{ \
    uint64_t value; \
    __asm__ volatile("1: " USER_LOAD##bits "\n" USER_ACCESS_SITE \
                     : "=r"(value) : "r"(ptr) : "memory"); \
    return value; \
} \
static forceinline void riscv_user_fault_store##bits(void* ptr, uint##bits##_t value) \
{ \
    __asm__ volatile("1: " USER_STORE##bits "\n" USER_ACCESS_SITE \
                     : : "r"(ptr), "r"((uint64_t)value) : "memory"); \
}
USER_ACCESS(8)
USER_ACCESS(16)
USER_ACCESS(32)
USER_ACCESS(64)
#undef USER_ACCESS

/* Native CAS keeps the fault before any architectural result is committed.
 * ARM selects LSE or exclusive instructions at runtime, avoiding out-of-line libatomic
 * helpers and locks that could be abandoned by signal recovery. */
#if defined(__x86_64__)
#define USER_CAS(bits, suffix, reg) \
static forceinline uint##bits##_t riscv_user_cas##bits(void* ptr, uint##bits##_t old, uint##bits##_t val) \
{ \
    __asm__ volatile("1: lock cmpxchg" suffix " " reg "2,(%1)\n" USER_ACCESS_SITE \
                     : "+a"(old) : "r"(ptr), "r"(val) : "memory", "cc"); \
    return old; \
}
USER_CAS(8, "b", "%b")
USER_CAS(16, "w", "%w")
USER_CAS(32, "l", "%k")
USER_CAS(64, "q", "%")
#elif defined(__aarch64__)
#define USER_CAS(bits, suffix, reg) \
static forceinline uint##bits##_t riscv_user_cas##bits(void* ptr, uint##bits##_t old, uint##bits##_t val) \
{ \
    if (riscv_user_lse_available()) { \
        __asm__ volatile(".arch_extension lse\n1: casal" suffix " " reg "0," reg "2,[%1]\n" USER_ACCESS_SITE \
                         : "+&r"(old) : "r"(ptr), "r"((uint64_t)val) : "memory"); \
        return old; \
    } \
    uint64_t found; unsigned status; \
    __asm__ volatile("0: 1: ldaxr" suffix " " reg "0,[%2]\n" USER_ACCESS_SITE \
                     "cmp " reg "0," reg "3\nb.ne 2f\n" \
                     "1: stlxr" suffix " %w1," reg "4,[%2]\n" USER_ACCESS_SITE \
                     "cbnz %w1,0b\nb 3f\n2: clrex\n3:\n" \
                     : "=&r"(found), "=&r"(status) \
                     : "r"(ptr), "r"((uint64_t)old), "r"((uint64_t)val) : "memory", "cc"); \
    return found; \
}
USER_CAS(8, "b", "%w")
USER_CAS(16, "h", "%w")
USER_CAS(32, "", "%w")
USER_CAS(64, "", "%")
#endif
#undef USER_CAS

static forceinline void riscv_user_cas128(void* ptr, uint64_t* expected, const uint64_t* value)
{
    uint64_t lo = expected[0], hi = expected[1];
#if defined(__x86_64__)
    __asm__ volatile("1: lock cmpxchg16b (%2)\n" USER_ACCESS_SITE
                     : "+a"(lo), "+d"(hi)
                     : "r"(ptr), "b"(value[0]), "c"(value[1]) : "memory", "cc");
#elif defined(__aarch64__)
    uint64_t found_lo, found_hi; unsigned status;
    __asm__ volatile("0: 1: ldaxp %0,%1,[%3]\n" USER_ACCESS_SITE
                     "cmp %0,%4\nccmp %1,%5,#0,eq\nb.ne 2f\n"
                     "1: stlxp %w2,%6,%7,[%3]\n" USER_ACCESS_SITE
                     "cbnz %w2,0b\nb 3f\n2: 1: stlxp %w2,%0,%1,[%3]\n" USER_ACCESS_SITE
                     "cbnz %w2,0b\n3:\n"
                     : "=&r"(found_lo), "=&r"(found_hi), "=&r"(status)
                     : "r"(ptr), "r"(lo), "r"(hi), "r"(value[0]), "r"(value[1]) : "memory", "cc");
    lo = found_lo; hi = found_hi;
#endif
    expected[0] = lo; expected[1] = hi;
}
#endif
