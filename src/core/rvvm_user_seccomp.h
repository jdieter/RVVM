/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RVVM_USER_SECCOMP_H
#define RVVM_USER_SECCOMP_H

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

/* Evaluate guest filters before translating syscalls. Installing these in the
 * host kernel would filter native runtime calls with a different syscall ABI.
 * This supports ALLOW/ERRNO policies; other actions and TSYNC are rejected. */
struct user_seccomp_filter {
    struct user_seccomp_filter* prev;
    uint32_t refs, count, total;
    struct sock_filter insns[];
};
static THREAD_LOCAL struct user_seccomp_filter* user_seccomp;

static struct user_seccomp_filter* user_seccomp_retain(struct user_seccomp_filter* filter)
{
    if (filter) atomic_add_uint32(&filter->refs, 1);
    return filter;
}

static void user_seccomp_release(struct user_seccomp_filter* filter)
{
    while (filter && atomic_sub_uint32(&filter->refs, 1) == 1) {
        struct user_seccomp_filter* prev = filter->prev;
        free(filter);
        filter = prev;
    }
}

static bool user_seccomp_valid(const struct sock_filter* insns, unsigned count)
{
    if (!count || count > BPF_MAXINSNS) return false;
    /* Forward-only control flow lets us intersect initialized scratch words
     * at every join, including jumps that skip a scratch store. */
    uint32_t initialized[BPF_MAXINSNS + 1];
    for (unsigned i = 0; i <= count; i++) initialized[i] = UINT32_MAX;
    initialized[0] = 0;
    for (unsigned i = 0; i < count; i++) {
        const struct sock_filter* f = insns + i;
        uint32_t mask = initialized[i];
        unsigned yes = i + 1, no = i + 1;
        switch (f->code) {
            case BPF_LD | BPF_W | BPF_ABS:
                if (f->k % 4 || f->k > sizeof(struct seccomp_data) - 4) return false;
                break;
            case BPF_LD | BPF_W | BPF_LEN:
            case BPF_LDX | BPF_W | BPF_LEN:
            case BPF_LD | BPF_W | BPF_IMM:
            case BPF_LDX | BPF_W | BPF_IMM:
            case BPF_MISC | BPF_TAX:
            case BPF_MISC | BPF_TXA:
            case BPF_ALU | BPF_NEG:
                break;
            case BPF_ST: case BPF_STX:
                if (f->k >= BPF_MEMWORDS) return false;
                mask |= 1U << f->k;
                break;
            case BPF_LD | BPF_W | BPF_MEM:
            case BPF_LDX | BPF_W | BPF_MEM:
                if (f->k >= BPF_MEMWORDS || !(mask & (1U << f->k))) return false;
                break;
            case BPF_JMP | BPF_JA:
                if (f->k >= count - i - 1) return false;
                yes = no = i + 1 + f->k;
                break;
            case BPF_JMP | BPF_JEQ | BPF_K: case BPF_JMP | BPF_JEQ | BPF_X:
            case BPF_JMP | BPF_JGT | BPF_K: case BPF_JMP | BPF_JGT | BPF_X:
            case BPF_JMP | BPF_JGE | BPF_K: case BPF_JMP | BPF_JGE | BPF_X:
            case BPF_JMP | BPF_JSET | BPF_K: case BPF_JMP | BPF_JSET | BPF_X:
                if (f->jt >= count - i - 1 || f->jf >= count - i - 1) return false;
                yes += f->jt;
                no += f->jf;
                break;
            case BPF_RET | BPF_K:
                if ((f->k & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_ALLOW
                    && (f->k & SECCOMP_RET_ACTION_FULL) != SECCOMP_RET_ERRNO) return false;
                continue;
            default: {
                unsigned op = BPF_OP(f->code);
                if (BPF_CLASS(f->code) != BPF_ALU || f->code != (BPF_ALU | op | BPF_SRC(f->code)))
                    return false;
                if (op != BPF_ADD && op != BPF_SUB && op != BPF_MUL && op != BPF_DIV
                    && op != BPF_OR && op != BPF_AND && op != BPF_LSH && op != BPF_RSH
                    && op != BPF_MOD && op != BPF_XOR) return false;
                /* A zero register divisor terminates a native seccomp task;
                 * do not accept that action until task-kill is implemented. */
                if ((op == BPF_DIV || op == BPF_MOD) && BPF_SRC(f->code) == BPF_X) return false;
                if (BPF_SRC(f->code) == BPF_K) {
                    if ((op == BPF_DIV || op == BPF_MOD) && !f->k) return false;
                    if ((op == BPF_LSH || op == BPF_RSH) && f->k >= 32) return false;
                }
                break;
            }
        }
        initialized[yes] &= mask;
        initialized[no] &= mask;
    }
    return insns[count - 1].code == (BPF_RET | BPF_K);
}

static uint32_t user_seccomp_run(const struct user_seccomp_filter* filter, const struct seccomp_data* data)
{
    uint32_t a = 0, x = 0, mem[BPF_MEMWORDS] = {0};
    for (unsigned pc = 0; pc < filter->count; pc++) {
        const struct sock_filter* f = filter->insns + pc;
        uint32_t value = BPF_SRC(f->code) == BPF_X ? x : f->k;
        switch (BPF_CLASS(f->code)) {
            case BPF_LD: case BPF_LDX: {
                uint32_t loaded;
                switch (BPF_MODE(f->code)) {
                    case BPF_ABS: memcpy(&loaded, (const char*)data + f->k, 4); break;
                    case BPF_LEN: loaded = sizeof(*data); break;
                    case BPF_MEM: loaded = mem[f->k]; break;
                    default: loaded = f->k; break;
                }
                if (BPF_CLASS(f->code) == BPF_LD) a = loaded;
                else x = loaded;
                break;
            }
            case BPF_ST: mem[f->k] = a; break;
            case BPF_STX: mem[f->k] = x; break;
            case BPF_MISC:
                if (BPF_MISCOP(f->code) == BPF_TAX) x = a;
                else a = x;
                break;
            case BPF_ALU:
                switch (BPF_OP(f->code)) {
                    case BPF_ADD: a += value; break;
                    case BPF_SUB: a -= value; break;
                    case BPF_MUL: a *= value; break;
                    case BPF_DIV: if (!value) return 0; a /= value; break;
                    case BPF_MOD: if (!value) return 0; a %= value; break;
                    case BPF_OR: a |= value; break;
                    case BPF_AND: a &= value; break;
                    case BPF_XOR: a ^= value; break;
                    case BPF_LSH: a <<= value & 31; break;
                    case BPF_RSH: a >>= value & 31; break;
                    case BPF_NEG: a = -a; break;
                }
                break;
            case BPF_JMP: {
                bool yes = false;
                switch (BPF_OP(f->code)) {
                    case BPF_JA: pc += f->k; continue;
                    case BPF_JEQ: yes = a == value; break;
                    case BPF_JGT: yes = a > value; break;
                    case BPF_JGE: yes = a >= value; break;
                    case BPF_JSET: yes = (a & value) != 0; break;
                }
                pc += yes ? f->jt : f->jf;
                break;
            }
            case BPF_RET: return f->k;
        }
    }
    return 0;
}

static long user_seccomp_install(unsigned flags, const void* program)
{
    if (flags) return -EINVAL;
    if (user_native_child_active) return -EOPNOTSUPP;
    struct sock_fprog prog;
    if (user_memory_copy(&prog, program, sizeof(prog))) return -EFAULT;
    if (!prog.len || prog.len > BPF_MAXINSNS) return -EINVAL;
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
        struct __user_cap_data_struct caps[2] = {0};
        if (syscall(SYS_capget, &header, caps) || !(caps[0].effective & (1U << CAP_SYS_ADMIN)))
            return -EACCES;
    }
    unsigned total = prog.len + (user_seccomp ? user_seccomp->total + 4 : 0);
    if (total > 32768) return -ENOMEM;
    struct user_seccomp_filter* filter = malloc(sizeof(*filter) + prog.len * sizeof(*prog.filter));
    if (!filter) return -ENOMEM;
    long error = user_memory_copy(filter->insns, prog.filter, prog.len * sizeof(*prog.filter));
    if (!error && !user_seccomp_valid(filter->insns, prog.len)) error = -EINVAL;
    if (error) { free(filter); return error; }
    filter->refs = 1;
    filter->count = prog.len;
    filter->total = total;
    filter->prev = user_seccomp;
    user_seccomp = filter;
    return 0;
}

static long user_seccomp_call(unsigned operation, unsigned flags, void* arg)
{
    if (operation == SECCOMP_SET_MODE_FILTER) return user_seccomp_install(flags, arg);
    if (operation == SECCOMP_GET_ACTION_AVAIL) {
        uint32_t action;
        if (flags) return -EINVAL;
        if (user_memory_copy(&action, arg, sizeof(action))) return -EFAULT;
        return action == SECCOMP_RET_ALLOW || action == SECCOMP_RET_ERRNO ? 0 : -EOPNOTSUPP;
    }
    return -EINVAL;
}

static long user_seccomp_check(const struct seccomp_data* data)
{
    for (const struct user_seccomp_filter* filter = user_seccomp; filter; filter = filter->prev) {
        uint32_t result = user_seccomp_run(filter, data);
        if ((result & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_ERRNO) {
            /* All remaining supported actions have lower precedence. The
             * newest filter supplies errno when multiple ERRNO actions tie. */
            return -(long)EVAL_MIN(result & SECCOMP_RET_DATA, 4095U);
        }
    }
    return 1; // ALLOW; zero is a valid ERRNO result that skips the syscall.
}

#endif
