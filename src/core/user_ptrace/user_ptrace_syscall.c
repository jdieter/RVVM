/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#if defined(RVVM_USER_TEST) && defined(__linux__)
#include "user_ptrace_syscall.h"
#include "cpu/riscv_cpu.h"
#include <stddef.h>
#include <string.h>

/* Linux's UAPI layout, independent of the host's ptrace headers/architecture. */
struct syscall_info {
    uint8_t op, pad[3];
    uint32_t arch;
    uint64_t ip, sp;
    union {
        struct { uint64_t nr, args[6]; } entry;
        struct { int64_t result; uint8_t is_error; } exit;
    } data;
};

void user_ptrace_syscall_entry(rvvm_hart_t* cpu, struct user_ptrace_syscall_state* state)
{
    state->phase = 1;
    state->nr = (int32_t)rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 17);
    for (size_t i = 0; i < 6; i++)
        state->args[i] = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10 + i);
    /* Caller publishes the already-advanced PC, as Linux does at syscall entry. */
    state->ip = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC);
    state->sp = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 2);
    state->result = 0;
}

void user_ptrace_syscall_exit(rvvm_hart_t* cpu, struct user_ptrace_syscall_state* state)
{
    state->phase = 2;
    state->ip = rvvm_read_cpu_reg(cpu, RVVM_REGID_PC);
    state->sp = rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 2);
    state->result = (int64_t)rvvm_read_cpu_reg(cpu, RVVM_REGID_X0 + 10);
}

void user_ptrace_syscall_refresh_entry(rvvm_hart_t* cpu, struct user_ptrace_syscall_state* state)
{
    /* RISC-V keeps orig_a0 outside NT_PRSTATUS; a0 is the return-value slot. */
    uint64_t orig_a0 = state->args[0];
    user_ptrace_syscall_entry(cpu, state);
    state->args[0] = orig_a0;
}

size_t user_ptrace_syscall_info(const struct user_ptrace_syscall_state* state,
                              bool tracesysgood, void* buffer, size_t capacity)
{
    struct syscall_info info = {0};
    info.arch = UINT32_C(0xc00000f3); /* AUDIT_ARCH_RISCV64 */
    info.ip = state->ip;
    info.sp = state->sp;
    size_t size = offsetof(struct syscall_info, data);
    if (tracesysgood && state->phase == 1) {
        info.op = 1;
        info.data.entry.nr = state->nr;
        memcpy(info.data.entry.args, state->args, sizeof(info.data.entry.args));
        size += sizeof(info.data.entry);
    } else if (tracesysgood && state->phase == 2) {
        info.op = 2;
        info.data.exit.result = state->result;
        info.data.exit.is_error = state->result < 0 && state->result >= -4095;
        size = offsetof(struct syscall_info, data.exit.is_error) + 1;
    }
    if (capacity > size) capacity = size;
    if (capacity) memcpy(buffer, &info, capacity);
    return size;
}
#endif
