/* SPDX-License-Identifier: MPL-2.0 */
/* Exact RMM fallback. Other rounding modes retain the native FP fast path. */
#if defined(USE_FPU)
#include "riscv_fpu.h"
#include "softfloat/platform.h"
// SoftFloat defines missing THREAD_LOCAL as empty, so check availability first.
#if !defined(THREAD_LOCAL)
#define RVVM_SOFTFLOAT_NEEDS_LOCK 1
#include "locking.h"
#include "feature_test.h"
#if !defined(USE_THREAD_EMU) && defined(HOST_TARGET_POSIX)
#define RVVM_SOFTFLOAT_FORK_CHECK 1
#include <unistd.h>
#endif
#endif
#include "softfloat/softfloat.h"
// Include the vendored sources once, as .inc files, so recursive source discovery
// builds only this wrapper and all helpers share RVVM's platform configuration.
#include "softfloat/softfloat_state.inc"
#include "softfloat/softfloat_raiseFlags.inc"
#ifndef SOFTFLOAT_BUILTIN_CLZ
#include "softfloat/s_countLeadingZeros8.inc"
#include "softfloat/s_countLeadingZeros64.inc"
#endif
#ifndef softfloat_mul64To128
#include "softfloat/s_mul64To128.inc"
#endif
#include "softfloat/s_propagateNaNF32UI.inc"
#include "softfloat/s_propagateNaNF64UI.inc"
#include "softfloat/s_shiftRightJam128.inc"
#include "softfloat/s_approxRecipSqrt_1Ks.inc"
#include "softfloat/s_approxRecipSqrt32_1.inc"
#include "softfloat/s_roundPackToF32.inc"
#include "softfloat/s_roundPackToF64.inc"
#include "softfloat/s_normRoundPackToF32.inc"
#include "softfloat/s_normRoundPackToF64.inc"
#include "softfloat/s_normSubnormalF32Sig.inc"
#include "softfloat/s_normSubnormalF64Sig.inc"
#include "softfloat/s_addMagsF32.inc"
#include "softfloat/s_addMagsF64.inc"
#include "softfloat/s_subMagsF32.inc"
#include "softfloat/s_subMagsF64.inc"
#include "softfloat/s_mulAddF32.inc"
#include "softfloat/s_mulAddF64.inc"
#include "softfloat/f32_add.inc"
#include "softfloat/f32_sub.inc"
#include "softfloat/f32_mul.inc"
#include "softfloat/f32_div.inc"
#include "softfloat/f32_sqrt.inc"
#include "softfloat/f32_mulAdd.inc"
#include "softfloat/f64_add.inc"
#include "softfloat/f64_sub.inc"
#include "softfloat/f64_mul.inc"
#include "softfloat/f64_div.inc"
#include "softfloat/f64_sqrt.inc"
#include "softfloat/f64_mulAdd.inc"
#include "softfloat/f64_to_f32.inc"
#include "softfloat/i32_to_f32.inc"
#include "softfloat/i64_to_f32.inc"
#include "softfloat/i64_to_f64.inc"
#include "softfloat/ui32_to_f32.inc"
#include "softfloat/ui64_to_f32.inc"
#include "softfloat/ui64_to_f64.inc"

#if defined(RVVM_SOFTFLOAT_NEEDS_LOCK)
static bool riscv_fpu_rmm_impl(rvvm_hart_t* vm, uint32_t insn)
#else
bool riscv_fpu_rmm(rvvm_hart_t* vm, uint32_t insn)
#endif
{
    unsigned rm = (insn >> 12) & 7;
    if ((rm == 7 ? vm->csr.fcsr >> 5 : rm) != 4) return false;
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31, rs2 = (insn >> 20) & 31;
    unsigned fmt = (insn >> 25) & 3, op = insn & 0x7f;
    if (fmt > 1) return false;
    float32_t a = {fpu_bit_f32_to_u32(riscv_read_s(vm, rs1))};
    float32_t b = {fpu_bit_f32_to_u32(riscv_read_s(vm, rs2))}, s;
    float64_t x = {fpu_bit_f64_to_u64(riscv_view_d(vm, rs1))};
    float64_t y = {fpu_bit_f64_to_u64(riscv_view_d(vm, rs2))}, d;
    uint64_t integer = riscv_read_reg(vm, rs1);
    // RISC-V detects tininess after rounding. Reset per-operation flags here;
    // the host fenv retains the guest's accrued flags when we merge below.
    softfloat_roundingMode = softfloat_round_near_maxMag;
    softfloat_detectTininess = softfloat_tininess_afterRounding;
    softfloat_exceptionFlags = 0;
    if (op == 0x43 || op == 0x47 || op == 0x4b || op == 0x4f) {
        // Negate operands before mulAdd so every variant rounds only once.
        unsigned rs3 = insn >> 27;
        if (!fmt) {
            float32_t c = {fpu_bit_f32_to_u32(riscv_read_s(vm, rs3))};
            if (op == 0x4b || op == 0x4f) a.v ^= UINT32_C(1) << 31;
            if (op == 0x47 || op == 0x4f) c.v ^= UINT32_C(1) << 31;
            s = f32_mulAdd(a, b, c);
            goto single;
        }
        float64_t z = {fpu_bit_f64_to_u64(riscv_view_d(vm, rs3))};
        if (op == 0x4b || op == 0x4f) x.v ^= UINT64_C(1) << 63;
        if (op == 0x47 || op == 0x4f) z.v ^= UINT64_C(1) << 63;
        d = f64_mulAdd(x, y, z);
        goto double_precision;
    }
    if (op != 0x53) return false;
    // Exact widening and FP-to-integer conversions use the existing helpers.
    switch (insn >> 25) {
        case 0x00: s = f32_add(a,b); goto single;
        case 0x01: d = f64_add(x,y); goto double_precision;
        case 0x04: s = f32_sub(a,b); goto single;
        case 0x05: d = f64_sub(x,y); goto double_precision;
        case 0x08: s = f32_mul(a,b); goto single;
        case 0x09: d = f64_mul(x,y); goto double_precision;
        case 0x0c: s = f32_div(a,b); goto single;
        case 0x0d: d = f64_div(x,y); goto double_precision;
        case 0x2c: if (rs2) return false; s = f32_sqrt(a); goto single;
        case 0x2d: if (rs2) return false; d = f64_sqrt(x); goto double_precision;
        case 0x20: if (rs2 != 1) return false; s = f64_to_f32(x); goto single;
        case 0x68:
            switch (rs2) {
                case 0: s = i32_to_f32(integer); break;
                case 1: s = ui32_to_f32(integer); break;
                case 2: if (!vm->rv64) return false; s = i64_to_f32(integer); break;
                case 3: if (!vm->rv64) return false; s = ui64_to_f32(integer); break;
                default: return false;
            }
            goto single;
        case 0x69:
            switch (rs2) {
                case 2: if (!vm->rv64) return false; d = i64_to_f64(integer); break;
                case 3: if (!vm->rv64) return false; d = ui64_to_f64(integer); break;
                default: return false;
            }
            goto double_precision;
        default: return false;
    }
single:
    // The RISC-V SoftFloat specialization already supplies canonical NaNs;
    // emit directly while preserving single-precision NaN boxing and dirty state.
    riscv_emit_s(vm, rd, fpu_bit_u32_to_f32(s.v));
    goto flags;
double_precision:
    riscv_emit_d(vm, rd, fpu_bit_u64_to_f64(d.v));
flags:
    // SoftFloat and FPU_LIB use the same NX/UF/OF/DZ/NV bit layout.
    fpu_raise_exceptions(softfloat_exceptionFlags);
    return true;
}

#if defined(RVVM_SOFTFLOAT_NEEDS_LOCK)
static rvvm_lock_t riscv_softfloat_lock = RVVM_LOCK_INIT;

#if defined(RVVM_SOFTFLOAT_FORK_CHECK)
static void riscv_softfloat_fork_check(void)
{
    static uint32_t process = 0;
    const uint32_t pid = (uint32_t)getpid();
    // A child may inherit a lock whose owner vanished, even during first use.
    // The high bit marks a reset in progress, so child threads reset only once.
    for (;;) {
        uint32_t prev = atomic_load_uint32(&process);
        if (prev == pid) return;
        if ((prev & 0x7FFFFFFFU) == pid) continue;
        if (atomic_cas_uint32(&process, prev, pid | 0x80000000U)) {
            rvvm_lock_init(&riscv_softfloat_lock);
            atomic_store_uint32(&process, pid);
            return;
        }
    }
}
#endif

bool riscv_fpu_rmm(rvvm_hart_t* vm, uint32_t insn)
{
#if defined(RVVM_SOFTFLOAT_FORK_CHECK)
    riscv_softfloat_fork_check();
#endif
    // Shared state must stay locked through the flag merge, including early exits.
    rvvm_lock(&riscv_softfloat_lock);
    bool handled = riscv_fpu_rmm_impl(vm, insn);
    rvvm_unlock(&riscv_softfloat_lock);
    return handled;
}
#endif
#endif
