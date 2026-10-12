/* SPDX-License-Identifier: MPL-2.0 */
/* Exact RMM and native tininess-boundary fallback. */
#if defined(USE_FPU)
#include "riscv_fpu.h"
#include "softfloat/platform.h"
#include "softfloat/softfloat.h"
#include "softfloat/softfloat_state.inc"
#include "softfloat/softfloat_raiseFlags.inc"
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
#include "softfloat/s_roundToI32.inc"
#include "softfloat/s_roundToI64.inc"
#include "softfloat/s_roundToUI32.inc"
#include "softfloat/s_roundToUI64.inc"
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
#include "softfloat/f32_to_f64.inc"
#include "softfloat/f64_to_f32.inc"
#include "softfloat/f32_to_i32.inc"
#include "softfloat/f32_to_i64.inc"
#include "softfloat/f32_to_ui32.inc"
#include "softfloat/f32_to_ui64.inc"
#include "softfloat/f64_to_i32.inc"
#include "softfloat/f64_to_i64.inc"
#include "softfloat/f64_to_ui32.inc"
#include "softfloat/f64_to_ui64.inc"
#include "softfloat/i32_to_f32.inc"
#include "softfloat/i32_to_f64.inc"
#include "softfloat/i64_to_f32.inc"
#include "softfloat/i64_to_f64.inc"
#include "softfloat/ui32_to_f32.inc"
#include "softfloat/ui32_to_f64.inc"
#include "softfloat/ui64_to_f32.inc"
#include "softfloat/ui64_to_f64.inc"

bool riscv_fpu_softfloat(rvvm_hart_t* vm, uint32_t insn)
{
    unsigned rm = (insn >> 12) & 7;
    rm = rm == 7 ? vm->csr.fcsr >> 5 : rm;
    if (rm > 4) return false;
    unsigned rd = (insn >> 7) & 31, rs1 = (insn >> 15) & 31, rs2 = (insn >> 20) & 31;
    unsigned fmt = (insn >> 25) & 3, op = insn & 0x7f;
    if (fmt > 1) return false;
    float32_t a = {fpu_bit_f32_to_u32(riscv_read_s(vm, rs1))};
    float32_t b = {fpu_bit_f32_to_u32(riscv_read_s(vm, rs2))}, s;
    float64_t x = {fpu_bit_f64_to_u64(riscv_view_d(vm, rs1))};
    float64_t y = {fpu_bit_f64_to_u64(riscv_view_d(vm, rs2))}, d;
    uint64_t integer = riscv_read_reg(vm, rs1), result;
    softfloat_roundingMode = rm;
    softfloat_detectTininess = softfloat_tininess_afterRounding;
    softfloat_exceptionFlags = 0;
    if (op == 0x43 || op == 0x47 || op == 0x4b || op == 0x4f) {
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
        case 0x21: if (rs2) return false; d = f32_to_f64(a); goto double_precision;
        case 0x60:
        case 0x61:
            switch (rs2) {
                case 0: result = (int32_t)(fmt ? f64_to_i32(x,4,true) : f32_to_i32(a,4,true)); break;
                case 1: result = (int32_t)(fmt ? f64_to_ui32(x,4,true) : f32_to_ui32(a,4,true)); break;
                case 2: if (!vm->rv64) return false; result = fmt ? f64_to_i64(x,4,true) : f32_to_i64(a,4,true); break;
                case 3: if (!vm->rv64) return false; result = fmt ? f64_to_ui64(x,4,true) : f32_to_ui64(a,4,true); break;
                default: return false;
            }
            riscv_write_reg(vm, rd, result);
            goto flags;
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
                case 0: d = i32_to_f64(integer); break;
                case 1: d = ui32_to_f64(integer); break;
                case 2: if (!vm->rv64) return false; d = i64_to_f64(integer); break;
                case 3: if (!vm->rv64) return false; d = ui64_to_f64(integer); break;
                default: return false;
            }
            goto double_precision;
        default: return false;
    }
single:
    riscv_emit_s(vm, rd, fpu_bit_u32_to_f32(s.v));
    goto flags;
double_precision:
    riscv_emit_d(vm, rd, fpu_bit_u64_to_f64(d.v));
flags:
    fpu_raise_exceptions(softfloat_exceptionFlags);
    return true;
}
#endif
