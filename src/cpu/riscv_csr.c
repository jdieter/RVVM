/*
riscv_csr.c - RISC-V Control and Status Registers
Copyright (C) 2021  LekKit <github.com/LekKit>
                    cerg2010cerg2010 <github.com/cerg2010cerg2010>

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#include "riscv_csr.h"
#include "riscv_hart.h"
#include "riscv_mmu.h"

PUSH_OPTIMIZATION_SIZE

#if defined(USE_FPU)
#include "fpu_lib.h"
#endif

// Get RVVM commit in a mimpid hex form
static uint32_t rvvm_mimpid(void)
{
    const char* ver  = RVVM_VERSION;
    const char* dash = rvvm_strfind(ver, "-");
    if (dash) {
        uint32_t commit_hex = str_to_uint_base(dash + 1, NULL, 16) << 4;
        if (rvvm_strfind(ver, "dirty")) {
            commit_hex |= 0xD;
        }
        return commit_hex;
    }
    return 0;
}

// Make a misa CSR value from ISA string
static uint64_t riscv_mkmisa(const char* str)
{
    uint64_t ret = 0;
    if (rvvm_strfind(str, "rv64")) {
        ret |= CSR_MISA_RV64;
        str += 4;
    } else if (rvvm_strfind(str, "rv32")) {
        ret |= CSR_MISA_RV32;
        str += 4;
    }
    while (*str && *str != '_') {
        if (*str >= 'a' && *str <= 'z') {
            ret |= (1 << (*str - 'a'));
        }
        str++;
    }
    return ret;
}

static inline bool riscv_is_csr_write(rvvm_uxlen_t* dest, uint8_t op)
{
    return (*dest != 0) || (op == CSR_SWAP);
}

static inline bool riscv_csr_helper_masked(rvvm_hart_t* vm, rvvm_uxlen_t* csr, //
                                           rvvm_uxlen_t* dest, rvvm_uxlen_t mask, uint8_t op)
{
    rvvm_uxlen_t tmp = *csr;
    if (!vm->rv64) {
        mask &= (uint32_t)-1;
    }
    switch (op) {
        case CSR_SWAP:
            *csr &= (~mask);
            *csr |= (*dest & mask);
            break;
        case CSR_SETBITS:
            *csr |= (*dest & mask);
            break;
        case CSR_CLEARBITS:
            *csr &= (~(*dest & mask));
            break;
    }
    *dest = tmp & mask;
    return true;
}

static inline bool riscv_csr_helper(rvvm_hart_t* vm, rvvm_uxlen_t* csr, rvvm_uxlen_t* dest, uint8_t op)
{
    if (vm->rv64) {
        rvvm_uxlen_t tmp = *csr;
        switch (op) {
            case CSR_SWAP:
                *csr = *dest;
                break;
            case CSR_SETBITS:
                *csr |= *dest;
                break;
            case CSR_CLEARBITS:
                *csr &= ~(*dest);
                break;
        }
        *dest = tmp;
        return true;
    } else {
        return riscv_csr_helper_masked(vm, csr, dest, -1, op);
    }
}

static inline bool riscv_csr_tvec(rvvm_hart_t* vm, rvvm_uxlen_t* csr, rvvm_uxlen_t* dest, uint8_t op)
{
    // Apply normal CSR op first (preserves read-old-value behavior)
    riscv_csr_helper(vm, csr, dest, op);

    // WARL legalization for tvec.MODE:
    // legal values are 0 (Direct) and 1 (Vectored).
    // Any write producing mode >= 2 is mapped to a legal value.
    *csr = bit_replace(*csr, 0, 2, bit_cut(*csr, 0, 2) & 0x1);

    return true;
}

static inline bool riscv_csr_epc(rvvm_hart_t* vm, rvvm_uxlen_t* csr, rvvm_uxlen_t* dest, uint8_t op)
{
    riscv_csr_helper(vm, csr, dest, op);

    // epc[0] is always zero
    *csr &= ~((rvvm_uxlen_t)1);

    return true;
}

static inline bool riscv_csr_helper_l(rvvm_hart_t* vm, uint64_t* csr, rvvm_uxlen_t* dest, uint64_t mask, uint8_t op)
{
    rvvm_uxlen_t tmp = *csr;
    riscv_csr_helper_masked(vm, &tmp, dest, mask, op);
    if (vm->rv64) {
        *csr = tmp;
    } else {
        *csr = bit_replace(*csr, 0, 32, tmp);
    }
    return true;
}

static inline bool riscv_csr_helper_h(rvvm_hart_t* vm, uint64_t* csr, rvvm_uxlen_t* dest, uint64_t mask, uint8_t op)
{
    if (!vm->rv64) {
        rvvm_uxlen_t tmp = (*csr >> 32);
        riscv_csr_helper_masked(vm, &tmp, dest, mask >> 32, op);
        *csr = bit_replace(*csr, 32, 32, tmp);
        return true;
    }
    return false;
}

static inline bool riscv_csr_const(rvvm_uxlen_t* dest, rvvm_uxlen_t val)
{
    *dest = val;
    return true;
}

static inline bool riscv_csr_zero(rvvm_uxlen_t* dest)
{
    return riscv_csr_const(dest, 0);
}

static inline bool riscv_csr_zero_h(rvvm_hart_t* vm, rvvm_uxlen_t* dest)
{
    if (!vm->rv64) {
        return riscv_csr_const(dest, 0);
    }
    return false;
}

static inline bool riscv_csr_counter(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint32_t counter)
{
    if (riscv_csr_counter_enabled(vm, counter)) {
        uint64_t value = rvtimer_get(&vm->machine->timer);
        if (vm->virt && counter == CSR_TIME - CSR_CYCLE) value += vm->hypervisor.timedelta;
        return riscv_csr_const(dest, value);
    }
    if (vm->virt && (vm->csr.counteren[RISCV_PRIV_MACHINE] & (1U << counter))) {
        riscv_trap(vm, RISCV_TRAP_VIRTUAL_INSN, 0);
    }
    return false;
}

static inline bool riscv_csr_counter_h(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint32_t counter)
{
    if (!vm->rv64 && riscv_csr_counter_enabled(vm, counter)) {
        return riscv_csr_const(dest, rvtimer_get(&vm->machine->timer) >> 32);
    }
    return false;
}

static inline bool riscv_csr_seed(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    // Zkr: SEED must be accessed via CSR read-write instruction form
    if (op != CSR_SWAP) {
        return false;
    }

    if (riscv_csr_seed_enabled(vm)) {
        uint16_t seed = 0;
        rvvm_randombytes(&seed, sizeof(seed));
        return riscv_csr_const(dest, seed | CSR_SEED_OPST_ES16);
    }
    return false;
}

static bool riscv_csr_misa(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    rvvm_uxlen_t misa = vm->csr.isa;
#ifdef USE_FPU
    misa |= riscv_mkmisa("imafdcbsu");
#else
    misa |= riscv_mkmisa("imacbsu");
#endif
    if (vm->hypervisor.enabled) misa |= riscv_mkmisa("h");
    riscv_csr_helper(vm, &misa, dest, op);

    if (vm->hypervisor.enabled) return true; // H keeps all execution modes RV64.
    if ((vm->csr.isa & CSR_MISA_RV64) && (misa & CSR_MISA_RV32)) {
        vm->csr.isa = CSR_MISA_RV32;
        riscv_update_xlen(vm);
    } else if ((vm->csr.isa & CSR_MISA_RV32) && (misa & (CSR_MISA_RV64 >> 32))) {
        // Switch to RV64 if machine allows
        if (vm->machine->rv64) {
            vm->csr.isa = (rvvm_uxlen_t)CSR_MISA_RV64;
            riscv_update_xlen(vm);
        }
    }
    return true;
}

static inline rvvm_uxlen_t riscv_csr_sd_bit(rvvm_hart_t* vm)
{
    if (vm->rv64) {
        return (rvvm_uxlen_t)0x8000000000000000ULL;
    } else {
        return 0x80000000U;
    }
}

#define CSR_STATUS_XL_RV32 0x1
#define CSR_STATUS_XL_RV64 0x2

static inline bool riscv_csr_status_xl_valid(uint8_t xl)
{
#ifdef USE_RV32
    if (xl == CSR_STATUS_XL_RV32) {
        return true;
    }
#endif
    if (xl == CSR_STATUS_XL_RV64) {
        return true;
    }
    return false;
}

static bool riscv_csr_status_bank(rvvm_hart_t* vm, rvvm_uxlen_t* reg, rvvm_uxlen_t* dest, uint64_t mask, uint8_t op)
{
    rvvm_uxlen_t status     = *reg;
    rvvm_uxlen_t old_status = status;

    // No additional extension state is implemented; FS/VS independently feed SD.
    uint8_t fs = bit_cut(status, 13, 2);
    uint8_t vs = bit_cut(status, 9, 2);
    uint8_t dirty_state = EVAL_MAX(fs, vs);
    status = bit_replace(status, 15, 2, 0);

    riscv_csr_helper_masked(vm, &status, dest, mask, op);

    if (unlikely(dirty_state == FS_DIRTY)) {
        *dest |= riscv_csr_sd_bit(vm);
    }

    if (unlikely(status != old_status)) {
        // Validate WARL fields
        if (vm->machine->rv64) {
            // Validate UXL, SXL if machine is 64-bit
            if (vm->hypervisor.enabled || !riscv_csr_status_xl_valid(bit_cut(status, 32, 2))) {
                status = bit_replace(status, 32, 2, CSR_STATUS_XL_RV64);
            }
            if (reg == &vm->csr.status
                && (vm->hypervisor.enabled || !riscv_csr_status_xl_valid(bit_cut(status, 34, 2)))) {
                status = bit_replace(status, 34, 2, CSR_STATUS_XL_RV64);
            }
        }
        if (bit_cut(status, 11, 2) == RISCV_PRIV_HYPERVISOR) {
            // Validate MPP
            status = bit_replace(status, 11, 2, RISCV_PRIV_USER);
        }
        status = bit_replace(status, 15, 2, 0);

#ifndef USE_FPU
        status = bit_replace(status, 13, 2, FS_OFF);
#endif

#ifndef USE_RVV
        // TODO: Vector extension state handling
        status = bit_replace(status, 9, 2, FS_OFF);
#endif

        if ((status & 0xA) & ~(old_status & 0xA)) {
            // MIE/SIE were enabled, check interrupts
            riscv_hart_check_interrupts(vm);
        }

        *reg = status;
        if ((status ^ old_status) & (CSR_STATUS_SUM | CSR_STATUS_MXR | CSR_STATUS_MPRV
                                     | CSR_STATUS_MPV | (3ULL << 11))) {
            riscv_tlb_flush(vm);
        }
    }
    return true;
}

static bool riscv_csr_status(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint64_t mask, uint8_t op)
{
    return riscv_csr_status_bank(vm, &vm->csr.status, dest, mask, op);
}

static bool riscv_csr_hgatp(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    if (!vm->rv64) return false;
    if (vm->priv_mode == RISCV_PRIV_SUPERVISOR && (vm->csr.status & CSR_STATUS_TVM)) return false;
    rvvm_uxlen_t value = vm->hypervisor.gatp;
    riscv_csr_helper(vm, &value, dest, op);
    uint8_t mode = value >> 60;
    if (mode != CSR_SATP_MODE_BARE && mode != CSR_SATP_MODE_SV39 && mode != CSR_SATP_MODE_SV48) return true;
    // VMIDLEN=0 is architectural. x4 roots require 16 KiB alignment.
    value &= (15ULL << 60) | (bit_mask(44) & ~3ULL);
    if (value != vm->hypervisor.gatp) {
        vm->hypervisor.gatp = value;
        riscv_tlb_flush(vm);
    }
    return true;
}

static bool riscv_csr_vsatp(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    if (!vm->rv64) return false;
    rvvm_uxlen_t value = vm->hypervisor.vsatp;
    riscv_csr_helper(vm, &value, dest, op);
    uint8_t mode = value >> 60;
    if (mode != CSR_SATP_MODE_BARE && mode != CSR_SATP_MODE_SV39 && mode != CSR_SATP_MODE_SV48) return true;
    value &= (15ULL << 60) | bit_mask(44);
    if (value != vm->hypervisor.vsatp) {
        vm->hypervisor.vsatp = value;
        riscv_tlb_flush(vm);
    }
    return true;
}

static inline bool riscv_csr_ie(rvvm_hart_t* vm, rvvm_uxlen_t* dest, rvvm_uxlen_t mask, uint8_t op)
{
    riscv_csr_helper_masked(vm, &vm->csr.ie, dest, mask, op);
    riscv_hart_check_interrupts(vm);
    return true;
}

static inline bool riscv_csr_ip(rvvm_hart_t* vm, rvvm_uxlen_t* dest, rvvm_uxlen_t mask, uint8_t op)
{
    riscv_csr_helper_masked(vm, &vm->csr.ip, dest, mask, op);
    *dest |= (riscv_interrupts_raised(vm) & mask);
    riscv_hart_check_interrupts(vm);
    return true;
}

static inline bool riscv_csr_topi(rvvm_hart_t* vm, rvvm_uxlen_t* dest, rvvm_uxlen_t mask, uint8_t op)
{
    if (vm->aia) {
        uint32_t pending = (riscv_interrupts_pending(vm) & mask);
        uint32_t irq     = riscv_interrupt_priority(pending);
        // Report IRQ as both pending and highest prio
        *dest = (!!irq) | (irq << 16);
        UNUSED(op);
        return true;
    }
    return false;
}

static inline bool riscv_csr_topei(rvvm_hart_t* vm, uint8_t priv_mode, rvvm_uxlen_t* dest, uint8_t op)
{
    if (vm->aia) {
        bool     smode = priv_mode == RISCV_PRIV_SUPERVISOR;
        uint32_t irq   = riscv_get_aia_irq(vm, smode, riscv_is_csr_write(dest, op));
        // Report IRQ as both pending and highest prio
        *dest = irq | (irq << 16);
        return true;
    }
    return false;
}

static void riscv_csr_stimecmp_set(rvvm_hart_t* vm, uint64_t stimecmp)
{
    rvtimecmp_set(&vm->stimecmp, stimecmp);
    if (rvtimecmp_pending(&vm->stimecmp)) {
        riscv_interrupt(vm, RISCV_INTERRUPT_STIMER);
    } else {
        riscv_interrupt_clear(vm, RISCV_INTERRUPT_STIMER);
    }
}

static inline bool riscv_csr_stimecmp(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    if (likely(riscv_csr_sstc_enabled(vm))) {
        uint64_t stimecmp = rvtimecmp_get(&vm->stimecmp);
        riscv_csr_helper_l(vm, &stimecmp, dest, -1ULL, op);
        riscv_csr_stimecmp_set(vm, stimecmp);
        return true;
    }
    return false;
}

static inline bool riscv_csr_stimecmph(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    if (!vm->rv64 && riscv_csr_sstc_enabled(vm)) {
        uint64_t stimecmp = rvtimecmp_get(&vm->stimecmp);
        riscv_csr_helper_h(vm, &stimecmp, dest, -1ULL, op);
        riscv_csr_stimecmp_set(vm, stimecmp);
        return true;
    }
    return false;
}

static bool riscv_csr_satp(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    uint8_t new_mmu_mode = 0;
    if ((vm->csr.status & CSR_STATUS_TVM) && vm->priv_mode < RISCV_PRIV_MACHINE) {
        // Accessing satp CSR should trap in S-mode when mstatus.TVM is enabled
        return false;
    }
    if (vm->rv64) {
        rvvm_uxlen_t satp = (((uint64_t)vm->mmu_mode) << 60) | (vm->root_page_table >> RISCV_PAGE_SHIFT);
        riscv_csr_helper(vm, &satp, dest, op);
        new_mmu_mode = bit_cut(satp, 60, 4);
        if (new_mmu_mode != CSR_SATP_MODE_BARE
            && (new_mmu_mode < CSR_SATP_MODE_SV39 || new_mmu_mode > CSR_SATP_MODE_SV57)) {
            // If satp is written with unsupported MODE, the entire write has no effect
            return true;
        }
        if (new_mmu_mode == CSR_SATP_MODE_SV57 && !rvvm_has_arg("sv57")) {
            // Disallow SV57 mode unless -sv57 is passed
            return true;
        }
        vm->root_page_table = (satp & bit_mask(44)) << RISCV_PAGE_SHIFT;
    } else {
        rvvm_uxlen_t satp = (((rvvm_uxlen_t)vm->mmu_mode) << 31) | (vm->root_page_table >> RISCV_PAGE_SHIFT);
        riscv_csr_helper(vm, &satp, dest, op);
        new_mmu_mode        = bit_cut(satp, 31, 1);
        vm->root_page_table = (satp & bit_mask(22)) << RISCV_PAGE_SHIFT;
    }

    if (!!vm->mmu_mode != !!new_mmu_mode) {
        // Switchin satp.MODE to Bare and vice versa should take effect immediately,
        // so we need to perform an implicit software TLB flush
        riscv_tlb_flush(vm);
        vm->mmu_mode = new_mmu_mode;
    }
    return true;
}

#ifdef USE_FPU

static inline void riscv_update_fflags(rvvm_hart_t* vm)
{
    vm->csr.fcsr |= fpu_get_exceptions();
}

static void riscv_update_fcsr(rvvm_hart_t* vm, uint32_t old_fcsr, uint32_t new_fcsr)
{
    if (unlikely(new_fcsr != old_fcsr)) {
        uint32_t old_frm    = bit_cut(old_fcsr, 5, 3);
        uint32_t new_frm    = bit_cut(new_fcsr, 5, 3);
        uint32_t old_fflags = bit_cut(old_fcsr, 0, 5);
        uint32_t new_fflags = bit_cut(new_fcsr, 0, 5);
        if (unlikely(new_frm != old_frm)) {
            if (new_frm > RM_RMM) {
                // Ignore invalid frm, apply other fcsr fields
                new_frm = old_frm;
            } else {
                // Set host rounding mode
                fpu_set_rounding_mode(new_frm);
            }
        }
        if (unlikely(~new_fflags & old_fflags)) {
            if (~new_fflags & fpu_get_exceptions()) {
                // Clear host-set FPU exceptions, anything needed is left in fcsr
                fpu_set_exceptions(0);
            }
        }
        vm->csr.fcsr = new_fflags | (new_frm << 5);
    }
}

static void riscv_set_fcsr(rvvm_hart_t* vm, uint32_t fcsr)
{
    riscv_update_fcsr(vm, vm->csr.fcsr, fcsr);
}

static bool riscv_csr_fflags(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    if (likely(riscv_fpu_is_enabled(vm))) {
        riscv_update_fflags(vm);
        rvvm_uxlen_t fcsr = vm->csr.fcsr;
        riscv_csr_helper_masked(vm, &fcsr, dest, CSR_FFLAGS_MASK, op);
        riscv_set_fcsr(vm, fcsr);
        return true;
    }
    return false;
}

static bool riscv_csr_frm(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    if (likely(riscv_fpu_is_enabled(vm))) {
        rvvm_uxlen_t fcsr = vm->csr.fcsr;
        rvvm_uxlen_t frm  = fcsr >> 5;
        riscv_csr_helper_masked(vm, &frm, dest, CSR_FRM_MASK, op);
        fcsr = bit_replace(fcsr, 5, 3, frm);
        riscv_set_fcsr(vm, fcsr);
        return true;
    }
    return false;
}

static bool riscv_csr_fcsr(rvvm_hart_t* vm, rvvm_uxlen_t* dest, uint8_t op)
{
    if (likely(riscv_fpu_is_enabled(vm))) {
        riscv_update_fflags(vm);
        rvvm_uxlen_t fcsr = vm->csr.fcsr;
        riscv_csr_helper_masked(vm, &fcsr, dest, CSR_FCSR_MASK, op);
        riscv_set_fcsr(vm, fcsr);
        return true;
    }
    return false;
}

#endif

static inline bool riscv_csr_atomic_helper(uint32_t* val, rvvm_uxlen_t* dest, uint8_t op)
{
    switch (op) {
        case CSR_SWAP:
            *dest = atomic_swap_uint32(val, *dest);
            return true;
        case CSR_SETBITS:
            if (*dest) {
                *dest = atomic_or_uint32(val, *dest);
                return true;
            }
            *dest = atomic_load_uint32(val);
            return false;
        case CSR_CLEARBITS:
            if (*dest) {
                *dest = atomic_and_uint32(val, ~(*dest));
                return true;
            }
            *dest = atomic_load_uint32(val);
            return false;
    }
    return false;
}

static bool riscv_csr_aia_helper(rvvm_hart_t* vm, bool smode, uint32_t* val, rvvm_uxlen_t* dest, uint8_t op)
{
    if (riscv_csr_atomic_helper(val, dest, op)) {
        riscv_update_aia_state(vm, smode);
    }
    return true;
}

static bool riscv_csr_aia_pair_helper(rvvm_hart_t* vm, bool smode, uint32_t reg, uint32_t* arr, rvvm_uxlen_t* dest,
                                      uint8_t op)
{
    if (vm->rv64 && (reg & 1)) {
        // Only even eip/eie are accessible in 64 bit mode
        return false;
    }
    if (reg < RVVM_AIA_ARR_LEN) {
        rvvm_uxlen_t top = ((uint64_t)*dest) >> 32;
        riscv_csr_aia_helper(vm, smode, &arr[reg], dest, op);
        if (vm->rv64 && reg + 1 < RVVM_AIA_ARR_LEN) {
            riscv_csr_aia_helper(vm, smode, &arr[reg + 1], &top, op);
            *dest |= ((uint64_t)top) << 32;
        }
        return true;
    }
    return false;
}

static bool riscv_csr_indirect(rvvm_hart_t* vm, uint8_t priv_mode, uint32_t csri, rvvm_uxlen_t* dest, uint8_t op)
{
    bool smode = priv_mode == RISCV_PRIV_SUPERVISOR;
    switch (csri) {
        case CSRI_EIDELIVERY:
            if (vm->aia) {
                *dest &= 1;
                return riscv_csr_aia_helper(vm, smode, &vm->aia[smode].eidelivery, dest, op);
            }
            break;
        case CSRI_EITHRESHOLD:
            if (vm->aia) {
                return riscv_csr_aia_helper(vm, smode, &vm->aia[smode].eithreshold, dest, op);
            }
            break;
        default:
            if (vm->aia) {
                if (csri >= CSRI_MIPRIO_0 && csri <= CSRI_MIPRIO_15) {
                    // Ignore, all major priorities hardwired to zero
                    return riscv_csr_zero(dest);
                } else if (csri >= CSRI_EIP0 && csri <= CSRI_EIP63) {
                    uint32_t reg = csri - CSRI_EIP0;
                    return riscv_csr_aia_pair_helper(vm, smode, reg, vm->aia[smode].eip, dest, op);
                } else if (csri >= CSRI_EIE0 && csri <= CSRI_EIE63) {
                    uint32_t reg = csri - CSRI_EIE0;
                    return riscv_csr_aia_pair_helper(vm, smode, reg, vm->aia[smode].eie, dest, op);
                }
            }
            break;
    }

    return false;
}

static forceinline bool riscv_csr_op_internal(rvvm_hart_t* vm, uint32_t csr_id, rvvm_uxlen_t* dest, uint8_t op)
{
    switch (csr_id) {
        case CSR_HSTATUS:
            riscv_csr_helper_masked(vm, &vm->hypervisor.status, dest, CSR_HSTATUS_MASK, op);
            *dest |= 2ULL << 32; // VSXL is fixed RV64 for now.
            return vm->rv64;
        case CSR_HEDELEG:
            return riscv_csr_helper_masked(vm, &vm->hypervisor.edeleg, dest, CSR_HEDELEG_MASK, op);
        case CSR_HIDELEG:
            return riscv_csr_helper_masked(vm, &vm->hypervisor.ideleg, dest, CSR_HVIP_MASK, op);
        case CSR_HIE:
            return riscv_csr_ie(vm, dest, CSR_HVIP_MASK, op);
        case CSR_HIP:
            riscv_csr_ip(vm, dest, 4, op);
            *dest |= (vm->csr.ip | riscv_interrupts_raised(vm)) & (CSR_HVIP_MASK & ~4U);
            return true;
        case CSR_HVIP:
            riscv_csr_helper_masked(vm, &vm->csr.ip, dest, CSR_HVIP_MASK, op);
            riscv_hart_check_interrupts(vm);
            return true;
        case CSR_HCOUNTEREN:
            return riscv_csr_helper_masked(vm, &vm->hypervisor.counteren, dest, CSR_COUNTEREN_MASK, op);
        case CSR_HTVAL:
            return riscv_csr_helper(vm, &vm->hypervisor.tval, dest, op);
        case CSR_HTINST:
            return riscv_csr_helper(vm, &vm->hypervisor.tinst, dest, op);
        case CSR_HGEIE:
        case CSR_HGEIP:
            return riscv_csr_zero(dest); // No hardware guest external interrupt files.
        case CSR_HENVCFG:
        case CSR_HTIMEDELTA: {
            uint64_t* reg = csr_id == CSR_HENVCFG ? &vm->hypervisor.envcfg : &vm->hypervisor.timedelta;
            uint64_t value = atomic_load_uint64_relax(reg);
            uint64_t old_value = value;
            uint64_t mask = CSR_MENVCFG_MASK | CSR_ENVCFG_PBMTE | CSR_ENVCFG_ADUE;
            if (csr_id == CSR_HENVCFG) {
                mask &= ~(CSR_ENVCFG_STCE | CSR_ENVCFG_PBMTE | CSR_ENVCFG_ADUE)
                    | vm->csr.envcfg[RISCV_PRIV_MACHINE];
                value &= mask;
            }
            riscv_csr_helper_l(vm, &value, dest, csr_id == CSR_HENVCFG ? mask : -1ULL, op);
            atomic_store_uint64(reg, value);
            if (csr_id == CSR_HENVCFG && ((old_value ^ value) & (CSR_ENVCFG_PBMTE | CSR_ENVCFG_ADUE))) {
                riscv_tlb_flush(vm);
            }
            riscv_hart_check_interrupts(vm);
            return true;
        }
        case CSR_VSTIMECMP: {
            if (vm->priv_mode < RISCV_PRIV_MACHINE
                && (!(vm->csr.envcfg[RISCV_PRIV_MACHINE] & CSR_ENVCFG_STCE)
                    || !(vm->csr.counteren[RISCV_PRIV_MACHINE] & CSR_COUNTEREN_TM))) return false;
            if (vm->virt && (!(vm->hypervisor.envcfg & CSR_ENVCFG_STCE)
                || !(vm->hypervisor.counteren & CSR_COUNTEREN_TM))) {
                riscv_trap(vm, RISCV_TRAP_VIRTUAL_INSN, 0);
                return false;
            }
            uint64_t value = atomic_load_uint64_relax(&vm->hypervisor.vstimecmp);
            riscv_csr_helper_l(vm, &value, dest, -1ULL, op);
            atomic_store_uint64(&vm->hypervisor.vstimecmp, value);
            riscv_hart_check_interrupts(vm);
            return true;
        }
        case CSR_HGATP:
            return riscv_csr_hgatp(vm, dest, op);
        case CSR_VSSTATUS:
            return riscv_csr_status_bank(vm, &vm->hypervisor.vsstatus, dest, CSR_SSTATUS_MASK, op);
        case CSR_VSIE: {
            rvvm_uxlen_t value = vm->csr.ie >> 1;
            riscv_csr_helper_masked(vm, &value, dest, vm->hypervisor.ideleg >> 1, op);
            vm->csr.ie = (vm->csr.ie & ~vm->hypervisor.ideleg) | ((value << 1) & vm->hypervisor.ideleg);
            riscv_hart_check_interrupts(vm);
            return true;
        }
        case CSR_VSIP: {
            rvvm_uxlen_t value = (vm->csr.ip | riscv_interrupts_raised(vm)) >> 1;
            // Only VSSIP is writable through vsip; VSTIP/VSEIP are read-only.
            rvvm_uxlen_t old = value;
            riscv_csr_helper_masked(vm, &value, dest, vm->hypervisor.ideleg >> 1, op);
            rvvm_uxlen_t writable = vm->hypervisor.ideleg & 4;
            vm->csr.ip = (vm->csr.ip & ~writable) | ((value << 1) & writable);
            *dest = old & (vm->hypervisor.ideleg >> 1);
            riscv_hart_check_interrupts(vm);
            return true;
        }
        case CSR_VSTVEC:
            return riscv_csr_tvec(vm, &vm->csr.tvec[RISCV_CSR_VS], dest, op);
        case CSR_VSSCRATCH:
            return riscv_csr_helper(vm, &vm->csr.scratch[RISCV_CSR_VS], dest, op);
        case CSR_VSEPC:
            return riscv_csr_epc(vm, &vm->csr.epc[RISCV_CSR_VS], dest, op);
        case CSR_VSCAUSE:
            return riscv_csr_helper(vm, &vm->csr.cause[RISCV_CSR_VS], dest, op);
        case CSR_VSTVAL:
            return riscv_csr_helper(vm, &vm->csr.tval[RISCV_CSR_VS], dest, op);
        case CSR_VSATP:
            return riscv_csr_vsatp(vm, dest, op);
        case CSR_VSISELECT:
            return riscv_csr_helper(vm, &vm->csr.iselect[RISCV_CSR_VS], dest, op);
        case CSR_VSIREG:
            return false; // No virtual AIA register file (GEILEN=0).
#ifdef USE_FPU
        // User Floating-Point CSRs
        case CSR_FFLAGS:
            return riscv_csr_fflags(vm, dest, op);
        case CSR_FRM:
            return riscv_csr_frm(vm, dest, op);
        case CSR_FCSR:
            return riscv_csr_fcsr(vm, dest, op);
#endif

        // Unprivileged Entropy Source CSR
        case CSR_SEED:
            return riscv_csr_seed(vm, dest, op);

        // User Counters / Timers
        case CSR_CYCLE:
        case CSR_TIME:
        case CSR_INSTRET:
            return riscv_csr_counter(vm, dest, csr_id - CSR_CYCLE);
        case CSR_CYCLEH:
        case CSR_TIMEH:
        case CSR_INSTRETH:
            return riscv_csr_counter_h(vm, dest, csr_id - CSR_CYCLEH);

        // Supervisor Trap Setup
        case CSR_SSTATUS:
            return riscv_csr_status(vm, dest, CSR_SSTATUS_MASK, op);
        case CSR_SIE:
            return riscv_csr_ie(vm, dest, CSR_SEIP_MASK, op);
        case CSR_SIEH:
            return riscv_csr_zero_h(vm, dest);
        case CSR_STVEC:
            return riscv_csr_tvec(vm, &vm->csr.tvec[RISCV_PRIV_SUPERVISOR], dest, op);
        case CSR_SCOUNTEREN:
            return riscv_csr_helper_masked(vm, &vm->csr.counteren[RISCV_PRIV_SUPERVISOR], dest, CSR_COUNTEREN_MASK, op);

        // Supervisor Configuration
        case CSR_SENVCFG:
            return riscv_csr_helper_l(vm, &vm->csr.envcfg[RISCV_PRIV_SUPERVISOR], dest, CSR_SENVCFG_MASK, op);

        // Supervisor Counter Setup
        case CSR_SCOUNTINHIBIT:
            return riscv_csr_zero(dest);

        // Supervisor Indirect CSR Access (Sscsrind)
        case CSR_SISELECT:
            return riscv_csr_helper(vm, &vm->csr.iselect[RISCV_PRIV_SUPERVISOR], dest, op);
        case CSR_SIREG:
            return riscv_csr_indirect(vm, RISCV_PRIV_SUPERVISOR, vm->csr.iselect[RISCV_PRIV_SUPERVISOR], dest, op);

        // Supervisor Trap Handling
        case CSR_SSCRATCH:
            return riscv_csr_helper(vm, &vm->csr.scratch[RISCV_PRIV_SUPERVISOR], dest, op);
        case CSR_SEPC:
            return riscv_csr_epc(vm, &vm->csr.epc[RISCV_PRIV_SUPERVISOR], dest, op);
        case CSR_SCAUSE:
            return riscv_csr_helper(vm, &vm->csr.cause[RISCV_PRIV_SUPERVISOR], dest, op);
        case CSR_STVAL:
            return riscv_csr_helper(vm, &vm->csr.tval[RISCV_PRIV_SUPERVISOR], dest, op);
        case CSR_SIP:
            return riscv_csr_ip(vm, dest, CSR_SEIP_MASK, op);
        case CSR_SIPH:
            return riscv_csr_zero_h(vm, dest);
        case CSR_STOPEI:
            return riscv_csr_topei(vm, RISCV_PRIV_SUPERVISOR, dest, op);
        case CSR_STOPI:
            return riscv_csr_topi(vm, dest, CSR_SEIP_MASK, op);
        case CSR_STIMECMP:
            return riscv_csr_stimecmp(vm, dest, op);
        case CSR_STIMECMPH:
            return riscv_csr_stimecmph(vm, dest, op);

        // Supervisor Protection and Translation
        case CSR_SATP:
            return riscv_csr_satp(vm, dest, op);

        // Machine Information Registers
        case CSR_MVENDORID:
            return riscv_csr_zero(dest); // Not a commercial implementation
        case CSR_MARCHID:
            return riscv_csr_const(dest, 0x5256564D); // 'RVVM' in hex
        case CSR_MIMPID:
            return riscv_csr_const(dest, rvvm_mimpid());
        case CSR_MHARTID:
            return riscv_csr_const(dest, vm->csr.hartid);

        // Machine Trap Setup
        case CSR_MSTATUS:
            return riscv_csr_status(vm, dest, CSR_MSTATUS_MASK
                | (vm->hypervisor.enabled ? CSR_STATUS_MPV | CSR_STATUS_GVA : 0), op);
        case CSR_MSTATUSH:
            return riscv_csr_zero(dest); // We don't need upper half on rv32 for now
        case CSR_MISA:
            return riscv_csr_misa(vm, dest, op);
        case CSR_MEDELEG:
            return riscv_csr_helper_masked(vm, &vm->csr.edeleg[RISCV_PRIV_MACHINE], dest,
                CSR_MEDELEG_MASK | (vm->hypervisor.enabled ? 0xF004F6U : 0), op);
        case CSR_MIDELEG:
            riscv_csr_helper_masked(vm, &vm->csr.ideleg[RISCV_PRIV_MACHINE], dest, CSR_MIDELEG_MASK, op);
            if (vm->hypervisor.enabled) {
                vm->csr.ideleg[RISCV_PRIV_MACHINE] |= CSR_HVIP_MASK;
                *dest |= CSR_HVIP_MASK;
            }
            return true;
        case CSR_MIDELEGH:
            return riscv_csr_zero_h(vm, dest);
        case CSR_MIE:
            return riscv_csr_ie(vm, dest, CSR_MEIP_MASK | (vm->hypervisor.enabled ? CSR_HVIP_MASK : 0), op);
        case CSR_MIEH:
            return riscv_csr_zero_h(vm, dest);
        case CSR_MTVEC:
            return riscv_csr_tvec(vm, &vm->csr.tvec[RISCV_PRIV_MACHINE], dest, op);
        case CSR_MCOUNTEREN:
            return riscv_csr_helper_masked(vm, &vm->csr.counteren[RISCV_PRIV_MACHINE], dest, CSR_COUNTEREN_MASK, op);
        // TODO: mvien, mvip

        // Machine Trap Handling
        case CSR_MSCRATCH:
            return riscv_csr_helper(vm, &vm->csr.scratch[RISCV_PRIV_MACHINE], dest, op);
        case CSR_MEPC:
            return riscv_csr_epc(vm, &vm->csr.epc[RISCV_PRIV_MACHINE], dest, op);
        case CSR_MCAUSE:
            return riscv_csr_helper(vm, &vm->csr.cause[RISCV_PRIV_MACHINE], dest, op);
        case CSR_MTVAL:
            return riscv_csr_helper(vm, &vm->csr.tval[RISCV_PRIV_MACHINE], dest, op);
        case CSR_MTVAL2:
            return riscv_csr_helper(vm, &vm->hypervisor.mtval2, dest, op);
        case CSR_MTINST:
            return riscv_csr_helper(vm, &vm->hypervisor.mtinst, dest, op);
        case CSR_MIP:
            return riscv_csr_ip(vm, dest, CSR_MEIP_MASK | (vm->hypervisor.enabled ? CSR_HVIP_MASK : 0), op);
        case CSR_MIPH:
            return riscv_csr_zero_h(vm, dest);
        case CSR_MTOPEI:
            return riscv_csr_topei(vm, RISCV_PRIV_MACHINE, dest, op);
        case CSR_MTOPI:
            return riscv_csr_topi(vm, dest, CSR_MEIP_MASK, op);

        // Machine Configuration
        case CSR_MENVCFG: {
            uint64_t previous = vm->csr.envcfg[RISCV_PRIV_MACHINE];
            bool result = riscv_csr_helper_l(vm, &vm->csr.envcfg[RISCV_PRIV_MACHINE], dest, CSR_MENVCFG_MASK
                | (vm->hypervisor.enabled ? CSR_ENVCFG_PBMTE | CSR_ENVCFG_ADUE : 0), op);
            if (vm->hypervisor.enabled && previous != vm->csr.envcfg[RISCV_PRIV_MACHINE]) {
                uint64_t mask = ~(CSR_ENVCFG_STCE | CSR_ENVCFG_PBMTE | CSR_ENVCFG_ADUE)
                    | vm->csr.envcfg[RISCV_PRIV_MACHINE];
                atomic_store_uint64(&vm->hypervisor.envcfg,
                    atomic_load_uint64_relax(&vm->hypervisor.envcfg) & mask);
                riscv_tlb_flush(vm);
                riscv_hart_check_interrupts(vm);
            }
            return result;
        }
        case CSR_MENVCFGH:
            return riscv_csr_helper_h(vm, &vm->csr.envcfg[RISCV_PRIV_MACHINE], dest, CSR_MENVCFG_MASK, op);
        case CSR_MSECCFG:
            return riscv_csr_helper_l(vm, &vm->csr.mseccfg, dest, CSR_MSECCFG_MASK, op);
        case CSR_MSECCFGH:
            return riscv_csr_helper_h(vm, &vm->csr.mseccfg, dest, CSR_MSECCFG_MASK, op);

        // TODO: Machine Memory Protection
        case 0x3A0: // pmpcfg0
        case 0x3A1: // pmpcfg1
        case 0x3A2: // pmpcfg2
        case 0x3A3: // pmpcfg3
            return riscv_csr_zero(dest);
        case 0x3B0: // pmpaddr0
        case 0x3B1: // pmpaddr1
        case 0x3B2: // pmpaddr2
        case 0x3B3: // pmpaddr3
        case 0x3B4: // pmpaddr4
        case 0x3B5: // pmpaddr5
        case 0x3B6: // pmpaddr6
        case 0x3B7: // pmpaddr7
        case 0x3B8: // pmpaddr8
        case 0x3B9: // pmpaddr9
        case 0x3BA: // pmpaddr10
        case 0x3BB: // pmpaddr11
        case 0x3BC: // pmpaddr12
        case 0x3BD: // pmpaddr13
        case 0x3BE: // pmpaddr14
        case 0x3BF: // pmpaddr15
            return riscv_csr_zero(dest);

        // Machine Counters/Timers
        case CSR_MCYCLE:
        case CSR_MINSTRET:
        case 0xB03: // mhpmcounter3
        case 0xB04: // mhpmcounter4
        case 0xB05: // mhpmcounter5
        case 0xB06: // mhpmcounter6
        case 0xB07: // mhpmcounter7
        case 0xB08: // mhpmcounter8
        case 0xB09: // mhpmcounter9
        case 0xB0A: // mhpmcounter10
        case 0xB0B: // mhpmcounter11
        case 0xB0C: // mhpmcounter12
        case 0xB0D: // mhpmcounter13
        case 0xB0E: // mhpmcounter14
        case 0xB0F: // mhpmcounter15
        case 0xB10: // mhpmcounter16
        case 0xB11: // mhpmcounter17
        case 0xB12: // mhpmcounter18
        case 0xB13: // mhpmcounter19
        case 0xB14: // mhpmcounter20
        case 0xB15: // mhpmcounter21
        case 0xB16: // mhpmcounter22
        case 0xB17: // mhpmcounter23
        case 0xB18: // mhpmcounter24
        case 0xB19: // mhpmcounter25
        case 0xB1A: // mhpmcounter26
        case 0xB1B: // mhpmcounter27
        case 0xB1C: // mhpmcounter28
        case 0xB1D: // mhpmcounter29
        case 0xB1E: // mhpmcounter30
        case 0xB1F: // mhpmcounter31
            return riscv_csr_zero(dest);
        case CSR_MCYCLEH:
        case CSR_MINSTRETH:
        case 0xB83: // mhpmcounter3h
        case 0xB84: // mhpmcounter4h
        case 0xB85: // mhpmcounter5h
        case 0xB86: // mhpmcounter6h
        case 0xB87: // mhpmcounter7h
        case 0xB88: // mhpmcounter8h
        case 0xB89: // mhpmcounter9h
        case 0xB8A: // mhpmcounter10h
        case 0xB8B: // mhpmcounter11h
        case 0xB8C: // mhpmcounter12h
        case 0xB8D: // mhpmcounter13h
        case 0xB8E: // mhpmcounter14h
        case 0xB8F: // mhpmcounter15h
        case 0xB90: // mhpmcounter16h
        case 0xB91: // mhpmcounter17h
        case 0xB92: // mhpmcounter18h
        case 0xB93: // mhpmcounter19h
        case 0xB94: // mhpmcounter20h
        case 0xB95: // mhpmcounter21h
        case 0xB96: // mhpmcounter22h
        case 0xB97: // mhpmcounter23h
        case 0xB98: // mhpmcounter24h
        case 0xB99: // mhpmcounter25h
        case 0xB9A: // mhpmcounter26h
        case 0xB9B: // mhpmcounter27h
        case 0xB9C: // mhpmcounter28h
        case 0xB9D: // mhpmcounter29h
        case 0xB9E: // mhpmcounter30h
        case 0xB9F: // mhpmcounter31h
            return riscv_csr_zero_h(vm, dest);

        // Machine Counter Setup
        case CSR_MCOUNTINHIBIT:
            return riscv_csr_zero(dest);

        // Machine Indirect CSR Access (Sscsrind)
        case CSR_MISELECT:
            return riscv_csr_helper(vm, &vm->csr.iselect[RISCV_PRIV_MACHINE], dest, op);
        case CSR_MIREG:
            return riscv_csr_indirect(vm, RISCV_PRIV_MACHINE, vm->csr.iselect[RISCV_PRIV_MACHINE], dest, op);
    }

    return false;
}

static bool riscv_csr_hs_qualified(rvvm_hart_t* vm, uint32_t csr_id)
{
    switch (csr_id) {
        case CSR_HSTATUS: case CSR_HEDELEG: case CSR_HIDELEG: case CSR_HIE:
        case CSR_HCOUNTEREN: case CSR_HGEIE: case CSR_HTVAL: case CSR_HIP:
        case CSR_HVIP: case CSR_HTINST: case CSR_HGEIP: case CSR_HENVCFG:
        case CSR_HTIMEDELTA: case CSR_HGATP: case CSR_VSSTATUS: case CSR_VSIE:
        case CSR_VSTVEC: case CSR_VSSCRATCH: case CSR_VSEPC: case CSR_VSCAUSE:
        case CSR_VSTVAL: case CSR_VSIP: case CSR_VSATP: case CSR_VSISELECT:
        case CSR_SSTATUS: case CSR_SIE: case CSR_STVEC: case CSR_SCOUNTEREN:
        case CSR_SENVCFG: case CSR_SCOUNTINHIBIT: case CSR_SISELECT: case CSR_SSCRATCH:
        case CSR_SEPC: case CSR_SCAUSE: case CSR_STVAL: case CSR_SIP: case CSR_SATP:
            return true;
        case CSR_VSTIMECMP: case CSR_STIMECMP:
            return (vm->csr.envcfg[RISCV_PRIV_MACHINE] & CSR_ENVCFG_STCE)
                && (vm->csr.counteren[RISCV_PRIV_MACHINE] & CSR_COUNTEREN_TM);
        case CSR_SIREG: case CSR_STOPEI: case CSR_STOPI:
            return !!vm->aia;
        default:
            return false;
    }
}

bool riscv_csr_op(rvvm_hart_t* vm, uint32_t csr_id, rvvm_uxlen_t* dest, uint8_t op)
{
    if (riscv_csr_readonly(csr_id)) {
        // This is a readonly CSR, only set/clear zero bits is allowed
        if (unlikely(op == CSR_SWAP || *dest != 0)) {
            return false;
        }
    }

    uint8_t required_priv = riscv_csr_privilege(csr_id);
    if (!vm->hypervisor.enabled && (required_priv == RISCV_PRIV_HYPERVISOR
        || csr_id == CSR_MTVAL2 || csr_id == CSR_MTINST)) return false;
    if (vm->virt && (required_priv == RISCV_PRIV_HYPERVISOR
        || (required_priv == RISCV_PRIV_SUPERVISOR && vm->priv_mode == RISCV_PRIV_USER))
        && riscv_csr_hs_qualified(vm, csr_id)) {
        riscv_trap(vm, RISCV_TRAP_VIRTUAL_INSN, 0);
        return false;
    }
    // H and explicit VS CSRs use privilege encoding 2 but execute in HS.
    if (!vm->virt && required_priv == RISCV_PRIV_HYPERVISOR) required_priv = RISCV_PRIV_SUPERVISOR;
    if (unlikely(required_priv > vm->priv_mode)) {
        // Not privileged enough to access this CSR
        return false;
    }

    if (vm->virt) {
        switch (csr_id) {
            case CSR_SSTATUS: csr_id = CSR_VSSTATUS; break;
            case CSR_SIE: csr_id = CSR_VSIE; break;
            case CSR_STVEC: csr_id = CSR_VSTVEC; break;
            case CSR_SSCRATCH: csr_id = CSR_VSSCRATCH; break;
            case CSR_SEPC: csr_id = CSR_VSEPC; break;
            case CSR_SCAUSE: csr_id = CSR_VSCAUSE; break;
            case CSR_STVAL: csr_id = CSR_VSTVAL; break;
            case CSR_SIP: csr_id = CSR_VSIP; break;
            case CSR_STIMECMP: csr_id = CSR_VSTIMECMP; break;
            case CSR_SISELECT: csr_id = CSR_VSISELECT; break;
            case CSR_SIREG: csr_id = CSR_VSIREG; break;
            case CSR_SATP:
                if (vm->hypervisor.status & CSR_HSTATUS_VTVM) {
                    riscv_trap(vm, RISCV_TRAP_VIRTUAL_INSN, 0);
                    return false;
                }
                csr_id = CSR_VSATP;
                break;
        }
    }

    bool ret = riscv_csr_op_internal(vm, csr_id, dest, op);
    if (!vm->rv64) {
        // Sign-extend the result into the register
        *dest = (int32_t)*dest;
    }
    return ret;
}

void riscv_csr_init(rvvm_hart_t* vm)
{
    vm->hypervisor.enabled = vm->machine->rv64 && !vm->machine->userland && !rvvm_has_arg("nokvm");
    if (vm->hypervisor.enabled) vm->csr.ideleg[RISCV_PRIV_MACHINE] |= CSR_HVIP_MASK;
    if (vm->rv64) {
#ifdef USE_RV64
        vm->csr.status = 0xA00000000;
        vm->csr.isa    = CSR_MISA_RV64;
        vm->hypervisor.vsstatus = 2ULL << 32;
        vm->hypervisor.vstimecmp = -1ULL;
#else
        rvvm_warn("Requested RV64 in RV32-only build");
#endif
    } else {
        vm->csr.isa = CSR_MISA_RV32;
    }
}

void riscv_csr_sync_fpu(rvvm_hart_t* vm)
{
#ifdef USE_FPU
    riscv_update_fflags(vm);
    riscv_update_fcsr(vm, 0, vm->csr.fcsr);
#else
    UNUSED(vm);
#endif
}

POP_OPTIMIZATION_SIZE
