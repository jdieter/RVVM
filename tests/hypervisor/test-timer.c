#include <assert.h>
#include <stdio.h>
#include <cpu/riscv_csr.h>
#include <cpu/riscv_hart.h>
#include "test-support.h"

int main(void)
{
    enable_h();
    rvvm_machine_t machine = { .rv64 = true };
    rvvm_hart_t hart = { .machine = &machine, .rv64 = true, .priv_mode = RISCV_PRIV_SUPERVISOR };
    riscv_csr_init(&hart);
    rvtimer_init(&machine.timer, 1);
    rvtimer_rebase(&machine.timer, 1000);
    hart.csr.envcfg[RISCV_PRIV_MACHINE] = CSR_ENVCFG_STCE;
    hart.csr.counteren[RISCV_PRIV_MACHINE] = CSR_COUNTEREN_TM;
    rvvm_uxlen_t value = 1100;
    assert(riscv_csr_op(&hart, CSR_VSTIMECMP, &value, CSR_SWAP));
    value = CSR_ENVCFG_STCE;
    assert(riscv_csr_op(&hart, CSR_HENVCFG, &value, CSR_SWAP));
    assert(!(riscv_interrupts_raised(&hart) & (1U << 6)));
    value = 200;
    assert(riscv_csr_op(&hart, CSR_HTIMEDELTA, &value, CSR_SWAP));
    assert(riscv_interrupts_raised(&hart) & (1U << 6));
    value = 1300;
    assert(riscv_csr_op(&hart, CSR_VSTIMECMP, &value, CSR_SWAP));
    assert(!(riscv_interrupts_raised(&hart) & (1U << 6)));
    hart.csr.ie = 1U << 6;
    value = 1U << 6;
    assert(riscv_csr_op(&hart, CSR_HVIP, &value, CSR_SWAP));
    assert(riscv_interrupts_pending(&hart) == (1U << 6));
    value = 0;
    assert(riscv_csr_op(&hart, CSR_HIP, &value, CSR_SETBITS));
    assert(value & (1U << 6)); // HIP combines injection with the timer signal.
    value = 0;
    assert(riscv_csr_op(&hart, CSR_HVIP, &value, CSR_SWAP));
    assert(value == (1U << 6) && !riscv_interrupts_pending(&hart));
    value = 1100;
    assert(riscv_csr_op(&hart, CSR_VSTIMECMP, &value, CSR_SWAP));
    assert(riscv_interrupts_pending(&hart) == (1U << 6));
    value = 0;
    assert(riscv_csr_op(&hart, CSR_HVIP, &value, CSR_SETBITS));
    assert(value == 0); // An expired comparison does not invent stored injection.
    hart.csr.ip = 1U << 6;
    value = 0;
    assert(riscv_csr_op(&hart, CSR_HENVCFG, &value, CSR_SWAP));
    assert(riscv_interrupts_pending(&hart) == (1U << 6));
    hart.priv_mode = RISCV_PRIV_MACHINE;
    value = 0;
    assert(riscv_csr_op(&hart, CSR_MENVCFG, &value, CSR_SWAP));
    value = CSR_ENVCFG_STCE | CSR_ENVCFG_PBMTE | CSR_ENVCFG_ADUE;
    assert(riscv_csr_op(&hart, CSR_HENVCFG, &value, CSR_SWAP));
    value = 0;
    assert(riscv_csr_op(&hart, CSR_HENVCFG, &value, CSR_SETBITS));
    assert(value == 0); // Parent menvcfg makes these delegated fields read-only zero.
    puts("PASS virtual Sstc comparison, time offset and independent HVIP injection");
}
