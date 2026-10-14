#include <assert.h>
#include <stdio.h>
#include <cpu/riscv_csr.h>
#include <cpu/riscv_hart.h>
#include "test-support.h"

int main(void)
{
    assert(riscv_interrupt_priority((1U << 3) | (1U << 7)) == 3);
    assert(riscv_interrupt_priority((1U << 9) | (1U << 10)) == 9);
    assert(riscv_interrupt_priority((1U << 1) | (1U << 5) | (1U << 10)) == 1);
    assert(riscv_interrupt_priority((1U << 2) | (1U << 6)) == 2);
    enable_h();
    rvvm_machine_t machine = { .rv64 = true };
    rvvm_hart_t hart = { .machine = &machine, .rv64 = true, .priv_mode = RISCV_PRIV_SUPERVISOR };
    riscv_csr_init(&hart);
    assert(hart.csr.ideleg[RISCV_PRIV_MACHINE] == CSR_HVIP_MASK);
    hart.csr.ip = 4;
    rvvm_uxlen_t value = 0;
    assert(riscv_csr_op(&hart, CSR_VSIP, &value, CSR_SWAP));
    assert(value == 0 && hart.csr.ip == 4); // Hidden pending IRQ cannot be cleared by vsip.
    hart.hypervisor.ideleg = 4;
    assert(riscv_csr_op(&hart, CSR_VSIP, &value, CSR_SWAP));
    assert(value == 2 && hart.csr.ip == 0);
    hart.csr.tvec[RISCV_PRIV_MACHINE] = 0x1000;
    hart.csr.tvec[RISCV_PRIV_SUPERVISOR] = 0x2000;
    hart.csr.tvec[RISCV_CSR_VS] = 0x3001;
    hart.csr.ideleg[RISCV_PRIV_MACHINE] = CSR_HVIP_MASK | CSR_SEIP_MASK;
    hart.hypervisor.ideleg = CSR_HVIP_MASK;
    hart.csr.ie = hart.csr.ip = 4;
    hart.registers[RISCV_REG_PC] = 0x80000000;
    riscv_hart_handle_irqs(&hart);
    assert(hart.registers[RISCV_REG_PC] == 0x80000000); // Delegated VS IRQ stays pending in HS.
    hart.virt = true;
    hart.hypervisor.vsstatus |= 2;
    riscv_hart_handle_irqs(&hart);
    assert(hart.virt && hart.registers[RISCV_REG_PC] == 0x3004);
    assert(hart.csr.cause[RISCV_CSR_VS] == (1ULL << 63 | 1));
    assert(hart.csr.epc[RISCV_CSR_VS] == 0x80000000);
    assert(!(hart.hypervisor.vsstatus & 2));

    // A host S interrupt preempts VS even if the HS SIE bit is clear.
    hart.csr.ie = hart.csr.ip = 2;
    hart.csr.status &= ~(rvvm_uxlen_t)2;
    hart.registers[RISCV_REG_PC] = 0x80001000;
    riscv_hart_handle_irqs(&hart);
    assert(!hart.virt && hart.registers[RISCV_REG_PC] == 0x2000);
    assert(hart.csr.cause[RISCV_PRIV_SUPERVISOR] == (1ULL << 63 | 1));
    assert(hart.hypervisor.status & CSR_HSTATUS_SPV);
    assert(hart.hypervisor.status & CSR_HSTATUS_SPVP);
    assert(hart.csr.epc[RISCV_PRIV_SUPERVISOR] == 0x80001000);

    // Machine IRQ saves V and returns through the M bank, never the VS bank.
    hart.virt = true;
    hart.csr.ie = hart.csr.ip = 1U << RISCV_INTERRUPT_MTIMER;
    hart.registers[RISCV_REG_PC] = 0x80002000;
    riscv_hart_handle_irqs(&hart);
    assert(!hart.virt && hart.priv_mode == RISCV_PRIV_MACHINE);
    assert(hart.registers[RISCV_REG_PC] == 0x1000);
    assert(hart.csr.status & CSR_STATUS_MPV);
    assert(hart.csr.epc[RISCV_PRIV_MACHINE] == 0x80002000);
    hart.priv_mode = RISCV_PRIV_SUPERVISOR;
    hart.virt = true;
    hart.csr.ie = hart.csr.ip = (1U << 9) | (1U << 10);
    hart.csr.ideleg[RISCV_PRIV_MACHINE] = hart.csr.ie;
    hart.hypervisor.ideleg = 0;
    riscv_hart_handle_irqs(&hart);
    assert(!hart.virt && hart.csr.cause[RISCV_PRIV_SUPERVISOR] == (1ULL << 63 | 9));
    hart.virt = true;
    hart.csr.ie = hart.csr.ip = (1U << 2) | (1U << 6);
    hart.csr.ideleg[RISCV_PRIV_MACHINE] = hart.hypervisor.ideleg = hart.csr.ie;
    hart.hypervisor.vsstatus |= 2;
    riscv_hart_handle_irqs(&hart);
    assert(hart.virt && hart.csr.cause[RISCV_CSR_VS] == (1ULL << 63 | 1));
    puts("PASS virtual IRQ remapping, HS preemption and M-mode V save");
}
