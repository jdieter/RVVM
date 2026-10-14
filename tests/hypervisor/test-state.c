/* Architectural state checks before advertising H to a guest kernel. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <cpu/riscv_csr.h>
#include <cpu/riscv_hart.h>
#include <cpu/riscv_priv.h>
#include "test-support.h"

static void write_csr(rvvm_hart_t* hart, unsigned csr, rvvm_uxlen_t value)
{
    assert(riscv_csr_op(hart, csr, &value, CSR_SWAP));
}

static rvvm_uxlen_t read_csr(rvvm_hart_t* hart, unsigned csr)
{
    rvvm_uxlen_t value = 0;
    assert(riscv_csr_op(hart, csr, &value, CSR_SETBITS));
    return value;
}

int main(void)
{
    rvvm_machine_t machine = { .rv64 = true };
    rvvm_hart_t hart = { .machine = &machine, .rv64 = true, .priv_mode = RISCV_PRIV_MACHINE };
    static char* disabled[] = { "hypervisor-test", "-nokvm" };
    rvvm_set_args(2, disabled);
    riscv_csr_init(&hart);
    rvvm_uxlen_t absent = 0;
    assert(!riscv_csr_op(&hart, CSR_HSTATUS, &absent, CSR_SETBITS));
    enable_h();
    riscv_csr_init(&hart);
    write_csr(&hart, CSR_STVEC, 0x1000);
    write_csr(&hart, CSR_VSTVEC, 0x2000);
    write_csr(&hart, CSR_SSCRATCH, 0x123);
    write_csr(&hart, CSR_VSSCRATCH, 0x456);
    riscv_switch_priv(&hart, RISCV_PRIV_SUPERVISOR);
    assert(read_csr(&hart, CSR_HSTATUS) == 2ULL << 32);
    hart.lrsc = true;
    riscv_switch_virt(&hart, true);
    assert(!hart.lrsc);
    assert(read_csr(&hart, CSR_STVEC) == 0x2000);
    assert(read_csr(&hart, CSR_SSCRATCH) == 0x456);
    write_csr(&hart, CSR_SSCRATCH, 0x789);
    riscv_switch_virt(&hart, false);
    assert(read_csr(&hart, CSR_SSCRATCH) == 0x123);
    assert(read_csr(&hart, CSR_VSSCRATCH) == 0x789);
    write_csr(&hart, CSR_VSSTATUS, (2ULL << 32) | (FS_DIRTY << 13));
    rvvm_uxlen_t fp_status = read_csr(&hart, CSR_VSSTATUS);
    assert(fp_status & (1ULL << 63));
    assert(!(fp_status & (3ULL << 15))); // XS excludes the ordinary F and V state.

    hart.csr.edeleg[RISCV_PRIV_MACHINE] = 1U << RISCV_TRAP_ECALL_VSMODE;
    hart.registers[RISCV_REG_PC] = 0x80000000;
    riscv_switch_virt(&hart, true);
    riscv_emulate_opc_system(&hart, 0x73);
    assert(!hart.virt && hart.priv_mode == RISCV_PRIV_SUPERVISOR);
    assert(hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_ECALL_VSMODE);
    assert(hart.hypervisor.status & CSR_HSTATUS_SPV);
    assert(hart.hypervisor.status & CSR_HSTATUS_SPVP);
    assert(hart.trap_pc == 0x1000);
    hart.trap = false;
    riscv_emulate_opc_system(&hart, 0x10200073);
    assert(hart.virt && hart.priv_mode == RISCV_PRIV_SUPERVISOR);
    assert(hart.registers[RISCV_REG_PC] + 4 == 0x80000000);
    assert(!(hart.hypervisor.status & CSR_HSTATUS_SPV));

    hart.hypervisor.edeleg = 1U << RISCV_TRAP_LOAD_PAGEFAULT;
    hart.csr.edeleg[RISCV_PRIV_MACHINE] |= 1U << RISCV_TRAP_LOAD_PAGEFAULT;
    riscv_trap(&hart, RISCV_TRAP_LOAD_PAGEFAULT, 0xCAFE);
    assert(hart.virt && hart.trap_pc == 0x2000);
    assert(hart.csr.cause[RISCV_CSR_VS] == RISCV_TRAP_LOAD_PAGEFAULT);
    assert(hart.csr.tval[RISCV_CSR_VS] == 0xCAFE);
    assert(hart.hypervisor.vsstatus & (1U << 8));
    hart.trap = false;

    hart.csr.edeleg[RISCV_PRIV_MACHINE] |= 1U << RISCV_TRAP_VIRTUAL_INSN;
    rvvm_uxlen_t value = 0;
    assert(!riscv_csr_op(&hart, CSR_HSTATUS, &value, CSR_SETBITS));
    assert(hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_VIRTUAL_INSN);
    hart.trap = false;
    hart.virt = true;
    hart.priv_mode = RISCV_PRIV_USER;
    value = 0;
    assert(!riscv_csr_op(&hart, CSR_HSTATUS, &value, CSR_SETBITS) && hart.trap);
    assert(hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_VIRTUAL_INSN);
    hart.trap = false;
    hart.virt = true;
    hart.priv_mode = RISCV_PRIV_USER;
    assert(!riscv_csr_op(&hart, CSR_HVIEN, &value, CSR_SETBITS) && !hart.trap);
    assert(!riscv_csr_op(&hart, CSR_SSTATUS, &value, CSR_SETBITS) && hart.trap);
    assert(hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_VIRTUAL_INSN);
    hart.trap = false;
    hart.virt = true;
    hart.priv_mode = RISCV_PRIV_USER;
    riscv_emulate_opc_system(&hart, 0x10200073);
    assert(hart.trap && hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_VIRTUAL_INSN);
    assert(hart.csr.tval[RISCV_PRIV_SUPERVISOR] == 0x10200073);
    assert(!hart.virt);
    hart.trap = false;

    // HGATP ignores unsupported modes, VMIDs, and unaligned root low bits.
    write_csr(&hart, CSR_HGATP, (8ULL << 60) | (0x1234ULL << 44) | 7);
    assert(read_csr(&hart, CSR_HGATP) == (8ULL << 60 | 4));
    write_csr(&hart, CSR_HGATP, 7ULL << 60);
    assert(read_csr(&hart, CSR_HGATP) == (8ULL << 60 | 4));

    riscv_switch_priv(&hart, RISCV_PRIV_MACHINE);
    hart.csr.status = (hart.csr.status & ~(3ULL << 11)) | (1ULL << 11) | CSR_STATUS_MPV;
    hart.csr.epc[RISCV_PRIV_MACHINE] = 0x80001000;
    riscv_emulate_opc_system(&hart, 0x30200073);
    assert(hart.virt && hart.priv_mode == RISCV_PRIV_SUPERVISOR);
    assert(hart.registers[RISCV_REG_PC] + 4 == 0x80001000);
    assert(!(hart.csr.status & CSR_STATUS_MPV));
    // VU counter denial is virtual if HS can access the same counter.
    hart.csr.counteren[RISCV_PRIV_MACHINE] = CSR_COUNTEREN_TM;
    hart.hypervisor.counteren = CSR_COUNTEREN_TM;
    hart.csr.counteren[RISCV_PRIV_SUPERVISOR] = 0;
    hart.priv_mode = RISCV_PRIV_USER;
    value = 0;
    assert(!riscv_csr_op(&hart, CSR_TIME, &value, CSR_SETBITS) && hart.trap);
    assert(hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_VIRTUAL_INSN);
    hart.trap = false;
    hart.virt = true;
    hart.priv_mode = RISCV_PRIV_USER;
    hart.hypervisor.counteren = 0;
    assert(!riscv_csr_op(&hart, CSR_TIME, &value, CSR_SETBITS) && hart.trap);
    assert(hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_VIRTUAL_INSN);
    puts("PASS hypervisor CSR banks, trap delegation and privilege returns");
    return 0;
}
