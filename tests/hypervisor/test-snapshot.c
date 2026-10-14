#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <core/rvvm.h>
#include <cpu/riscv_csr.h>
#include <rvvm/rvvm_blk.h>
#include <rvvm/rvvm_snapshot.h>
#include "test-support.h"

int main(void)
{
    enable_h();
    rvvm_machine_t* machine = rvvm_create_machine(16 << 20, 1, "rv64");
    assert(machine);
    rvvm_hart_t* hart = vector_at(machine->harts, 0);
    assert(hart->hypervisor.enabled);
    *(uint32_t*)machine->mem.data = 0x0000006F; // jal x0,0, no status CSR writes.
    hart->csr.ideleg[RISCV_PRIV_MACHINE] = 0;
    assert(rvvm_start_machine(machine) && rvvm_pause_machine(machine));
    rvvm_uxlen_t status = 0;
    assert(riscv_csr_op(hart, CSR_MSTATUS, &status, CSR_SETBITS));
    assert((status & (15ULL << 32)) == 0xA00000000ULL);
    status = 0;
    assert(riscv_csr_op(hart, CSR_SSTATUS, &status, CSR_SETBITS));
    assert((status & (3ULL << 32)) == 2ULL << 32);
    assert(hart->csr.ideleg[RISCV_PRIV_MACHINE] == CSR_HVIP_MASK);
    machine->power_state = 1; // Powered, but no execution thread is running.
    hart->virt = true;
    hart->priv_mode = RISCV_PRIV_SUPERVISOR;
    hart->hypervisor.status = 0x200;
    hart->hypervisor.vsstatus = 0x40000;
    hart->hypervisor.gatp = 8ULL << 60;
    hart->hypervisor.vsatp = 9ULL << 60;
    hart->hypervisor.timedelta = 123;
    hart->hypervisor.vstimecmp = UINT64_MAX - 5;
    hart->hypervisor.tval = 0x987654;
    hart->hypervisor.mtval2 = 0xABC;
    hart->csr.epc[RISCV_CSR_VS] = 0x80000100;
    char path[] = "/tmp/rvvm-h-snapshot-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0 && close(fd) == 0);
    rvvm_blk_dev_t* block = rvvm_blk_open(path, "raw", RVVM_BLK_RW | RVVM_BLK_GROW);
    assert(block && rvvm_machine_snapshot(machine, block, true));
    memset(&hart->hypervisor, 0, sizeof(hart->hypervisor));
    hart->hypervisor.enabled = true;
    hart->virt = false;
    hart->csr.epc[RISCV_CSR_VS] = 0;
    assert(rvvm_machine_snapshot(machine, block, false));
    assert(hart->virt && hart->priv_mode == RISCV_PRIV_SUPERVISOR);
    assert(hart->hypervisor.status == 0x200 && hart->hypervisor.vsstatus == 0x40000);
    assert(hart->hypervisor.gatp == 8ULL << 60 && hart->hypervisor.vsatp == 9ULL << 60);
    assert(hart->hypervisor.timedelta == 123 && hart->hypervisor.vstimecmp == UINT64_MAX - 5);
    assert(hart->hypervisor.tval == 0x987654 && hart->hypervisor.mtval2 == 0xABC);
    assert(hart->csr.epc[RISCV_CSR_VS] == 0x80000100);
    hart->hypervisor.enabled = false;
    assert(!rvvm_machine_snapshot(machine, block, false));
    hart->hypervisor.enabled = true;
    hart->hypervisor.gatp = hart->hypervisor.vsatp = 0;
    hart->virt = true;
    hart->priv_mode = RISCV_PRIV_SUPERVISOR;
    hart->csr.ie = 0;
    hart->registers[RISCV_REG_PC] = machine->mem.addr + 0x100;
    hart->registers[5] = 0;
    uint32_t* code = (void*)((uint8_t*)machine->mem.data + 0x100);
    code[0] = 0x00128293; // addi t0,t0,1
    code[1] = 0xFFDFF06F; // jal x0,-4
    assert(rvvm_start_machine(machine));
    usleep(20000);
    assert(rvvm_pause_machine(machine));
    rvvm_uxlen_t counter = hart->registers[5];
    assert(counter && hart->virt);
    assert(rvvm_blk_set_size(block, 0));
    assert(rvvm_machine_snapshot(machine, block, true));
    hart->virt = false;
    hart->registers[5] = 0;
    assert(rvvm_machine_snapshot(machine, block, false));
    assert(hart->virt && hart->registers[5] == counter);
    assert(rvvm_start_machine(machine));
    usleep(20000);
    assert(rvvm_pause_machine(machine));
    assert(hart->virt && hart->registers[5] > counter);
    rvvm_blk_close(block);
    assert(unlink(path) == 0);
    rvvm_free_machine(machine);
    puts("PASS H snapshot state, CPU-model mismatch rejection and live VS resume");
}
