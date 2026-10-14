#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cpu/riscv_csr.h>
#include <cpu/riscv_hart.h>
#include <cpu/riscv_mmu.h>
#include <cpu/riscv_priv.h>
#include "test-support.h"

static uint64_t pte(uint64_t address, unsigned flags)
{
    return ((address >> 12) << 10) | flags;
}

int main(void)
{
    enable_h();
    const uint64_t base = 0x80000000;
    uint8_t* ram = calloc(1, 0x20000);
    assert(ram);
    rvvm_machine_t machine = { .rv64 = true };
    rvvm_hart_t hart = { .machine = &machine, .rv64 = true, .priv_mode = RISCV_PRIV_SUPERVISOR,
                         .mem = { .addr = base, .size = 0x20000, .data = ram }, .virt = true };
    riscv_csr_init(&hart);
    hart.csr.envcfg[RISCV_PRIV_MACHINE] = CSR_ENVCFG_ADUE | CSR_ENVCFG_PBMTE;
    hart.hypervisor.envcfg = CSR_ENVCFG_ADUE | CSR_ENVCFG_PBMTE;
    uint64_t* groot = (void*)ram;
    uint64_t* gmiddle = (void*)(ram + 0x4000);
    uint64_t* gleaf = (void*)(ram + 0x5000);
    groot[0] = pte(base + 0x4000, 1);
    gmiddle[0] = pte(base + 0x5000, 1);
    for (unsigned i = 0; i < 16; i++) gleaf[i] = pte(base + 0x8000 + i * 4096, 0x1F);
    uint64_t* vsroot = (void*)(ram + 0x9000);
    uint64_t* vsmiddle = (void*)(ram + 0xA000);
    uint64_t* vsleaf = (void*)(ram + 0xB000);
    vsroot[0] = pte(0x2000, 1);
    vsmiddle[0] = pte(0x3000, 1);
    vsleaf[4] = pte(0x4000, 0xF);
    hart.hypervisor.gatp = 8ULL << 60 | base >> 12;
    hart.hypervisor.vsatp = 8ULL << 60 | 1;
    uint64_t physical;
    assert(riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_READ));
    assert(physical == base + 0xC010);
    assert(vsleaf[4] & RISCV_PTE_ACCESSED);
    assert(gleaf[3] & RISCV_PTE_DIRTY); // VS A-bit update writes through G-stage.
    assert(riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_WRITE));
    assert(vsleaf[4] & RISCV_PTE_DIRTY);
    assert(gleaf[4] & RISCV_PTE_DIRTY);

    // MXR relaxes explicit loads, never implicit VS page-table reads.
    uint64_t root_mapping = gleaf[1];
    gleaf[1] = pte(base + 0x9000, RISCV_PTE_VALID | RISCV_MMU_EXEC
                                   | RISCV_PTE_USER | RISCV_PTE_ACCESSED);
    hart.csr.status |= CSR_STATUS_MXR;
    assert(!riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_READ));
    assert(hart.hypervisor.guest_fault && hart.hypervisor.implicit_fault);
    assert(hart.hypervisor.fault_gpa == 0x1000);
    gleaf[1] = root_mapping;
    hart.csr.status &= ~CSR_STATUS_MXR;

    // Changing MPV with MPRV already set must not reuse the HS data TLB.
    uint64_t* hsroot = (void*)(ram + 0x10000);
    uint64_t* hsmiddle = (void*)(ram + 0x11000);
    uint64_t* hsleaf = (void*)(ram + 0x12000);
    hsroot[0] = pte(base + 0x11000, 1);
    hsmiddle[0] = pte(base + 0x12000, 1);
    hsleaf[4] = pte(base + 0xD000, 0xCF);
    *(uint32_t*)(ram + 0xD010) = 0x11111111;
    *(uint32_t*)(ram + 0xC010) = 0x22222222;
    hart.virt = false;
    hart.priv_mode = RISCV_PRIV_MACHINE;
    hart.root_page_table = base + 0x10000;
    hart.mmu_mode = 8;
    hart.csr.status = CSR_STATUS_MPRV | (1ULL << 11);
    riscv_tlb_flush(&hart);
    riscv_load_u32(&hart, 0x4010, 10);
    assert(hart.registers[10] == 0x11111111);
    rvvm_uxlen_t status = CSR_STATUS_MPV;
    assert(riscv_csr_op(&hart, CSR_MSTATUS, &status, CSR_SETBITS));
    riscv_load_u32(&hart, 0x4010, 10);
    assert(hart.registers[10] == 0x22222222);
    status = CSR_STATUS_MPV;
    assert(riscv_csr_op(&hart, CSR_MSTATUS, &status, CSR_CLEARBITS));
    riscv_load_u32(&hart, 0x4010, 10);
    assert(hart.registers[10] == 0x11111111);
    for (unsigned interrupt = 0; interrupt < 2; ++interrupt) {
        status = CSR_STATUS_MPRV | (1ULL << 11) | 8;
        assert(riscv_csr_op(&hart, CSR_MSTATUS, &status, CSR_SWAP));
        riscv_load_u32(&hart, 0x4010, 10);
        assert(!hart.trap && hart.registers[10] == 0x11111111);
        if (interrupt) {
            hart.csr.ie = hart.csr.ip = 1U << RISCV_INTERRUPT_MTIMER;
            riscv_hart_handle_irqs(&hart);
        } else {
            riscv_trap(&hart, RISCV_TRAP_ILL_INSN, 0);
        }
        // Trap entry stays in M but replaces effective MPP=S with MPP=M.
        hart.trap = false;
        riscv_load_u32(&hart, 0x4010, 10);
        // This platform reads zero outside mapped RAM; the stale HS value is wrong.
        assert(!hart.trap && hart.registers[10] == 0);
        hart.trap = false;
        hart.csr.ie = hart.csr.ip = 0;
    }
    status = CSR_STATUS_MPRV | (3ULL << 11);
    assert(riscv_csr_op(&hart, CSR_MSTATUS, &status, CSR_SWAP));
    riscv_load_u32(&hart, base + 0xD010, 10);
    assert(!hart.trap && hart.registers[10] == 0x11111111);
    riscv_emulate_opc_system(&hart, 0x30200073); // MRET stays M, resets MPP to U.
    assert(hart.priv_mode == RISCV_PRIV_MACHINE && (hart.csr.status & CSR_STATUS_MPRV));
    riscv_load_u32(&hart, base + 0xD010, 10);
    assert(hart.trap && hart.csr.cause[RISCV_PRIV_MACHINE] == RISCV_TRAP_LOAD_PAGEFAULT);
    hart.trap = false;
    hart.csr.status = 0xA00000000ULL;
    hart.priv_mode = RISCV_PRIV_SUPERVISOR;
    hart.virt = true;
    riscv_tlb_flush(&hart);

    // PBMT legality follows both machine and hypervisor environment gates.
    vsleaf[4] |= 2ULL << 61;
    assert(riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_READ));
    hart.hypervisor.envcfg &= ~CSR_ENVCFG_PBMTE;
    assert(!riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_READ));
    assert(!hart.hypervisor.guest_fault);
    hart.hypervisor.envcfg |= CSR_ENVCFG_PBMTE;
    vsleaf[4] &= ~(3ULL << 61);

    // ADUE=0 behaves as Svade, faulting instead of updating the VS A bit.
    vsleaf[4] &= ~RISCV_PTE_ACCESSED;
    hart.hypervisor.envcfg &= ~CSR_ENVCFG_ADUE;
    assert(!riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_READ));
    assert(!(vsleaf[4] & RISCV_PTE_ACCESSED) && !hart.hypervisor.guest_fault);
    hart.hypervisor.envcfg |= CSR_ENVCFG_ADUE;

    // Cache management checks R-or-W permission and A, without setting D.
    vsleaf[4] = pte(0x4000, RISCV_PTE_VALID | RISCV_MMU_READ);
    gleaf[4] = pte(base + 0xC000, RISCV_PTE_VALID | RISCV_MMU_READ | RISCV_PTE_USER);
    hart.csr.envcfg[RISCV_PRIV_MACHINE] |= CSR_ENVCFG_CBCFE;
    hart.hypervisor.envcfg |= CSR_ENVCFG_CBCFE;
    hart.registers[10] = 0x4010;
    riscv_emulate_opc_misc_mem(&hart, (1U << 20) | (10U << 15) | (2U << 12) | 0xF);
    assert(!hart.trap && (vsleaf[4] & RISCV_PTE_ACCESSED) && (gleaf[4] & RISCV_PTE_ACCESSED));
    assert(!(vsleaf[4] & RISCV_PTE_DIRTY) && !(gleaf[4] & RISCV_PTE_DIRTY));
    hart.csr.edeleg[RISCV_PRIV_MACHINE] = 1U << RISCV_TRAP_STORE_GUEST_PAGEFAULT;
    gleaf[4] &= ~RISCV_PTE_USER;
    riscv_emulate_opc_misc_mem(&hart, (1U << 20) | (10U << 15) | (2U << 12) | 0xF);
    assert(hart.trap && hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_STORE_GUEST_PAGEFAULT);
    hart.trap = false;
    hart.virt = true;
    vsleaf[4] = pte(0x4000, 0xF);
    gleaf[4] = pte(base + 0xC000, 0x1F);

    // H memory accesses use guest translation without changing actual V.
    hart.virt = false;
    hart.hypervisor.status = CSR_HSTATUS_SPVP;
    hart.registers[10] = 0x4010;
    // HLV rs2 is an opcode field, not a source register for narrow loads.
    hart.registers[1] = 0xFFFFFFFF80001234ULL;
    hart.registers[3] = 0xFFFFFFFF831D1A10ULL;
    *(uint64_t*)(ram + 0xC010) = 0xFEDCBA9876543210ULL;
    riscv_emulate_opc_system(&hart, (0x36U << 25) | (10U << 15) | (4U << 12) | (11U << 7) | 0x73);
    assert(hart.registers[11] == 0xFEDCBA9876543210ULL && !hart.virt && !hart.trap);
    hart.registers[12] = 0xDEADBEEF12345678ULL;
    riscv_emulate_opc_system(&hart, (0x37U << 25) | (12U << 20) | (10U << 15) | (4U << 12) | 0x73);
    assert(*(uint64_t*)(ram + 0xC010) == 0xDEADBEEF12345678ULL);
    // HLVX works on executable-only pages, while HLV must fault.
    vsleaf[4] = pte(0x4000, RISCV_PTE_VALID | RISCV_MMU_EXEC | RISCV_PTE_ACCESSED);
    gleaf[4] = pte(base + 0xC000, RISCV_PTE_VALID | RISCV_MMU_EXEC | RISCV_PTE_USER | RISCV_PTE_ACCESSED);
    riscv_emulate_opc_system(&hart, (0x32U << 25) | (3U << 20) | (10U << 15) | (4U << 12) | (11U << 7) | 0x73);
    assert(hart.registers[11] == 0x5678 && !hart.trap);
    vsleaf[4] |= RISCV_PTE_USER;
    hart.hypervisor.vsstatus |= CSR_STATUS_SUM;
    riscv_emulate_opc_system(&hart, (0x32U << 25) | (3U << 20) | (10U << 15) | (4U << 12) | (11U << 7) | 0x73);
    assert(hart.registers[11] == 0x5678 && !hart.trap);
    hart.hypervisor.vsstatus &= ~CSR_STATUS_SUM;
    vsleaf[4] &= ~RISCV_PTE_USER;
    riscv_emulate_opc_system(&hart, (0x32U << 25) | (1U << 20) | (10U << 15) | (4U << 12) | (11U << 7) | 0x73);
    assert(hart.trap && hart.csr.cause[RISCV_PRIV_MACHINE] == RISCV_TRAP_LOAD_PAGEFAULT);
    hart.trap = false;
    hart.priv_mode = RISCV_PRIV_SUPERVISOR;
    hart.virt = true;
    vsleaf[4] = pte(0x4000, 0xF);
    gleaf[4] = pte(base + 0xC000, 0x1F);

    // G-stage rejects a leaf without U even when VS is supervisor.
    gleaf[4] &= ~RISCV_PTE_USER;
    assert(!riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_READ));
    assert(hart.hypervisor.guest_fault && hart.hypervisor.fault_gpa == 0x4010);
    gleaf[4] |= RISCV_PTE_USER;

    // A/D update fault identifies the implicit guest PTE access.
    vsleaf[4] &= ~(RISCV_PTE_ACCESSED | RISCV_PTE_DIRTY);
    gleaf[3] &= ~RISCV_MMU_WRITE;
    assert(!riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_READ));
    assert(hart.hypervisor.guest_fault && hart.hypervisor.implicit_fault);
    assert(hart.hypervisor.fault_gpa == 0x3020);
    gleaf[3] |= RISCV_MMU_WRITE;

    // An ordinary VS permission fault must not become a G-stage fault.
    vsleaf[4] = pte(0x4000, 0xB);
    assert(!riscv_mmu_virt_translate(&hart, 0x4010, &physical, RISCV_MMU_WRITE));
    assert(!hart.hypervisor.guest_fault);

    // Sv39x4 has two extra unsigned GPA bits in its root index.
    hart.hypervisor.vsatp = 0;
    uint64_t high_gpa = 1ULL << 39;
    groot[512] = pte(base + 0x4000, 1);
    assert(riscv_mmu_virt_translate(&hart, high_gpa + 0x4010, &physical, RISCV_MMU_READ));
    assert(physical == base + 0xC010);
    assert(!riscv_mmu_virt_translate(&hart, 1ULL << 41, &physical, RISCV_MMU_READ));
    assert(hart.hypervisor.guest_fault);

    // Guest page faults retain guest VA and expose shifted GPA to HS.
    hart.csr.edeleg[RISCV_PRIV_MACHINE] = 1U << RISCV_TRAP_LOAD_GUEST_PAGEFAULT;
    uint64_t value;
    assert(!riscv_mmu_op(&hart, 1ULL << 41, &value, 8, RISCV_MMU_READ));
    assert(!hart.virt && hart.csr.cause[RISCV_PRIV_SUPERVISOR] == RISCV_TRAP_LOAD_GUEST_PAGEFAULT);
    assert(hart.csr.tval[RISCV_PRIV_SUPERVISOR] == 1ULL << 41);
    assert(hart.hypervisor.tval == 1ULL << 39);
    assert(hart.hypervisor.status & (1U << 6)); // GVA
    hart.trap = false;
    hart.priv_mode = RISCV_PRIV_MACHINE;
    hart.csr.status = (1ULL << 11) | CSR_STATUS_MPRV | CSR_STATUS_MPV;
    assert(!riscv_mmu_op(&hart, 1ULL << 41, &value, 8, RISCV_MMU_READ));
    assert(hart.csr.cause[RISCV_PRIV_MACHINE] == RISCV_TRAP_LOAD_GUEST_PAGEFAULT);
    assert(hart.csr.status & CSR_STATUS_GVA);
    assert(!(hart.csr.status & CSR_STATUS_MPV)); // The trap saves actual V, not MPRV's effective V.
    assert(hart.hypervisor.mtval2 == 1ULL << 39);
    // A physical failure fetching a G-stage PTE is an access fault, not a guest PF.
    hart.trap = false;
    hart.virt = true;
    hart.priv_mode = RISCV_PRIV_SUPERVISOR;
    hart.csr.status = 0;
    hart.hypervisor.gatp = (8ULL << 60) | ((base + hart.mem.size) >> 12);
    riscv_tlb_flush(&hart);
    assert(!riscv_mmu_op(&hart, 0x4010, &value, 8, RISCV_MMU_READ));
    assert(hart.csr.cause[RISCV_PRIV_MACHINE] == RISCV_TRAP_LOAD_FAULT);
    assert(hart.csr.tval[RISCV_PRIV_MACHINE] == 0x4010 && hart.hypervisor.mtval2 == 0);
    hart.trap = false;
    hart.virt = true;
    hart.priv_mode = RISCV_PRIV_SUPERVISOR;
    hart.hypervisor.gatp = (8ULL << 60) | (base >> 12);
    groot[2] = pte(base, 0x1F);
    assert(riscv_mmu_virt_translate(&hart, base + 0x4010, &physical, RISCV_MMU_READ));
    assert(physical == base + 0x4010); // A properly aligned G-stage 1 GiB leaf.
    groot[2] = pte(base + 0x1000, 0x1F);
    assert(!riscv_mmu_virt_translate(&hart, base + 0x4010, &physical, RISCV_MMU_READ));
    // Sv48x4 root also uses the extra unsigned GPA bits.
    memset(groot, 0, 0x4000);
    groot[512] = pte(base + 0x10000, 1);
    uint64_t* fourth_level = (void*)(ram + 0x10000);
    fourth_level[0] = pte(base + 0x4000, 1);
    hart.hypervisor.gatp = (9ULL << 60) | (base >> 12);
    assert(riscv_mmu_virt_translate(&hart, (1ULL << 48) + 0x4010, &physical, RISCV_MMU_READ));
    assert(physical == base + 0xC010);
    assert(!riscv_mmu_virt_translate(&hart, 1ULL << 50, &physical, RISCV_MMU_READ));
    hart.hypervisor.vsatp = hart.hypervisor.gatp = 0;
    hart.csr.edeleg[RISCV_PRIV_MACHINE] = 0;
    assert(!riscv_mmu_cache_check(&hart, 0x10001000));
    assert(hart.csr.cause[RISCV_PRIV_MACHINE] == RISCV_TRAP_STORE_FAULT);
    free(ram);
    puts("PASS two-stage translation, implicit A/D writes, x4 and guest faults");
}
