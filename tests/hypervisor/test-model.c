#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <core/rvvm.h>
#include <cpu/riscv_csr.h>
#include <util/fdtlib.h>
#include "test-support.h"

static void check_model(const char* isa, bool h)
{
    rvvm_machine_t* machine = rvvm_create_machine(16 << 20, 1, isa);
    assert(machine);
    rvvm_hart_t* hart = vector_at(machine->harts, 0);
    rvvm_uxlen_t value = 0;
    assert(riscv_csr_op(hart, CSR_MISA, &value, CSR_SETBITS));
    assert(!!(value & 128) == h && hart->hypervisor.enabled == h);
    value = 0;
    assert(riscv_csr_op(hart, CSR_HSTATUS, &value, CSR_SETBITS) == h);
    if (h) assert(value == 2ULL << 32);
    struct fdt_node* cpu = fdt_node_find_reg(fdt_node_find(rvvm_get_fdt_root(machine), "cpus"), "cpu", 0);
    const char* extensions = fdt_node_get_prop_data(cpu, "riscv,isa-extensions");
    size_t size = fdt_node_get_prop_size(cpu, "riscv,isa-extensions");
    bool found = false;
    for (size_t offset = 0; offset < size; offset += strlen(extensions + offset) + 1) {
        if (!strcmp(extensions + offset, "h")) found = true;
    }
    assert(found == h);
    const char* advertised = fdt_node_get_prop_data(cpu, "riscv,isa");
    assert(advertised);
    const char* suffix = strchr(advertised, '_');
    const char* letter = strchr(advertised, 'h');
    assert(!!(letter && (!suffix || letter < suffix)) == h);
    rvvm_free_machine(machine);
}

int main(void)
{
    enable_h();
    check_model("rv64", true);
#ifdef USE_RV32
    check_model("rv32", false);
#endif
    static char* disabled[] = { "model-test", "-nokvm" };
    rvvm_set_args(2, disabled);
    check_model("rv64", false);
#ifdef USE_RV32
    check_model("rv32", false);
#endif
    enable_h();
    rvvm_machine_t* machine = rvvm_create_userland("rv64");
    assert(machine && machine->userland);
    rvvm_hart_t* hart = rvvm_create_user_thread(machine);
    assert(hart && !hart->hypervisor.enabled);
    rvvm_free_user_thread(hart);
    vector_free(machine->harts);
    free(machine);
    puts("PASS default RV64 H, -nokvm MISA/FDT/CSR agreement and H-disabled RV32/userspace");
}
