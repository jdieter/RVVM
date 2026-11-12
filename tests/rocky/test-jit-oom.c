/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Optional links may fail; required fault metadata must prevent publication. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "core/rvvm.h"
#include "rvjit/rvjit.h"
#include "rvjit/rvjit_emit.h"
#include "util/utils.h"

static bool fail_realloc;
static bool fail_calloc;
void* __real_calloc(size_t, size_t);
void* __wrap_calloc(size_t count, size_t size)
{
    if (fail_calloc) { fail_calloc = false; return NULL; }
    return __real_calloc(count, size);
}
void* __real_realloc(void*, size_t);
void* __wrap_realloc(void* p, size_t n)
{
    if (fail_realloc) { fail_realloc = false; return NULL; }
    return __real_realloc(p, n);
}

static void check_cache(bool split)
{
    char* args[] = {"test-jit-oom", "--rvjit_disable_rwx"};
    rvvm_set_args(split ? 2 : 1, args);
    rvjit_block_t block = {0};
    rvvm_hart_t* hart = calloc(1, sizeof(*hart));
    assert(hart && rvjit_ctx_init(&block, 1 << 20));
    rvjit_set_rv64(&block, true);
    assert(rvjit_set_native_ptrs(&block, true));
    size_t mapped = block.heap.size * (block.heap.code == block.heap.data ? 1 : 2);
    assert(rvjit_ctx_memory_size(&block) > mapped);
    assert(rvjit_user_memory_size(block.heap.size) >= rvjit_ctx_memory_size(&block));
    if (split) assert(block.heap.code != block.heap.data);
    rvjit_block_init(&block);
    block.phys_pc = block.virt_pc = 0x1000;
    block.pc_off = 4;
    fail_realloc = true;
    rvjit_func_t code = rvjit_block_finalize(&block);
    assert(!fail_realloc && code && !block.links.count);
    hart->registers[RISCV_REG_PC] = 0x1000;
    code(hart);
    assert(hart->registers[RISCV_REG_PC] == 0x1004);
    rvjit_block_init(&block);
    block.phys_pc = block.virt_pc = 0x2000;
    block.pc_off = 4;
    fail_realloc = true;
    rvjit_fault_record(&block, 4);
    assert(!fail_realloc && !rvjit_block_finalize(&block));
    assert(!rvjit_block_lookup(&block, 0x2000));
    rvjit_block_init(&block);
    block.phys_pc = block.virt_pc = 0x2000;
    block.pc_off = 4;
    rvjit_fault_record(&block, 4);
    assert(rvjit_block_finalize(&block));
    rvjit_ctx_free(&block);
    assert(!rvjit_ctx_memory_size(&block));
    free(hart);
}

static void load_block(rvjit_block_t* block, uintptr_t pc)
{
    rvjit_block_init(block);
    block->phys_pc = block->virt_pc = pc;
    block->pc_off = 4;
    rvjit64_ld(block, 1, 2, 0);
}

static void check_metadata_growth(void)
{
    char* args[] = {"test-jit-oom"};
    rvvm_set_args(1, args);
    struct rlimit original;
    assert(!getrlimit(RLIMIT_AS, &original) && original.rlim_cur == RLIM_INFINITY);
    rvjit_block_t block = {0};
    assert(rvjit_ctx_init(&block, 16U << 20));
    rvjit_set_rv64(&block, true);
    assert(rvjit_set_native_ptrs(&block, true));
    size_t capacity = block.heap.faults.size;
    size_t lookup = hashmap_capacity(&block.heap.blocks);
    uintptr_t pc = 0x1000;
    while (block.heap.faults.count < capacity) {
        load_block(&block, pc);
        if (hashmap_size(&block.heap.blocks) == lookup / 2
            && hashmap_capacity(&block.heap.blocks) == lookup) {
            size_t before = rvjit_ctx_memory_size(&block);
            fail_calloc = true;
            assert(!rvjit_block_finalize(&block) && !fail_calloc);
            assert(!rvjit_block_lookup(&block, pc));
            assert(rvjit_block_lookup(&block, 0x1000));
            assert(rvjit_ctx_memory_size(&block) == before);
            load_block(&block, pc);
        }
        assert(rvjit_block_finalize(&block));
        pc += 4;
    }
    assert(block.heap.faults.count == capacity);
    assert(hashmap_capacity(&block.heap.blocks) > lookup);
    assert(rvjit_block_lookup(&block, 0x1000));
    load_block(&block, pc);
    size_t before = rvjit_ctx_memory_size(&block);

    /* Limits lowered after startup retain the old cache and its metadata.
     * A refused growth must not publish a partially described block. */
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        struct rlimit tight = {1, original.rlim_max};
        assert(!setrlimit(RLIMIT_AS, &tight));
        assert(!rvjit_block_finalize(&block));
        assert(!rvjit_block_lookup(&block, pc));
        assert(rvjit_block_lookup(&block, 0x1000));
        assert(rvjit_ctx_memory_size(&block) == before);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    /* A finite limit with ample headroom must not restore the old metadata
     * ceilings and compiler cache thrashing. */
    child = fork();
    assert(child >= 0);
    if (!child) {
        struct rlimit finite = {1U << 30, original.rlim_max};
        assert(!setrlimit(RLIMIT_AS, &finite));
        assert(rvjit_block_finalize(&block));
        assert(block.heap.faults.size > capacity);
        assert(rvjit_block_lookup(&block, 0x1000));
        _exit(0);
    }
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    fail_realloc = true;
    assert(!rvjit_block_finalize(&block) && !fail_realloc);
    assert(!rvjit_block_lookup(&block, pc));
    assert(rvjit_ctx_memory_size(&block) == before);
    load_block(&block, pc);
    rvjit_func_t code = rvjit_block_finalize(&block);
    assert(code && block.heap.faults.size > capacity);
    assert(rvjit_ctx_memory_size(&block) > before);
    const rvjit_fault_t* last = &block.heap.faults.data[block.heap.faults.count - 1];
    assert(rvjit_fault_lookup(&block, (uintptr_t)block.heap.code + last->start) == last);
    assert(last->guest_pc == pc + 4);
    const rvjit_fault_t* first = &block.heap.faults.data[0];
    assert(first->guest_pc == 0x1004);
    assert(rvjit_fault_lookup(&block, (uintptr_t)block.heap.code + first->start) == first);
    assert(rvjit_block_lookup(&block, 0x1000));
    rvjit_flush_cache(&block);
    assert(!rvjit_block_lookup(&block, pc));
    assert(rvjit_ctx_memory_size(&block) > before);
    rvjit_ctx_free(&block);
}

static void check_fault_registers(void)
{
    uint8_t regs[RVJIT_FAULT_REG_BYTES];
    uint8_t expected[RVJIT_FAULT_REG_COUNT];
    memset(regs, RVJIT_FAULT_REG_EMPTY, sizeof(regs));
    for (unsigned host = 0; host < RVJIT_FAULT_REG_COUNT; ++host) {
        expected[host] = host % 31 + 1;
        rvjit_fault_reg_set(regs, host, expected[host]);
    }
    /* All guest values at every host slot, including packed byte boundaries. */
    for (unsigned host = 0; host < RVJIT_FAULT_REG_COUNT; ++host) {
        for (unsigned guest = 1; guest < 32; ++guest) {
            rvjit_fault_reg_set(regs, host, guest);
            expected[host] = guest;
            for (unsigned other = 0; other < RVJIT_FAULT_REG_COUNT; ++other)
                assert(rvjit_fault_reg_get(regs, other) == expected[other]);
        }
        rvjit_fault_reg_set(regs, host, REG_ILL);
        expected[host] = REG_ILL;
        assert(rvjit_fault_reg_get(regs, host) == REG_ILL);
    }
    rvjit_fault_t fault = {.start = 100};
#ifdef RVJIT_X86
    fault.length = 4;
#elif !defined(RVJIT_ARM64)
    fault.end = 104;
#endif
    assert(rvjit_fault_end_offset(&fault) == 104);
#ifdef RVJIT_ARM64
    rvjit_block_t block = {0};
    rvjit_fault_record(&block, 8);
    assert(block.fault_failed && !block.faults.count);
#elif defined(RVJIT_X86)
    rvjit_block_t block = {0};
    rvjit_fault_record(&block, (size_t)UINT16_MAX + 1);
    assert(block.fault_failed && !block.faults.count);
#endif
}

static void check_fault_allocation(void)
{
    rvjit_block_t block = {0};
    assert(rvjit_ctx_init(&block, 1U << 20));
    rvjit_set_rv64(&block, true);
    assert(rvjit_set_native_ptrs(&block, true));
    rvjit_block_init(&block);
    block.phys_pc = block.virt_pc = 0x1000;
    fail_realloc = true;
    rvjit64_ld(&block, 1, 2, 0);
    assert(!fail_realloc && block.fault_failed && !block.faults.count);
    assert(!rvjit_block_finalize(&block));
    rvjit_ctx_free(&block);
}

int main(void)
{
    check_fault_registers();
    check_fault_allocation();
    check_cache(false);
    check_cache(true);
    check_metadata_growth();
    puts("PASS JIT allocation failure, W^X execution and cache accounting");
}
