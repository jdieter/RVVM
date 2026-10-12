/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Optional links may fail; required fault metadata must prevent publication. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "core/rvvm.h"
#include "rvjit/rvjit.h"
#include "util/utils.h"

static bool fail_realloc;
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

int main(void)
{
    check_cache(false);
    check_cache(true);
    puts("PASS JIT allocation failure, W^X execution and cache accounting");
}
