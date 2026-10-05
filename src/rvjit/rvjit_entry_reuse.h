/* SPDX-License-Identifier: MPL-2.0 */
#ifndef RVJIT_ENTRY_REUSE_H
#define RVJIT_ENTRY_REUSE_H
#include <stdio.h>

/* Reuse only an exact prefix of VM-register loads on a known backward edge.
 * All dirty guest registers are still saved before linking, so cold entries,
 * faults and debugger stops keep the existing memory-state contract. */
static size_t rvjit_entry_reuse(rvjit_block_t* block, uint8_t linkage, regmask_t* keep)
{
#ifdef RVJIT_ARM64
    if (!block->entry_reuse || !block->rv64 || !block->native_ptrs ||
        linkage != LINKAGE_JMP || block->pc_off > 0) return 0;
    rvjit_addr_t next = block->phys_pc + block->pc_off;
    if ((next >> 12) != (block->phys_pc >> 12)) return 0;
    const uint8_t* code;
    size_t available;
    if (next == block->phys_pc) {
        code = block->code;
        available = block->size;
    } else {
        uintptr_t target = hashmap_get(&block->heap.blocks, next);
        if (!target) return 0;
        target += (uintptr_t)block->heap.data - (uintptr_t)block->heap.code;
        code = (const uint8_t*)target;
        available = block->heap.curr - (code - block->heap.data);
    }
    block->reuse_candidates++;
    size_t skip = 0;
    while (skip + 4 <= available && skip < 32) {
        uint32_t insn = read_uint32_le(code + skip);
        /* LDR Xt, [X0, #unsigned_scaled_offset], without writeback. */
        if ((insn & 0xFFC003E0U) != 0xF9400000U) break;
        regid_t host = insn & 31;
        size_t offset = ((insn >> 10) & 0xFFF) * 8;
        if (offset < VM_REG_OFFSET(1) || offset > VM_REG_OFFSET(31) ||
            (offset - VM_REG_OFFSET(0)) % sizeof(rvvm_uxlen_t)) break;
        regid_t guest = (offset - VM_REG_OFFSET(0)) / sizeof(rvvm_uxlen_t);
        /* Restoring the host ABI must not overwrite any retained value. */
        if (!(rvjit_native_default_hregmask() & rvjit_hreg_mask(host)) ||
            block->regs[guest].hreg != host ||
            !(block->regs[guest].flags & (REG_LOADED | REG_DIRTY))) break;
        *keep |= rvjit_hreg_mask(host);
        skip += 4;
    }
    if (skip) {
        block->reuse_links++;
        block->reuse_loads += skip / 4;
        if (block->reuse_stats)
            fprintf(stderr, "JIT reuse edge %llx -> %llx skip=%zu keep=%x\n",
                    (unsigned long long)block->phys_pc, (unsigned long long)next,
                    skip, (unsigned)*keep);
    }
    return skip;
#else
    UNUSED(block);
    UNUSED(linkage);
    UNUSED(keep);
    return 0;
#endif
}

#endif
