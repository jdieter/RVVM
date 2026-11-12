/*
elf_load.c - ELF Loader
Copyright (C) 2023  LekKit <github.com/LekKit>
              2021  cerg2010cerg2010 <github.com/cerg2010cerg2010>

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#include "elf_load.h"
#include "mem_ops.h"
#include "utils.h"
#include "vma_ops.h"

PUSH_OPTIMIZATION_SIZE

#define ELF_ET_NONE    0x00
#define ELF_ET_REL     0x01
#define ELF_ET_EXEC    0x02
#define ELF_ET_DYN     0x03

#define ELF_PT_NULL    0x00
#define ELF_PT_LOAD    0x01
#define ELF_PT_DYNAMIC 0x02
#define ELF_PT_INTERP  0x03
#define ELF_PT_NOTE    0x04
#define ELF_PT_SHLIB   0x05
#define ELF_PT_PHDR    0x06
#define ELF_PT_TLS     0x07

#define ELF_PF_X       0x01
#define ELF_PF_W       0x02
#define ELF_PF_R       0x04

// Padding past the fixed ELF image, usable as guest brk heap
#define ELF_USERLAND_HEAP_MARGIN 0x10000000

// TODO: Handling >64k PHENTs
#define ELF_PN_XNUM    0xFFFF

#define WRAP_ERR(cond, error)                                                                                          \
    if (!(cond)) {                                                                                                     \
        rvvm_error(error);                                                                                             \
        return false;                                                                                                  \
    }

static bool elf_load_segment(rvfile_t* file, elf_desc_t* elf, void* addr, size_t size,
                             uint64_t offset, bool readonly)
{
    size_t prefix = size, mapped = 0;
    if (readonly && elf->map_file) {
        size_t page = vma_page_size();
        size_t skip = (-(uintptr_t)addr) & (page - 1);
        /* Leave partial pages anonymous: another LOAD segment may occupy
         * their other bytes, or the file tail may be followed by BSS. */
        if (skip < size && ((offset + skip) & (page - 1)) == 0) {
            size_t span = (size - skip) & ~(page - 1);
            if (span && offset <= UINT64_MAX - skip
                && elf->map_file(file, (char*)addr + skip, span, offset + skip)) {
                prefix = skip;
                mapped = span;
            }
        }
    }
    if (prefix && rvread(file, addr, prefix, offset) != prefix) return false;
    size_t tail = prefix + mapped;
    return tail == size || rvread(file, (char*)addr + tail, size - tail, offset + tail) == size - tail;
}

bool elf_load_file(rvfile_t* file, elf_desc_t* elf)
{
    uint8_t tmp[64] = {0};
    WRAP_ERR(file && elf, "Invalid arguments to elf_load_file()");
    WRAP_ERR(rvread(file, tmp, 64, 0) == 64, "Failed to read ELF header");
    WRAP_ERR(read_uint32_le_m(tmp) == 0x464c457F, "Not an ELF file");
    WRAP_ERR(tmp[4] == 1 || tmp[4] == 2, "Invalid ELF class");
    WRAP_ERR(tmp[5] == 1, "Not a little-endian ELF");

    // Parse ELF header
    bool     objcopy   = !!elf->base;
    bool     class64   = (tmp[4] == 2);
    uint16_t elf_type  = read_uint16_le_m(tmp + 16);
    uint64_t elf_entry = class64 ? read_uint64_le_m(tmp + 24) : read_uint32_le_m(tmp + 24);
    uint64_t elf_phoff = class64 ? read_uint64_le_m(tmp + 32) : read_uint32_le_m(tmp + 28);
    // uint64_t elf_shoff = class64 ? read_uint64_le_m(tmp + 40) : read_uint32_le_m(tmp + 32);
    size_t elf_phnsz = class64 ? 56 : 32;
    size_t elf_phnum = read_uint16_le_m(tmp + (class64 ? 56 : 44));

    elf->entry       = elf_entry;
    elf->interp_path = NULL;
    elf->phdr        = 0;
    elf->phnum       = elf_phnum;
    elf->phdr_data   = NULL;
    elf->phentsize   = elf_phnsz;

    // Determine lowest / highest virtual address, PHDR address
    uint64_t elf_loaddr = (uint64_t)-1;
    uint64_t elf_hiaddr = 0;
    bool have_phdr = false;
    for (size_t i = 0; i < elf_phnum; ++i) {
        uint64_t elf_phent_off = elf_phoff + (elf_phnsz * i);
        WRAP_ERR(rvread(file, tmp, elf_phnsz, elf_phent_off) == elf_phnsz, "Failed to read ELF phent");
        uint32_t p_type  = read_uint32_le_m(tmp);
        uint64_t p_vaddr = class64 ? read_uint64_le_m(tmp + 16) : read_uint32_le_m(tmp + 8);
        uint64_t p_memsz = class64 ? read_uint64_le_m(tmp + 40) : read_uint32_le_m(tmp + 20);
        if (p_type == ELF_PT_LOAD || p_type == ELF_PT_PHDR) {
            if (p_vaddr < elf_loaddr) {
                elf_loaddr = p_vaddr;
            }
            if (p_vaddr + p_memsz > elf_hiaddr) {
                elf_hiaddr = p_vaddr + p_memsz;
            }
        }
        if (p_type == ELF_PT_PHDR) {
            elf->phdr = p_vaddr;
            have_phdr = true;
        } else if (p_type == ELF_PT_LOAD && !have_phdr) {
            // PT_PHDR is optional: the table can reside inside a LOAD segment.
            uint64_t offset = class64 ? read_uint64_le_m(tmp + 8) : read_uint32_le_m(tmp + 4);
            uint64_t filesz = class64 ? read_uint64_le_m(tmp + 32) : read_uint32_le_m(tmp + 16);
            if (elf_phoff >= offset && elf_phoff - offset <= filesz
                && elf_phnum * elf_phnsz <= filesz - (elf_phoff - offset)) {
                elf->phdr = p_vaddr + (elf_phoff - offset);
                have_phdr = true;
            }
        }
    }
    if (elf_loaddr == (uint64_t)-1) {
        elf_loaddr = 0; // No ELF segments
    }

    // Relocate pointers
    if (objcopy) {
        if (elf->entry) {
            elf->entry -= elf_loaddr;
        }
        if (have_phdr) {
            elf->phdr -= elf_loaddr;
        }
    } else {
        // Userland ELF loading
        elf->buf_size = elf_hiaddr - elf_loaddr;
        if (elf_type == ELF_ET_DYN) {
            // Dynamic (PIC) ELF, relocate it
            elf->base = elf->map ? elf->map(NULL, elf->buf_size) : vma_alloc(NULL, elf->buf_size, VMA_RDWR);
            WRAP_ERR(elf->base, "Failed to allocate dynamic ELF VMA");
        } else {
            // Non-relocatable ELF at fixed address
            // Extra pages past the image serve as the initial brk heap area,
            // real kernels map them accessible right after the image
            elf->base = elf->map ? elf->map((void*)(size_t)elf_loaddr, elf->buf_size + ELF_USERLAND_HEAP_MARGIN)
                : vma_alloc((void*)(size_t)elf_loaddr, elf->buf_size + ELF_USERLAND_HEAP_MARGIN, VMA_RDWR | VMA_FIXED);
            WRAP_ERR(elf->base, "Failed to map fixed ELF VMA, address collision?");
        }
        if (elf->entry) {
            elf->entry += (size_t)elf->base - elf_loaddr;
        }
        if (have_phdr) {
            elf->phdr += (size_t)elf->base - elf_loaddr;
        }
    }

    for (size_t i = 0; i < elf_phnum; ++i) {
        uint64_t elf_phent_off = elf_phoff + (elf_phnsz * i);
        WRAP_ERR(rvread(file, tmp, elf_phnsz, elf_phent_off) == elf_phnsz, "Failed to read ELF phent");
        uint32_t p_type   = read_uint32_le_m(tmp);
        uint64_t p_offset = class64 ? read_uint64_le_m(tmp + 8) : read_uint32_le_m(tmp + 4);
        uint64_t p_vaddr  = class64 ? read_uint64_le_m(tmp + 16) : read_uint32_le_m(tmp + 8);
        uint64_t p_fsize  = class64 ? read_uint64_le_m(tmp + 32) : read_uint32_le_m(tmp + 16);
        uint64_t p_memsz  = class64 ? read_uint64_le_m(tmp + 40) : read_uint32_le_m(tmp + 20);
        uint32_t p_flags = class64 ? read_uint32_le_m(tmp + 4) : read_uint32_le_m(tmp + 24);

        if (p_type == ELF_PT_LOAD || p_type == ELF_PT_PHDR) {
            // Load ELF program segment or PHDR segment
            void* vaddr = ((uint8_t*)elf->base) + (p_vaddr - elf_loaddr);
            WRAP_ERR(p_vaddr + p_memsz <= elf_loaddr + elf->buf_size, "ELF segment does not fit in memory");
            WRAP_ERR(p_fsize <= p_memsz, "ELF file segment exceeds memory size");
            WRAP_ERR(elf_load_segment(file, elf, vaddr, p_fsize, p_offset,
                                     !objcopy && !(p_flags & ELF_PF_W)), "Failed to read ELF segment");
        }
        if (p_type == ELF_PT_INTERP && !objcopy && !elf->interp_path) {
            // Get ELF interpreter path
            WRAP_ERR(p_fsize < 1024, "ELF interpreter path is too long");
            elf->interp_path = safe_new_arr(char, p_fsize + 1);
            WRAP_ERR(rvread(file, elf->interp_path, p_fsize, p_offset) == p_fsize, "Failed to read ELF interp_path");
        }
    }

    if (!objcopy) {
        elf->load_bias = (size_t)elf->base - elf_loaddr;
        size_t size = elf_phnum * elf_phnsz;
        void* headers = safe_malloc(size);
        if (rvread(file, headers, size, elf_phoff) != size) {
            free(headers);
            return false;
        }
        elf->phdr_data = headers;
    }
    return true;
}

bool bin_objcopy(rvfile_t* file, void* buffer, size_t size, bool try_elf)
{
    uint8_t mag[4] = {0};
    if (try_elf && rvread(file, mag, 4, 0) == 4 && read_uint32_le_m(mag) == 0x464c457F) {
        elf_desc_t elf = {
            .base     = buffer,
            .buf_size = size,
        };
        if (elf_load_file(file, &elf)) {
            return true;
        }
    }
    return rvread(file, buffer, size, 0);
}

POP_OPTIMIZATION_SIZE
