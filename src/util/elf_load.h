/*
elf_load.h - ELF Loader
Copyright (C) 2023  LekKit <github.com/LekKit>
              2021  cerg2010cerg2010 <github.com/cerg2010cerg2010>

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#ifndef ELF_LOAD_H
#define ELF_LOAD_H

#include "blk_io.h"

typedef struct {
    // Pass a buffer for objcopy, NULL for userland loading
    // Receive base ELF address for userland
    void*  base;
    // Objcopy buffer size
    size_t buf_size;

    // Various loaded ELF info
    size_t entry;
    char*  interp_path;
    size_t phdr;
    size_t phnum;
    // Host-owned headers for permission setup, even when not guest-mapped.
    void* phdr_data;
    size_t phentsize;
    size_t load_bias;
    /* Optional placement policy for user emulation; objcopy is unaffected. */
    void* (*map)(void* addr, size_t size);
} elf_desc_t;

bool elf_load_file(rvfile_t* file, elf_desc_t* elf);

bool bin_objcopy(rvfile_t* file, void* buffer, size_t size, bool try_elf);

#endif
