/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "util/feature_test.h"
#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "util/elf_load.h"
#include "util/vma_ops.h"

static size_t page, mapped;
static bool fallback;

static void* reserve(void* addr, size_t size)
{
    assert(!addr);
    void* ret = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return ret == MAP_FAILED ? NULL : ret;
}

static bool map_file(rvfile_t* file, void* addr, size_t size, uint64_t offset)
{
    assert(!((uintptr_t)addr % page) && !(size % page) && !(offset % page));
    if (fallback || offset > rvfilesize(file) || size > rvfilesize(file) - offset) return false;
    assert(mmap(addr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED,
                rvfile_get_posix_fd(file), offset) == addr);
    mapped += size;
    return true;
}

static void release(elf_desc_t* elf)
{
    assert(!munmap(elf->base, elf->buf_size));
    free(elf->phdr_data);
    free(elf->interp_path);
}

int main(void)
{
    page = vma_page_size();
    size_t length = 14 * page;
    unsigned char* image = malloc(length);
    memset(image, 0xa5, length);
    for (size_t i = 6 * page; i < 9 * page; ++i) image[i] = (unsigned char)(i / page);
    Elf64_Ehdr* eh = (void*)image;
    *eh = (Elf64_Ehdr){.e_type = ET_DYN, .e_machine = EM_RISCV, .e_version = EV_CURRENT,
        .e_phoff = sizeof(*eh), .e_phentsize = sizeof(Elf64_Phdr), .e_phnum = 3};
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_ident[EI_DATA] = ELFDATA2LSB;
    Elf64_Phdr* ph = (void*)(image + eh->e_phoff);
    ph[0] = (Elf64_Phdr){.p_type = PT_LOAD, .p_flags = PF_R | PF_X,
        .p_filesz = 3 * page + 37, .p_memsz = 3 * page + 37};
    ph[1] = (Elf64_Phdr){.p_type = PT_LOAD, .p_flags = PF_R,
        .p_vaddr = 6 * page + 13, .p_offset = 6 * page + 13,
        .p_filesz = 2 * page + 29, .p_memsz = 2 * page + 29};
    ph[2] = (Elf64_Phdr){.p_type = PT_LOAD, .p_flags = PF_R | PF_W,
        .p_vaddr = 10 * page + 7, .p_offset = 10 * page + 7,
        .p_filesz = page + 31, .p_memsz = 2 * page + 57};
    char path[] = "/tmp/rvvm-elf-pages.XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0 && write(fd, image, length) == (ssize_t)length);
    close(fd);
    for (int mode = 0; mode < 4; ++mode) {
        if (mode == 3) {
            /* The second LOAD overwrites part of the first one's last pages. */
            ph[1].p_vaddr = 2 * page + 33;
            ph[1].p_offset = 6 * page + 33;
            fd = open(path, O_WRONLY);
            assert(fd >= 0 && pwrite(fd, image, page, 0) == (ssize_t)page);
            close(fd);
        }
        fallback = mode == 1;
        mapped = 0;
        rvfile_t* file = rvopen(path, RVFILE_READ);
        elf_desc_t elf = {.map = reserve, .map_file = map_file};
        unsigned char* output = NULL;
        if (mode == 2) {
            output = calloc(1, length);
            elf.base = output;
            elf.buf_size = length;
        }
        assert(file && elf_load_file(file, &elf));
        assert(mapped == (mode == 0 || mode == 3 ? 4 * page : 0));
        unsigned char* expected = calloc(1, elf.buf_size);
        for (int i = 0; i < 3; ++i) {
            memcpy(expected + ph[i].p_vaddr, image + ph[i].p_offset, ph[i].p_filesz);
            memset(expected + ph[i].p_vaddr + ph[i].p_filesz, 0, ph[i].p_memsz - ph[i].p_filesz);
        }
        assert(!memcmp(elf.base, expected, elf.buf_size));
        free(expected);
        if (!mode) {
            /* A private write must not change either the file or another mapping. */
            unsigned char* other = mmap(NULL, page, PROT_READ, MAP_PRIVATE, rvfile_get_posix_fd(file), page);
            assert(other != MAP_FAILED && other[0] == 0xa5);
            ((unsigned char*)elf.base)[page] = 0x7f;
            assert(other[0] == 0xa5);
            assert(!munmap(other, page));
        }
        if (output) free(output); else release(&elf);
        rvclose(file);
    }
    assert(!truncate(path, page));
    rvfile_t* short_file = rvopen(path, RVFILE_READ);
    elf_desc_t elf = {.map = reserve, .map_file = map_file};
    assert(short_file && !elf_load_file(short_file, &elf));
    release(&elf);
    rvclose(short_file);
    unlink(path);
    free(image);
    puts("PASS ELF file pages, unaligned/overlapping segments, BSS, COW, fallback and objcopy");
    return 0;
}
