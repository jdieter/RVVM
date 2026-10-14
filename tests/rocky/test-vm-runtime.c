/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "feature_test.h"
#include "utils.h"
#include <assert.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "core/rvvm_user_vm.h"

static size_t virtual_bytes(void)
{
    FILE* stat = fopen("/proc/self/statm", "r");
    size_t pages;
    assert(stat && fscanf(stat, "%zu", &pages) == 1);
    fclose(stat);
    return pages * (size_t)sysconf(_SC_PAGESIZE);
}

static void test_protection_offsets(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    char* memory = user_vma_map(NULL, page * 4, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);
    for (size_t i = 0; i < 4; ++i) memory[i * page] = 17 + i;
    struct user_vm* vm = user_vm_prepare();
    assert(vm && !user_vm_share(vm));
    for (size_t i = 1; i < 4; ++i) assert(!user_vm_split(vm, (uintptr_t)memory + i * page));
    int prot[] = {PROT_READ | PROT_WRITE, PROT_WRITE, PROT_NONE, PROT_READ};
    for (size_t i = 0; i < vm->count; ++i) {
        struct user_vm_region* region = vm->regions + i;
        size_t index = (region->address - (uintptr_t)memory) / page;
        assert(index < 4 && region->size == page && region->offset == index * page);
        assert(!mprotect(region->original, page, prot[index]));
        region->prot = prot[index];
    }
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        for (size_t i = 0; i < 4; ++i) memory[i * page] = 71 + i;
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && !status);
    assert(!user_vm_restore(vm));
    user_vm_destroy(vm);
    assert(!mprotect(memory, page * 4, PROT_READ | PROT_WRITE));
    for (size_t i = 0; i < 4; ++i) assert(memory[i * page] == 71 + i);
    assert(!user_vma_unmap(memory, page * 4));
}

static void test_finite_address_space(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    char* memory = user_vma_map(NULL, page * 16, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(memory != MAP_FAILED);
    memory[0] = 17;
    struct rlimit saved;
    assert(!getrlimit(RLIMIT_AS, &saved));
    struct user_vm* vm = user_vm_prepare();
    assert(vm);
    size_t before = virtual_bytes();
    struct rlimit limited = saved;
    limited.rlim_cur = before + page;
    assert(!setrlimit(RLIMIT_AS, &limited));
    assert(!user_vm_share(vm) && virtual_bytes() == before);
    memory[0] = 42;
    assert(!user_vm_restore(vm) && memory[0] == 42);
    assert(!setrlimit(RLIMIT_AS, &saved));
    user_vm_destroy(vm);

    vm = user_vm_prepare();
    assert(vm);
    limited.rlim_cur = virtual_bytes() - page;
    assert(!setrlimit(RLIMIT_AS, &limited));
    assert(user_vm_share(vm) == -1 && errno == ENOMEM && memory[0] == 42);
    assert(!setrlimit(RLIMIT_AS, &saved));
    user_vm_destroy(vm);
    assert(!user_vma_unmap(memory, page * 16));
}

static void expect_sigbus(char* address)
{
    pid_t child = fork();
    assert(child >= 0);
    if (!child) { (void)*(volatile char*)address; _exit(1); }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS);
}

int main(void)
{
    size_t page = sysconf(_SC_PAGESIZE), size = (size_t)1 << 30;
    // glibc marks the main stack executable through its top page only.
    char* stack = user_vma_map(NULL, page * 5, PROT_NONE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    assert(stack != MAP_FAILED && !mprotect(stack + page, page * 3, PROT_READ | PROT_WRITE));
    uintptr_t start = (uintptr_t)(stack + page * 3);
    size_t span = page;
    assert(!user_vma_protect_span(&start, &span, PROT_GROWSDOWN));
    assert(start == (uintptr_t)(stack + page) && span == page * 3);
    assert(!mprotect(stack + page * 3, page, PROT_READ | PROT_GROWSDOWN));
    span = 0;
    assert(!user_vma_protect_span(&start, &span, PROT_GROWSDOWN) && !span);
    assert(!user_vma_unmap(stack, page * 5));
    char* source = user_vma_map(NULL, page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char* hint = user_vma_map(NULL, page * 64, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(source != MAP_FAILED && hint != MAP_FAILED);
    source[0] = 17;
    assert(!user_vma_unmap(hint, page * 64));
    assert(user_vma_remap(source, page, page, MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
                          hint + 1) == MAP_FAILED && errno == EINVAL && source[0] == 17);
    assert(user_vma_remap(source, page, page, MREMAP_MAYMOVE | MREMAP_DONTUNMAP,
                          source) == MAP_FAILED && errno == EINVAL && source[0] == 17);
    char* moved = user_vma_remap(source, page, page, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, hint);
    assert(moved == hint && moved[0] == 17 && !source[0]);
    source[0] = 23;
    assert(moved[0] == 17);
    char* again = user_vma_remap(source, page, page, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, moved);
    assert(again != MAP_FAILED && again != moved && again[0] == 23 && moved[0] == 17);
    assert(!user_vma_unmap(source, page) && !user_vma_unmap(moved, page) && !user_vma_unmap(again, page));
    assert(!user_vma_owned_count);
    unsigned char* memory = user_vma_map(NULL, size, PROT_NONE,
                                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    assert(memory != MAP_FAILED);
    assert(!mprotect(memory, page, PROT_READ | PROT_WRITE));
    assert(!mprotect(memory + size - page, page, PROT_READ | PROT_WRITE));
    memory[0] = 17;
    memory[size - 1] = 23;
    int file = user_vm_backing_create(page * 2);
    assert(file >= 0 && pwrite(file, "original", 8, 0) == 8);
    assert(pwrite(file, "unchanged", 9, page) == 9);
    char* private = user_vma_map(NULL, page * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0);
    assert(private != MAP_FAILED);
    struct user_vm* vm = user_vm_prepare();
    assert(vm && !user_vm_share(vm));
    expect_sigbus(private + page * 2);
    struct stat allocated;
    for (size_t i = 0; i < vm->count; ++i) {
        assert(!fstat(vm->regions[i].backing, &allocated));
        assert((size_t)allocated.st_blocks * 512 < page * 8);
    }
    int native = 123;
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        memory[0] = 42;
        memory[size - 1] = 99;
        memcpy(private, "changed!", 8);
        native = 456;
        _exit(native == 456 ? 0 : 1);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && !status);
    assert(memory[0] == 42 && memory[size - 1] == 99 && native == 123);
    assert(!memcmp(private, "changed!", 8));
    assert(pwrite(file, "external!", 9, page) == 9);
    assert(!user_vm_restore(vm));
    user_vm_destroy(vm);
    char bytes[8];
    assert(pread(file, bytes, sizeof(bytes), 0) == sizeof(bytes));
    assert(!memcmp(bytes, "original", sizeof(bytes)));
    assert(memory[0] == 42 && memory[size - 1] == 99);
    assert(!memcmp(private, "changed!", 8));
    assert(!memcmp(private + page, "external!", 9));
    expect_sigbus(private + page * 2);
    child = fork();
    assert(child >= 0);
    if (!child) { memory[0] = 1; private[0] = 'X'; _exit(0); }
    assert(waitpid(child, &status, 0) == child && !status);
    assert(memory[0] == 42 && private[0] == 'c');
    assert(!user_vma_unmap(memory, size));
    assert(!user_vma_unmap(private, page * 3));
    assert(!user_vma_owned_count);
    int segment = shmget(IPC_PRIVATE, page * 3, IPC_CREAT | 0600);
    assert(segment >= 0);
    char* attachment = user_vma_shmat(segment, NULL, 0);
    assert(attachment != (void*)-1);
    assert(!shmctl(segment, IPC_RMID, NULL));
    assert(user_vma_map(attachment + page, page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == attachment + page);
    assert(!user_vma_shmdt(attachment));
    assert(user_vma_owned_count == 1 && user_vma_owned[0].start == (uintptr_t)attachment + page
           && user_vma_owned[0].end == (uintptr_t)attachment + page * 2);
    assert(!user_vma_unmap(attachment + page, page));
    assert(!user_vma_owned_count);
    close(file);
    test_protection_offsets();
    test_finite_address_space();
    puts("PASS temporary shared views, file isolation, restored fork COW and SysV detach ownership");
    return 0;
}
