/* Run inside the outer RISC-V Linux guest, through its standard KVM ABI. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

struct guest {
    int vm, cpu;
    uint8_t* ram;
    struct kvm_run* run;
    size_t run_size;
};

static void reg_set(int cpu, uint64_t id, unsigned long value)
{
    struct kvm_one_reg reg = { .id = id, .addr = (uintptr_t)&value };
    assert(ioctl(cpu, KVM_SET_ONE_REG, &reg) == 0);
}

#define CORE(name) (KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CORE | KVM_REG_RISCV_CORE_REG(name))

static struct guest create(int kvm, uint64_t nonce)
{
    struct guest guest = { .vm = ioctl(kvm, KVM_CREATE_VM, 0) };
    assert(guest.vm >= 0);
    guest.ram = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guest.ram != MAP_FAILED);
    // Store a3 through a2, then request SBI system shutdown.
    const uint32_t payload[] = { 0x00d63023, 0x00000513, 0x00000593, 0x00000813,
                                 0x535258b7, 0x35488893, 0x00000073, 0x0000006f };
    for (unsigned i = 0; i < sizeof(payload) / sizeof(payload[0]); i++) {
        ((uint32_t*)guest.ram)[i] = payload[i];
    }
    struct kvm_userspace_memory_region region = {
        .slot = 0, .flags = KVM_MEM_LOG_DIRTY_PAGES, .guest_phys_addr = 0x80000000,
        .memory_size = 8192, .userspace_addr = (uintptr_t)guest.ram,
    };
    assert(ioctl(guest.vm, KVM_SET_USER_MEMORY_REGION, &region) == 0);
    guest.cpu = ioctl(guest.vm, KVM_CREATE_VCPU, 0);
    assert(guest.cpu >= 0);
    guest.run_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    assert(guest.run_size >= sizeof(struct kvm_run));
    guest.run = mmap(NULL, guest.run_size, PROT_READ | PROT_WRITE, MAP_SHARED, guest.cpu, 0);
    assert(guest.run != MAP_FAILED);
    reg_set(guest.cpu, CORE(regs.pc), 0x80000000);
    reg_set(guest.cpu, CORE(mode), KVM_RISCV_MODE_S);
    reg_set(guest.cpu, CORE(regs.a2), 0x80001000);
    reg_set(guest.cpu, CORE(regs.a3), nonce);
    return guest;
}

static void execute(struct guest* guest, uint64_t nonce)
{
    int result;
    do result = ioctl(guest->cpu, KVM_RUN, 0); while (result < 0 && errno == EINTR);
    assert(result == 0);
    assert(guest->run->exit_reason == KVM_EXIT_SYSTEM_EVENT);
    assert(guest->run->system_event.type == KVM_SYSTEM_EVENT_SHUTDOWN);
    assert(*(uint64_t*)(guest->ram + 4096) == nonce);
    unsigned long dirty = 0;
    struct kvm_dirty_log log = { .slot = 0, .dirty_bitmap = &dirty };
    assert(ioctl(guest->vm, KVM_GET_DIRTY_LOG, &log) == 0);
    assert(dirty & 2);
}

static void destroy(struct guest* guest)
{
    assert(munmap(guest->run, guest->run_size) == 0);
    assert(close(guest->cpu) == 0);
    assert(close(guest->vm) == 0);
    assert(munmap(guest->ram, 8192) == 0);
}

static void* worker(void* opaque)
{
    uint64_t seed = (uintptr_t)opaque;
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    assert(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == 12);
    for (unsigned iteration = 0; iteration < 8; iteration++) {
        uint64_t first = seed + iteration * 2 + 1, second = first + 1;
        struct guest a = create(kvm, first), b = create(kvm, second);
        execute(&a, first);
        assert(*(uint64_t*)(b.ram + 4096) == 0); // Same GPA in a different VM stays private.
        execute(&b, second);
        assert(*(uint64_t*)(a.ram + 4096) == first);
        destroy(&a);
        destroy(&b);
    }
    assert(close(kvm) == 0);
    return NULL;
}

int main(void)
{
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; i++) assert(pthread_create(&threads[i], NULL, worker, (void*)(0xABCD0000 + i * 256)) == 0);
    for (unsigned i = 0; i < 2; i++) assert(pthread_join(threads[i], NULL) == 0);
    puts("PASS 32 KVM VM lifecycles, parallel execution, RAM isolation and dirty logging");
}
