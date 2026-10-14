#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>
#define rvvm_irq_set pci_test_irq
#include <core/rvvm_pci.c>
#undef rvvm_irq_set

static atomic_bool wire;
static atomic_bool block_raise, entered, release_raise, lower_started;
static atomic_bool block_lower, mask_entered, release_lower, unmask_started;

void pci_test_irq(rvvm_irq_dev_t* device, rvvm_irq_t irq, bool level)
{
    (void)device;
    (void)irq;
    if (level && atomic_load(&block_raise)) {
        atomic_store(&entered, true);
        while (!atomic_load(&release_raise)) sched_yield();
    }
    if (!level && atomic_load(&block_lower)) {
        atomic_store(&mask_entered, true);
        while (!atomic_load(&release_lower)) sched_yield();
    }
    wire = level;
}

static void* raise_thread(void* function)
{
    pci_func_set_intx(function, true);
    return NULL;
}

static void* lower_thread(void* function)
{
    atomic_store(&lower_started, true);
    pci_func_set_intx(function, false);
    return NULL;
}

static void* mask_thread(void* function)
{
    pci_func_cfg_write(function, PCI_REG_CMD, PCI_CMD_BUS_MASTER | PCI_CMD_INTX_OFF);
    return NULL;
}

static void* unmask_thread(void* function)
{
    atomic_store(&unmask_started, true);
    pci_func_cfg_write(function, PCI_REG_CMD, PCI_CMD_BUS_MASTER);
    return NULL;
}

int main(void)
{
    rvvm_pci_bus_t bus = { .irqs = {1, 2, 3, 4} };
    rvvm_pci_func_t a = { .bus = &bus, .irq_pin = 1, .command = PCI_CMD_BUS_MASTER };
    rvvm_pci_func_t b = { .bus = &bus, .addr = 4 << 3, .irq_pin = 1, .command = PCI_CMD_BUS_MASTER };
    pci_func_set_intx(&a, true);
    pci_func_set_intx(&b, true);
    pci_func_cfg_write(&a, PCI_REG_CMD, PCI_CMD_BUS_MASTER | PCI_CMD_INTX_OFF);
    assert(wire);
    pci_func_cfg_write(&b, PCI_REG_CMD, PCI_CMD_BUS_MASTER | PCI_CMD_INTX_OFF);
    assert(!wire);
    pci_func_cfg_write(&a, PCI_REG_CMD, PCI_CMD_BUS_MASTER);
    pci_func_cfg_write(&b, PCI_REG_CMD, PCI_CMD_BUS_MASTER);
    assert(wire);
    pci_func_set_intx(&a, false);
    assert(wire); // Another function still asserts the same wired INTx pin.
    pci_func_set_intx(&b, false);
    assert(!wire);
    atomic_store(&block_raise, true);
    pthread_t raise, lower;
    assert(!pthread_create(&raise, NULL, raise_thread, &a));
    while (!atomic_load(&entered)) sched_yield();
    assert(!pthread_create(&lower, NULL, lower_thread, &a));
    while (!atomic_load(&lower_started)) sched_yield();
    usleep(10000);
    atomic_store(&release_raise, true);
    assert(!pthread_join(raise, NULL) && !pthread_join(lower, NULL));
    assert(!a.status && !wire); // Controller level and function status agree.
    block_raise = false;
    pci_func_set_intx(&a, true);
    block_lower = true;
    pthread_t mask, unmask;
    assert(!pthread_create(&mask, NULL, mask_thread, &a));
    while (!atomic_load(&mask_entered)) sched_yield();
    assert(!pthread_create(&unmask, NULL, unmask_thread, &a));
    while (!atomic_load(&unmask_started)) sched_yield();
    usleep(10000);
    assert(atomic_load_uint32_relax(&a.command) & PCI_CMD_INTX_OFF);
    release_lower = true;
    assert(!pthread_join(mask, NULL) && !pthread_join(unmask, NULL));
    assert(!(a.command & PCI_CMD_INTX_OFF) && wire);
    puts("PASS PCI shared INTx aggregation and concurrent level-update serialization");
}
