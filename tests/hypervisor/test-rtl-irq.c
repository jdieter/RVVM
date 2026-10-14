#include <assert.h>
#include <stdio.h>
#define USE_NET 1
#define rvvm_pci_set_irq rtl_test_irq
#include <devices/rtl8169.c>
#undef rvvm_pci_set_irq

static rtl8169_dev_t* model;
static bool wire, inject_set, inject_clear;

void rtl_test_irq(rvvm_pci_func_t* function, uint32_t vector, bool level)
{
    (void)function;
    (void)vector;
    if (!level && inject_set) {
        inject_set = false;
        rtl8169_interrupt(model, RTL8169_IRQ_ROK);
    } else if (level && inject_clear) {
        inject_clear = false;
        model->isr = 0;
        rtl8169_update_irqs(model);
    }
    wire = level;
}

int main(void)
{
    rtl8169_dev_t device = { .imr = 1U << RTL8169_IRQ_ROK };
    model = &device;
    inject_set = true;
    rtl8169_update_irqs(model);
    assert(wire); // Packet arrived after the interrupt handler's empty check.
    inject_clear = true;
    rtl8169_interrupt(model, RTL8169_IRQ_ROK);
    assert(!wire); // A late producer cannot assert an already acknowledged IRQ.
    device.isr = device.imr = 1U << RTL8169_IRQ_ROK;
    rtl8169_update_irqs(model);
    assert(wire);
    device.imr = 0;
    rtl8169_update_irqs(model);
    assert(!wire);
    puts("PASS RTL8169 receive/ack IRQ races and masking");
}
