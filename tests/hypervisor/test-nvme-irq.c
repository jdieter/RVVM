/* Model a completion arriving between the empty check and INTx deassertion. */
#include <assert.h>
#include <stdio.h>
#define rvvm_pci_set_irq nvme_test_irq
#include <devices/nvme.c>
#undef rvvm_pci_set_irq

static nvme_dev_t* model;
static bool level, inject, inject_ack;

void nvme_test_irq(rvvm_pci_func_t* func, uint32_t vector, bool raised)
{
    (void)func;
    (void)vector;
    if (!raised && inject) {
        inject = false;
        model->cq[1].tail++;
        nvme_queue_raise_irq(model, &model->cq[1]);
    }
    if (raised && inject_ack) {
        inject_ack = false;
        model->cq[2].head = model->cq[2].tail;
        nvme_queue_lower_irq(model, &model->cq[2]);
    }
    level = raised; // PCI INTx is shared even when CQs have different vectors.
}

int main(void)
{
    nvme_dev_t controller = {0};
    model = &controller;
    controller.cq[1].data = NVME_CQ_FLAGS_IEN;
    inject = true;
    nvme_queue_lower_irq(model, &model->cq[1]);
    assert(level); // A concurrent completion must remain visible to the driver.
    controller.cq[1].head = controller.cq[1].tail;
    nvme_queue_lower_irq(model, &model->cq[1]);
    assert(!level);
    controller.cq[2].data = NVME_CQ_FLAGS_IEN | (1U << 16);
    controller.cq[2].tail = 1;
    nvme_queue_raise_irq(model, &model->cq[2]);
    nvme_queue_lower_irq(model, &model->cq[1]);
    assert(level); // A different CQ still holds the legacy line asserted.
    controller.irq_mask = 1U << 1;
    nvme_check_masked_irqs(model, 1U << 1);
    assert(!level);
    controller.irq_mask = 0;
    nvme_check_masked_irqs(model, 1U << 1);
    assert(level);
    inject_ack = true;
    nvme_queue_raise_irq(model, &model->cq[2]);
    assert(!level); // A stale producer must not assert after the final ack.
    controller.cq[2].tail++;
    nvme_queue_raise_irq(model, &model->cq[2]);
    assert(level);
    nvme_reset(model);
    assert(!level);
    puts("PASS NVMe concurrent completion and shared INTx pending-state preservation");
}
