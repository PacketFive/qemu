/*
 * HiCAIN HiGPU - Virtual GPU PCIe device for QEMU.
 *
 * Phase 1 scaffold: PCI identifiers, BAR0 (control MMIO), BAR1 (device
 * memory window), MSI. No compute, no command processor yet.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/core/qdev-properties.h"
#include "qom/object.h"

#define TYPE_HICAIN_HIGPU "higpu"
typedef struct HigpuState HigpuState;
DECLARE_INSTANCE_CHECKER(HigpuState, HIGPU, TYPE_HICAIN_HIGPU)

#define HICAIN_VENDOR_ID    0x1ED5
#define HIGPU_DEVICE_ID     0xCA20

#define HIGPU_BAR0_SIZE     (64 * KiB)
#define HIGPU_BAR1_SIZE_DEFAULT  (8ULL * GiB)

#define REG_VENDOR_ID       0x000
#define REG_DEVICE_ID       0x004
#define REG_REVISION        0x008
#define REG_FW_VERSION      0x00C
#define REG_GPU_ID          0x010
#define REG_SM_COUNT        0x014
#define REG_LANES_PER_SM    0x018
#define REG_TENSOR_SIZE     0x01C
#define REG_DEVMEM_SIZE_LO  0x020
#define REG_DEVMEM_SIZE_HI  0x024
#define REG_IRQ_STATUS      0x100
#define REG_IRQ_MASK        0x104

#define HIGPU_FW_VERSION    0x00010000   /* 0.1.0 */
#define HIGPU_REVISION      0x01

struct HigpuState {
    PCIDevice pdev;
    MemoryRegion bar0;
    MemoryRegion bar1;

    uint32_t gpu_id;
    uint32_t sm_count;
    uint32_t lanes_per_sm;
    uint32_t tensor_size;
    uint64_t devmem_size;

    void *devmem;

    uint32_t irq_status;
    uint32_t irq_mask;
};

static void higpu_update_irq(HigpuState *s)
{
    uint32_t pending = s->irq_status & s->irq_mask;

    if (msi_enabled(&s->pdev)) {
        if (pending) {
            msi_notify(&s->pdev, 0);
        }
    } else {
        pci_set_irq(&s->pdev, !!pending);
    }
}

static uint64_t higpu_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    HigpuState *s = opaque;

    switch (addr) {
    case REG_VENDOR_ID:
        return HICAIN_VENDOR_ID;
    case REG_DEVICE_ID:
        return HIGPU_DEVICE_ID;
    case REG_REVISION:
        return HIGPU_REVISION;
    case REG_FW_VERSION:
        return HIGPU_FW_VERSION;
    case REG_GPU_ID:
        return s->gpu_id;
    case REG_SM_COUNT:
        return s->sm_count;
    case REG_LANES_PER_SM:
        return s->lanes_per_sm;
    case REG_TENSOR_SIZE:
        return s->tensor_size;
    case REG_DEVMEM_SIZE_LO:
        return (uint32_t)s->devmem_size;
    case REG_DEVMEM_SIZE_HI:
        return (uint32_t)(s->devmem_size >> 32);
    case REG_IRQ_STATUS:
        return s->irq_status;
    case REG_IRQ_MASK:
        return s->irq_mask;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu: read from unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        return 0;
    }
}

static void higpu_bar0_write(void *opaque, hwaddr addr,
                             uint64_t val, unsigned size)
{
    HigpuState *s = opaque;

    switch (addr) {
    case REG_IRQ_STATUS:
        s->irq_status &= ~val;
        higpu_update_irq(s);
        break;
    case REG_IRQ_MASK:
        s->irq_mask = val;
        higpu_update_irq(s);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu: write to unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        break;
    }
}

static const MemoryRegionOps higpu_bar0_ops = {
    .read = higpu_bar0_read,
    .write = higpu_bar0_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void higpu_realize(PCIDevice *pdev, Error **errp)
{
    HigpuState *s = HIGPU(pdev);

    pci_config_set_interrupt_pin(pdev->config, 1);
    msi_init(pdev, 0, 1, true, false, errp);

    memory_region_init_io(&s->bar0, OBJECT(s), &higpu_bar0_ops, s,
                          "higpu-bar0", HIGPU_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar0);

    s->devmem = g_malloc0(s->devmem_size);
    memory_region_init_ram_ptr(&s->bar1, OBJECT(s), "higpu-devmem",
                               s->devmem_size, s->devmem);
    pci_register_bar(pdev, 1,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_64 |
                         PCI_BASE_ADDRESS_MEM_PREFETCH,
                     &s->bar1);

    s->irq_status = 0;
    s->irq_mask = 0;
}

static void higpu_exit(PCIDevice *pdev)
{
    HigpuState *s = HIGPU(pdev);

    msi_uninit(pdev);
    g_free(s->devmem);
    s->devmem = NULL;
}

static const Property higpu_properties[] = {
    DEFINE_PROP_UINT32("gpu_id", HigpuState, gpu_id, 0),
    DEFINE_PROP_UINT32("sm_count", HigpuState, sm_count, 16),
    DEFINE_PROP_UINT32("lanes_per_sm", HigpuState, lanes_per_sm, 32),
    DEFINE_PROP_UINT32("tensor_size", HigpuState, tensor_size, 16),
    DEFINE_PROP_UINT64("devmem_size", HigpuState, devmem_size,
                       HIGPU_BAR1_SIZE_DEFAULT),
};

static void higpu_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = higpu_realize;
    k->exit = higpu_exit;
    k->vendor_id = HICAIN_VENDOR_ID;
    k->device_id = HIGPU_DEVICE_ID;
    k->class_id = PCI_CLASS_PROCESSOR_CO;
    k->revision = HIGPU_REVISION;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "HiCAIN HiGPU (virtual GPU)";
    device_class_set_props(dc, higpu_properties);
}

static const TypeInfo higpu_info = {
    .name          = TYPE_HICAIN_HIGPU,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(HigpuState),
    .class_init    = higpu_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void higpu_register_types(void)
{
    type_register_static(&higpu_info);
}

type_init(higpu_register_types)
