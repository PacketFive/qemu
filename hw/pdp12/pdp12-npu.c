// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QEMU PDP-12 Neural Processing Unit (NPU) Mock Stub.
 * Copyright (C) 2026 QEMU authors.
 * Contributed by Weqaar Janjua.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "qemu/log.h"

#define TYPE_PDP12_NPU "pdp12-npu"
#define PDP12_NPU(obj) OBJECT_CHECK(PDP12NPUState, (obj), TYPE_PDP12_NPU)

typedef struct PDP12NPUState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    uint32_t status;
    uint32_t doorbell;
    qemu_irq irq;
} PDP12NPUState;

static void pdp12_npu_write(void *opaque, hwaddr offset, uint64_t val,
                            unsigned size)
{
    PDP12NPUState *s = PDP12_NPU(opaque);
    switch (offset) {
    case 0x00: /* NPU_DOORBELL */
        s->doorbell = val;
        if (val > 0) {
            s->status |= 1; /* set busy */
            s->status &= ~1; /* immediately clear busy */
        }
        /*
         * The platform wires this as a level-high XIC source.  A zero
         * doorbell is therefore also the device acknowledgement and
         * deasserts the source before XIC completion.
         */
        qemu_set_irq(s->irq, val > 0);
        break;
    default:
        break;
    }
}

static uint64_t pdp12_npu_read(void *opaque, hwaddr offset, unsigned size)
{
    PDP12NPUState *s = PDP12_NPU(opaque);
    switch (offset) {
    case 0x00:
        return s->doorbell;
    case 0x04:
        return s->status;
    default:
        return 0;
    }
}

static const MemoryRegionOps pdp12_npu_ops = {
    .read = pdp12_npu_read,
    .write = pdp12_npu_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void pdp12_npu_reset(DeviceState *dev)
{
    PDP12NPUState *s = PDP12_NPU(dev);

    s->status = 0;
    s->doorbell = 0;
    qemu_set_irq(s->irq, 0);
}

static void pdp12_npu_realize(DeviceState *dev, Error **errp)
{
    PDP12NPUState *s = PDP12_NPU(dev);
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq);
    memory_region_init_io(&s->mmio, OBJECT(s), &pdp12_npu_ops, s,
                          "pdp12.npu", 0x1000);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void pdp12_npu_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = pdp12_npu_realize;
    device_class_set_legacy_reset(dc, pdp12_npu_reset);
}

static const TypeInfo pdp12_npu_info = {
    .name          = TYPE_PDP12_NPU,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PDP12NPUState),
    .class_init    = pdp12_npu_class_init,
};

static void pdp12_npu_register_types(void)
{
    type_register_static(&pdp12_npu_info);
}

type_init(pdp12_npu_register_types)
