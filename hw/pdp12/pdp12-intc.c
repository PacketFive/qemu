// SPDX-License-Identifier: GPL-2.0-or-later
/* QEMU PDP-12 Platform Level Interrupt Controller (PLIC).
   Copyright (C) 2026 QEMU authors.
   Contributed by Weqaar Janjua. */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "qemu/log.h"

#define TYPE_PDP12_INTC "pdp12-intc"
#define PDP12_INTC(obj) OBJECT_CHECK(PDP12INTCState, (obj), TYPE_PDP12_INTC)

typedef struct PDP12INTCState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    uint32_t pending;
    uint32_t enable;
    qemu_irq parent_irq;
} PDP12INTCState;

static void pdp12_intc_set_irq(void *opaque, int irq, int level)
{
    PDP12INTCState *s = PDP12_INTC(opaque);
    if (level) {
        s->pending |= (1 << irq);
    } else {
        s->pending &= ~(1 << irq);
    }
    
    /* Forward interrupt to CPU if enabled */
    qemu_set_irq(s->parent_irq, !!(s->pending & s->enable));
}

static void pdp12_intc_realize(DeviceState *dev, Error **errp)
{
    PDP12INTCState *s = PDP12_INTC(dev);
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->parent_irq);
    qdev_init_gpio_in(dev, pdp12_intc_set_irq, 32);
}

static void pdp12_intc_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = pdp12_intc_realize;
}

static const TypeInfo pdp12_intc_info = {
    .name          = TYPE_PDP12_INTC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PDP12INTCState),
    .class_init    = pdp12_intc_class_init,
};

static void pdp12_intc_register_types(void)
{
    type_register_static(&pdp12_intc_info);
}

type_init(pdp12_intc_register_types)
