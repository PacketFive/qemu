// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PDP-V pdpv-virt timer and inter-processor interrupt block.
 * Copyright (C) 2026 QEMU authors.
 * Contributed by Weqaar Janjua.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/qdev-properties.h"
#include "system/system.h"
#include "target/pdp12/cpu.h"

#define TYPE_PDP12_TIMER "pdp12-timer"
#define PDP12_TIMER(obj) \
    OBJECT_CHECK(PDP12TimerState, (obj), TYPE_PDP12_TIMER)

/*
 * pdpv-virt v0.1 Section 5. The canonical architectural interface is the
 * PDP-V-P0 time and timecmp CSR pair; this page exposes the same underlying
 * state for firmware and for cross-hart software interrupts.
 *
 *   0x000            64  read-only   TIME
 *   0x008 + 0x10*h   64  read/write  TIMECMP[h]
 *   0x010 + 0x10*h   64  read/write  SOFTIRQ[h] bit 0
 *
 * Only naturally aligned 64-bit accesses are accepted; any other width is
 * rejected by the region's access validation and reported to the guest as an
 * access fault.
 */
#define PDP12_TIMER_TIME        0x000
#define PDP12_TIMER_TIMECMP     0x008
#define PDP12_TIMER_SOFTIRQ     0x010
#define PDP12_TIMER_HART_STRIDE 0x10
#define PDP12_TIMER_SIZE        0x1000

typedef struct PDP12TimerState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    PDP12CPU *cpu;
} PDP12TimerState;

static CPUPDP12State *pdp12_timer_env(PDP12TimerState *s, hwaddr offset,
                                      hwaddr base)
{
    if (offset < base || offset - base >= PDP12_TIMER_HART_STRIDE ||
        (offset - base) != 0) {
        return NULL;
    }
    return s->cpu ? &s->cpu->env : NULL;
}

static uint64_t pdp12_timer_read(void *opaque, hwaddr offset, unsigned size)
{
    PDP12TimerState *s = opaque;
    CPUPDP12State *env;

    if (offset == PDP12_TIMER_TIME) {
        /*
         * The same 10 MHz virtual-time counter the time CSR reports, so
         * firmware polling this page and software reading the CSR observe
         * one coherent timebase.
         */
        return s->cpu ? pdp12_cpu_read_time(&s->cpu->env) : 0;
    }
    env = pdp12_timer_env(s, offset, PDP12_TIMER_TIMECMP);
    if (env) {
        return env->timecmp;
    }
    env = pdp12_timer_env(s, offset, PDP12_TIMER_SOFTIRQ);
    if (env) {
        return (env->irq_pending >> PDP12_IRQ_SOFTWARE) & 1;
    }
    return 0;
}

static void pdp12_timer_write(void *opaque, hwaddr offset, uint64_t value,
                              unsigned size)
{
    PDP12TimerState *s = opaque;
    CPUPDP12State *env;

    env = pdp12_timer_env(s, offset, PDP12_TIMER_TIMECMP);
    if (env) {
        pdp12_cpu_set_timecmp(env, value);
        return;
    }
    env = pdp12_timer_env(s, offset, PDP12_TIMER_SOFTIRQ);
    if (env) {
        pdp12_cpu_set_software_interrupt(env, (value & 1) != 0);
        return;
    }
    /* TIME is read-only; writes are ignored. */
}

static const MemoryRegionOps pdp12_timer_ops = {
    .read = pdp12_timer_read,
    .write = pdp12_timer_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 8,
        .max_access_size = 8,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 8,
        .max_access_size = 8,
    },
};

static void pdp12_timer_realize(DeviceState *dev, Error **errp)
{
    PDP12TimerState *s = PDP12_TIMER(dev);
    CPUState *cs = qemu_get_cpu(0);

    if (cs == NULL) {
        error_setg(errp, "pdp12-timer requires hart 0");
        return;
    }
    s->cpu = PDP12_CPU(cs);
}

static void pdp12_timer_init(Object *obj)
{
    PDP12TimerState *s = PDP12_TIMER(obj);

    memory_region_init_io(&s->iomem, obj, &pdp12_timer_ops, s,
                          TYPE_PDP12_TIMER, PDP12_TIMER_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->iomem);
}

static void pdp12_timer_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "PDP-V pdpv-virt timer and IPI block";
    dc->realize = pdp12_timer_realize;
}

static const TypeInfo pdp12_timer_type_info = {
    .name = TYPE_PDP12_TIMER,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PDP12TimerState),
    .instance_init = pdp12_timer_init,
    .class_init = pdp12_timer_class_init,
};

static void pdp12_timer_register_types(void)
{
    type_register_static(&pdp12_timer_type_info);
}

type_init(pdp12_timer_register_types)
