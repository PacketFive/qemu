// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PDP-V pdpv-virt reset, power, and hart-start controller.
 * Copyright (C) 2026 QEMU authors.
 * Contributed by Weqaar Janjua.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "system/runstate.h"

#define TYPE_PDP12_PLATFORM_CONTROL "pdp12-platform-control"
#define PDP12_PLATFORM_CONTROL(obj) \
    OBJECT_CHECK(PDP12PlatformControlState, (obj), \
                 TYPE_PDP12_PLATFORM_CONTROL)

#define PDP12_PLATFORM_CONTROL_SIZE 0x1000
#define CONTROL_COLD_RESET          0x000
#define CONTROL_POWER_OFF           0x004
#define HART_CAPABILITY             0x100
#define HART_PRESENT                0x108
#define HART_RUNNING                0x110
#define HART_ERROR                  0x118
#define HART_ENTRY_BASE             0x200
#define HART_START_BASE             0x400
#define HART_ARGUMENT_BASE          0x600
#define HART_REGISTER_COUNT         64
#define COLD_RESET_MAGIC            0x5555
#define POWER_OFF_MAGIC             0x3333

typedef struct PDP12PlatformControlState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    uint64_t hart_error;
    uint64_t hart_entry;
    uint64_t hart_argument;
} PDP12PlatformControlState;

static bool hart_register(hwaddr offset, hwaddr base, unsigned int *hart)
{
    if (offset < base ||
        offset >= base + HART_REGISTER_COUNT * sizeof(uint64_t) ||
        (offset - base) % sizeof(uint64_t) != 0) {
        return false;
    }
    *hart = (offset - base) / sizeof(uint64_t);
    return true;
}

static MemTxResult pdp12_platform_control_read(void *opaque, hwaddr offset,
                                               uint64_t *value,
                                               unsigned size,
                                               MemTxAttrs attrs)
{
    PDP12PlatformControlState *s = PDP12_PLATFORM_CONTROL(opaque);
    unsigned int hart;

    if (attrs.user) {
        return MEMTX_ERROR;
    }
    if (size == 4 && (offset == CONTROL_COLD_RESET ||
                      offset == CONTROL_POWER_OFF)) {
        *value = 0;
        return MEMTX_OK;
    }
    if (size != 8) {
        return MEMTX_ERROR;
    }
    switch (offset) {
    case HART_CAPABILITY:
        *value = 1ULL << 8;
        return MEMTX_OK;
    case HART_PRESENT:
    case HART_RUNNING:
        *value = 1;
        return MEMTX_OK;
    case HART_ERROR:
        *value = s->hart_error;
        return MEMTX_OK;
    }
    if (hart_register(offset, HART_ENTRY_BASE, &hart)) {
        *value = hart == 0 ? s->hart_entry : 0;
        return MEMTX_OK;
    }
    if (hart_register(offset, HART_ARGUMENT_BASE, &hart)) {
        *value = hart == 0 ? s->hart_argument : 0;
        return MEMTX_OK;
    }
    if (hart_register(offset, HART_START_BASE, &hart)) {
        *value = 0;
        return MEMTX_OK;
    }
    return MEMTX_ERROR;
}

static MemTxResult pdp12_platform_control_write(void *opaque, hwaddr offset,
                                                uint64_t value,
                                                unsigned size,
                                                MemTxAttrs attrs)
{
    PDP12PlatformControlState *s = PDP12_PLATFORM_CONTROL(opaque);
    unsigned int hart;

    if (attrs.user) {
        return MEMTX_ERROR;
    }
    if (size == 4) {
        if (offset == CONTROL_COLD_RESET) {
            if (value == COLD_RESET_MAGIC) {
                qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            }
            return MEMTX_OK;
        }
        if (offset == CONTROL_POWER_OFF) {
            if (value == POWER_OFF_MAGIC) {
                qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
            }
            return MEMTX_OK;
        }
        return MEMTX_ERROR;
    }
    if (size != 8) {
        return MEMTX_ERROR;
    }
    if (offset == HART_ERROR) {
        s->hart_error &= ~value;
        return MEMTX_OK;
    }
    if (hart_register(offset, HART_ENTRY_BASE, &hart)) {
        return MEMTX_OK;
    }
    if (hart_register(offset, HART_ARGUMENT_BASE, &hart)) {
        return MEMTX_OK;
    }
    if (hart_register(offset, HART_START_BASE, &hart)) {
        if (value & 1) {
            s->hart_error |= 1ULL << hart;
        }
        return MEMTX_OK;
    }
    qemu_log_mask(LOG_GUEST_ERROR,
                  "pdp12-platform-control: invalid write at offset 0x%"
                  HWADDR_PRIx "\n", offset);
    return MEMTX_ERROR;
}

static const MemoryRegionOps pdp12_platform_control_ops = {
    .read_with_attrs = pdp12_platform_control_read,
    .write_with_attrs = pdp12_platform_control_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
        .unaligned = false,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static void pdp12_platform_control_reset(DeviceState *dev)
{
    PDP12PlatformControlState *s = PDP12_PLATFORM_CONTROL(dev);

    s->hart_error = 0;
    s->hart_entry = 0;
    s->hart_argument = 0;
}

static void pdp12_platform_control_realize(DeviceState *dev, Error **errp)
{
    PDP12PlatformControlState *s = PDP12_PLATFORM_CONTROL(dev);

    memory_region_init_io(&s->mmio, OBJECT(s), &pdp12_platform_control_ops, s,
                          TYPE_PDP12_PLATFORM_CONTROL,
                          PDP12_PLATFORM_CONTROL_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void pdp12_platform_control_class_init(ObjectClass *klass,
                                              const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "PDP-V pdpv-virt reset, power, and hart-start controller";
    dc->realize = pdp12_platform_control_realize;
    device_class_set_legacy_reset(dc, pdp12_platform_control_reset);
}

static const TypeInfo pdp12_platform_control_info = {
    .name = TYPE_PDP12_PLATFORM_CONTROL,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PDP12PlatformControlState),
    .class_init = pdp12_platform_control_class_init,
};

static void pdp12_platform_control_register_types(void)
{
    type_register_static(&pdp12_platform_control_info);
}

type_init(pdp12_platform_control_register_types)
