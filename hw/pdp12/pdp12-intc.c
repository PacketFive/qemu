// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PDP-V pdpv-virt External Interrupt Controller (XIC) v1.
 * Copyright (C) 2026 QEMU authors.
 * Contributed by Weqaar Janjua.
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/sysbus.h"
#include "qemu/log.h"

#define TYPE_PDP12_INTC "pdp12-intc"
#define PDP12_INTC(obj) OBJECT_CHECK(PDP12INTCState, (obj), TYPE_PDP12_INTC)

#define PDP12_XIC_MAX_SOURCE       255
#define PDP12_XIC_SOURCE_COUNT     (PDP12_XIC_MAX_SOURCE + 1)
#define PDP12_XIC_BITMAP_WORDS     4
#define PDP12_XIC_MAX_PRIORITY     7
#define PDP12_XIC_CONTEXT_COUNT    1
#define PDP12_XIC_SIZE             0x100000

#define XIC_CAPABILITY             0x0000
#define XIC_GLOBAL_ERROR           0x0008
#define XIC_SOURCE_CONFIG_BASE     0x1000
#define XIC_PENDING_BASE           0x2000
#define XIC_IN_FLIGHT_BASE         0x2040
#define XIC_ASSERTED_BASE          0x2080
#define XIC_CONTEXT_BASE           0x40000
#define XIC_CONTEXT_STRIDE         0x1000
#define XIC_ENABLE_BASE            0x000
#define XIC_THRESHOLD              0x020
#define XIC_CLAIM_COMPLETE         0x028
#define XIC_ACTIVE                 0x030
#define XIC_CONTEXT_ERROR          0x038

#define XIC_TRIGGER_LEVEL_HIGH     0
#define XIC_TRIGGER_RISING_EDGE    1

typedef struct PDP12INTCState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    uint8_t priority[PDP12_XIC_SOURCE_COUNT];
    uint8_t trigger[PDP12_XIC_SOURCE_COUNT];
    uint64_t asserted[PDP12_XIC_BITMAP_WORDS];
    uint64_t pending[PDP12_XIC_BITMAP_WORDS];
    uint64_t in_flight[PDP12_XIC_BITMAP_WORDS];
    uint64_t edge_latched[PDP12_XIC_BITMAP_WORDS];
    uint64_t enable[PDP12_XIC_BITMAP_WORDS];
    uint8_t threshold;
    uint16_t active;
    bool global_error;
    bool context_error;
    qemu_irq parent_irq;
} PDP12INTCState;

static unsigned int xic_word(unsigned int source)
{
    return source / 64;
}

static uint64_t xic_mask(unsigned int source)
{
    return 1ULL << (source % 64);
}

static bool xic_bitmap_test(const uint64_t *bitmap, unsigned int source)
{
    return (bitmap[xic_word(source)] & xic_mask(source)) != 0;
}

static void xic_bitmap_set(uint64_t *bitmap, unsigned int source, bool value)
{
    if (value) {
        bitmap[xic_word(source)] |= xic_mask(source);
    } else {
        bitmap[xic_word(source)] &= ~xic_mask(source);
    }
}

/*
 * XIC v1 selects by descending priority and then ascending source number.
 * Iterating sources in ascending order means an equal-priority source never
 * replaces the current selection.
 */
static unsigned int xic_select(PDP12INTCState *s)
{
    unsigned int selected = 0;
    unsigned int selected_priority = 0;
    unsigned int source;

    if (s->active != 0) {
        return 0;
    }
    for (source = 1; source <= PDP12_XIC_MAX_SOURCE; source++) {
        unsigned int priority = s->priority[source];

        if (!xic_bitmap_test(s->pending, source) ||
            xic_bitmap_test(s->in_flight, source) ||
            !xic_bitmap_test(s->enable, source) ||
            priority <= s->threshold) {
            continue;
        }
        if (priority > selected_priority) {
            selected = source;
            selected_priority = priority;
        }
    }
    return selected;
}

static void xic_update(PDP12INTCState *s)
{
    qemu_set_irq(s->parent_irq, xic_select(s) != 0);
}

static void pdp12_xic_set_irq(void *opaque, int irq, int level)
{
    PDP12INTCState *s = PDP12_INTC(opaque);
    bool asserted;
    bool rising;

    if (irq <= 0 || irq > PDP12_XIC_MAX_SOURCE) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "pdp12-xic: invalid input source %d\n", irq);
        return;
    }

    asserted = xic_bitmap_test(s->asserted, irq);
    rising = !asserted && level;
    xic_bitmap_set(s->asserted, irq, level);

    if (s->trigger[irq] == XIC_TRIGGER_LEVEL_HIGH) {
        if (!xic_bitmap_test(s->in_flight, irq)) {
            xic_bitmap_set(s->pending, irq, level);
        }
    } else if (rising) {
        if (xic_bitmap_test(s->in_flight, irq)) {
            xic_bitmap_set(s->edge_latched, irq, true);
        } else {
            xic_bitmap_set(s->pending, irq, true);
        }
    }
    xic_update(s);
}

static uint64_t xic_capability(void)
{
    return 1ULL |
           ((uint64_t)PDP12_XIC_MAX_PRIORITY << 8) |
           ((uint64_t)PDP12_XIC_MAX_SOURCE << 16) |
           ((uint64_t)PDP12_XIC_CONTEXT_COUNT << 32);
}

static bool xic_bitmap_offset(hwaddr offset, hwaddr base,
                              unsigned int *word)
{
    if (offset < base ||
        offset >= base + PDP12_XIC_BITMAP_WORDS * sizeof(uint64_t)) {
        return false;
    }
    *word = (offset - base) / sizeof(uint64_t);
    return true;
}

static unsigned int xic_claim(PDP12INTCState *s)
{
    unsigned int source = xic_select(s);

    if (source != 0) {
        xic_bitmap_set(s->pending, source, false);
        xic_bitmap_set(s->in_flight, source, true);
        s->active = source;
        xic_update(s);
    }
    return source;
}

static void xic_complete(PDP12INTCState *s, uint64_t value)
{
    unsigned int source;

    if (value == 0 || value > PDP12_XIC_MAX_SOURCE ||
        s->active != value) {
        s->context_error = true;
        return;
    }

    source = value;
    xic_bitmap_set(s->in_flight, source, false);
    s->active = 0;
    if (s->trigger[source] == XIC_TRIGGER_LEVEL_HIGH) {
        if (xic_bitmap_test(s->asserted, source)) {
            xic_bitmap_set(s->pending, source, true);
        }
    } else if (xic_bitmap_test(s->edge_latched, source)) {
        xic_bitmap_set(s->pending, source, true);
        xic_bitmap_set(s->edge_latched, source, false);
    }
    xic_update(s);
}

static MemTxResult pdp12_xic_read(void *opaque, hwaddr offset,
                                  uint64_t *value, unsigned size,
                                  MemTxAttrs attrs)
{
    PDP12INTCState *s = PDP12_INTC(opaque);
    unsigned int source;
    unsigned int word;
    hwaddr context_offset;

    switch (offset) {
    case XIC_CAPABILITY:
        *value = xic_capability();
        return MEMTX_OK;
    case XIC_GLOBAL_ERROR:
        *value = s->global_error;
        return MEMTX_OK;
    }

    if (offset >= XIC_SOURCE_CONFIG_BASE && offset < XIC_PENDING_BASE) {
        source = (offset - XIC_SOURCE_CONFIG_BASE) / sizeof(uint64_t);
        if (source >= 1 && source <= PDP12_XIC_MAX_SOURCE) {
            *value = s->priority[source] |
                     ((uint64_t)s->trigger[source] << 3);
            return MEMTX_OK;
        }
        goto invalid;
    }
    if (xic_bitmap_offset(offset, XIC_PENDING_BASE, &word)) {
        *value = s->pending[word];
        return MEMTX_OK;
    }
    if (xic_bitmap_offset(offset, XIC_IN_FLIGHT_BASE, &word)) {
        *value = s->in_flight[word];
        return MEMTX_OK;
    }
    if (xic_bitmap_offset(offset, XIC_ASSERTED_BASE, &word)) {
        *value = s->asserted[word];
        return MEMTX_OK;
    }

    if (offset >= XIC_CONTEXT_BASE &&
        offset < XIC_CONTEXT_BASE + XIC_CONTEXT_STRIDE) {
        context_offset = offset - XIC_CONTEXT_BASE;
        if (xic_bitmap_offset(context_offset, XIC_ENABLE_BASE, &word)) {
            *value = s->enable[word];
            return MEMTX_OK;
        }
        switch (context_offset) {
        case XIC_THRESHOLD:
            *value = s->threshold;
            return MEMTX_OK;
        case XIC_CLAIM_COMPLETE:
            *value = xic_claim(s);
            return MEMTX_OK;
        case XIC_ACTIVE:
            *value = s->active;
            return MEMTX_OK;
        case XIC_CONTEXT_ERROR:
            *value = s->context_error;
            return MEMTX_OK;
        }
    }

invalid:
    qemu_log_mask(LOG_GUEST_ERROR,
                  "pdp12-xic: invalid read at offset 0x%" HWADDR_PRIx "\n",
                  offset);
    *value = 0;
    return MEMTX_ERROR;
}

static bool xic_configure_source(PDP12INTCState *s, unsigned int source,
                                 uint64_t value)
{
    unsigned int priority = value & 7;
    unsigned int trigger = (value >> 3) & 3;
    bool trigger_change_blocked;

    if (source < 1 || source > PDP12_XIC_MAX_SOURCE ||
        (value & ~0x1fULL) != 0 || trigger > XIC_TRIGGER_RISING_EDGE) {
        return false;
    }

    trigger_change_blocked =
        trigger != s->trigger[source] &&
        (s->priority[source] != 0 ||
         xic_bitmap_test(s->pending, source) ||
         xic_bitmap_test(s->in_flight, source));
    if (trigger_change_blocked) {
        return false;
    }

    s->priority[source] = priority;
    s->trigger[source] = trigger;
    return true;
}

static MemTxResult pdp12_xic_write(void *opaque, hwaddr offset,
                                   uint64_t value, unsigned size,
                                   MemTxAttrs attrs)
{
    PDP12INTCState *s = PDP12_INTC(opaque);
    unsigned int source;
    unsigned int word;
    hwaddr context_offset;

    if (offset == XIC_GLOBAL_ERROR) {
        if (value & 1) {
            s->global_error = false;
        }
        return MEMTX_OK;
    }

    if (offset >= XIC_SOURCE_CONFIG_BASE && offset < XIC_PENDING_BASE) {
        source = (offset - XIC_SOURCE_CONFIG_BASE) / sizeof(uint64_t);
        if (!xic_configure_source(s, source, value)) {
            s->global_error = true;
        } else {
            xic_update(s);
        }
        return MEMTX_OK;
    }

    if (offset >= XIC_CONTEXT_BASE &&
        offset < XIC_CONTEXT_BASE + XIC_CONTEXT_STRIDE) {
        context_offset = offset - XIC_CONTEXT_BASE;
        if (xic_bitmap_offset(context_offset, XIC_ENABLE_BASE, &word)) {
            s->enable[word] = value;
            s->enable[0] &= ~1ULL;
            xic_update(s);
            return MEMTX_OK;
        }
        switch (context_offset) {
        case XIC_THRESHOLD:
            if (value <= PDP12_XIC_MAX_PRIORITY) {
                s->threshold = value;
                xic_update(s);
            } else {
                s->context_error = true;
            }
            return MEMTX_OK;
        case XIC_CLAIM_COMPLETE:
            xic_complete(s, value);
            return MEMTX_OK;
        case XIC_CONTEXT_ERROR:
            if (value & 1) {
                s->context_error = false;
            }
            return MEMTX_OK;
        }
    }

    qemu_log_mask(LOG_GUEST_ERROR,
                  "pdp12-xic: invalid write at offset 0x%" HWADDR_PRIx "\n",
                  offset);
    return MEMTX_ERROR;
}

static const MemoryRegionOps pdp12_xic_ops = {
    .read_with_attrs = pdp12_xic_read,
    .write_with_attrs = pdp12_xic_write,
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

static void pdp12_xic_reset(DeviceState *dev)
{
    PDP12INTCState *s = PDP12_INTC(dev);

    memset(s->priority, 0, sizeof(s->priority));
    memset(s->trigger, 0, sizeof(s->trigger));
    memset(s->asserted, 0, sizeof(s->asserted));
    memset(s->pending, 0, sizeof(s->pending));
    memset(s->in_flight, 0, sizeof(s->in_flight));
    memset(s->edge_latched, 0, sizeof(s->edge_latched));
    memset(s->enable, 0, sizeof(s->enable));
    s->threshold = 0;
    s->active = 0;
    s->global_error = false;
    s->context_error = false;
    xic_update(s);
}

static void pdp12_xic_realize(DeviceState *dev, Error **errp)
{
    PDP12INTCState *s = PDP12_INTC(dev);

    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->parent_irq);
    qdev_init_gpio_in(dev, pdp12_xic_set_irq, PDP12_XIC_SOURCE_COUNT);
    memory_region_init_io(&s->mmio, OBJECT(s), &pdp12_xic_ops, s,
                          TYPE_PDP12_INTC, PDP12_XIC_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->mmio);
}

static void pdp12_xic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "PDP-V pdpv-virt External Interrupt Controller v1";
    dc->realize = pdp12_xic_realize;
    device_class_set_legacy_reset(dc, pdp12_xic_reset);
}

static const TypeInfo pdp12_xic_info = {
    .name = TYPE_PDP12_INTC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(PDP12INTCState),
    .class_init = pdp12_xic_class_init,
};

static void pdp12_xic_register_types(void)
{
    type_register_static(&pdp12_xic_info);
}

type_init(pdp12_xic_register_types)
