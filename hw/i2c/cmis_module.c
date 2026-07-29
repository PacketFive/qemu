/*
 * CMIS optical module (QSFP-DD / OSFP) I2C management interface.
 *
 * Models the management controller inside a pluggable optical transceiver as
 * seen from a switch BMC: an I2C target at 0x50 exposing the Common
 * Management Interface Specification memory map. The BMC reads module
 * identity from it and polls diagnostic monitoring, which is the entire
 * reason a top of rack BMC has an I2C sideband at all.
 *
 * The memory model is CMIS's, not an EEPROM's. Lower memory, bytes 0 to 127,
 * is always visible; upper memory, bytes 128 to 255, is a window onto one of
 * several pages selected by writing byte 127. That is why an at24c EEPROM
 * cannot stand in for a module: software that selects page 11h to read
 * per-lane optical power would silently read identity bytes instead.
 *
 * Diagnostic values are computed when read rather than stored, so they can be
 * changed on a running machine with qom-set and the next poll sees the new
 * value. That is what makes this useful for testing a BMC's alarm handling:
 * drive the temperature above the threshold on page 02h and watch what the
 * firmware does.
 *
 * Copyright (c) 2025 PacketFive
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/i2c/i2c.h"
#include "hw/core/qdev-properties.h"
#include "migration/vmstate.h"
#include "qom/object.h"

#define TYPE_CMIS_MODULE "cmis-module"
OBJECT_DECLARE_SIMPLE_TYPE(CmisModuleState, CMIS_MODULE)

#define CMIS_PAGE_SIZE      128
#define CMIS_MAX_LANES      8

/* Lower memory. */
#define CMIS_REG_IDENTIFIER     0
#define CMIS_REG_REVISION       1
#define CMIS_REG_MEMORY_MODEL   2
#define CMIS_REG_MODULE_STATE   3
#define CMIS_REG_TEMPERATURE    14  /* int16, 1/256 degree C */
#define CMIS_REG_VOLTAGE        16  /* uint16, 100 uV */
#define CMIS_REG_MEDIA_TYPE     85
#define CMIS_REG_BANK_SELECT    126
#define CMIS_REG_PAGE_SELECT    127

/* Upper page 00h, module identity. Offsets are absolute, as CMIS states them. */
#define CMIS_REG_VENDOR_NAME    129 /* 16 ASCII, space padded */
#define CMIS_REG_VENDOR_OUI     145 /* 3 bytes */
#define CMIS_REG_VENDOR_PN      148 /* 16 ASCII */
#define CMIS_REG_VENDOR_REV     164 /* 2 ASCII */
#define CMIS_REG_VENDOR_SN      166 /* 16 ASCII */
#define CMIS_REG_DATE_CODE      182 /* 8 ASCII */
#define CMIS_REG_PAGE00_CSUM    222 /* sum of bytes 128..221 */

/* Upper page 10h, lane control. */
#define CMIS_REG_TX_DISABLE     130

/* Upper page 11h, lane diagnostics. */
#define CMIS_REG_TX_BIAS        138 /* 8 x uint16, 2 uA */
#define CMIS_REG_TX_POWER       154 /* 8 x uint16, 0.1 uW */
#define CMIS_REG_RX_POWER       170 /* 8 x uint16, 0.1 uW */

/* Upper page 02h, thresholds. */
#define CMIS_REG_TEMP_THRESH    128 /* high alarm, low alarm, high warn, low warn */
#define CMIS_REG_VOLT_THRESH    136

#define CMIS_PAGE_ID_00         0x00
#define CMIS_PAGE_ID_01         0x01
#define CMIS_PAGE_ID_02         0x02
#define CMIS_PAGE_ID_10         0x10
#define CMIS_PAGE_ID_11         0x11

struct CmisModuleState {
    I2CSlave parent_obj;

    /*
     * Static memory. Identity and capability bytes live here; the monitors do
     * not, because they are computed from the properties below on every read.
     */
    uint8_t lower[CMIS_PAGE_SIZE];
    uint8_t page00[CMIS_PAGE_SIZE];
    uint8_t page01[CMIS_PAGE_SIZE];
    uint8_t page02[CMIS_PAGE_SIZE];
    uint8_t page10[CMIS_PAGE_SIZE];
    uint8_t page11[CMIS_PAGE_SIZE];

    /* I2C transaction state. */
    uint8_t pointer;
    bool have_pointer;

    /* Monitored quantities, in units a human can type. */
    int32_t temperature;    /* millidegrees C */
    uint32_t voltage;       /* millivolts */
    uint32_t tx_power;      /* microwatts, per lane */
    uint32_t rx_power;      /* microwatts, per lane */
    uint32_t tx_bias;       /* microamps, per lane */

    char *vendor_name;
    char *vendor_pn;
    char *vendor_sn;
    char *vendor_rev;
    char *date_code;
    uint8_t lanes;
};

static void cmis_put_ascii(uint8_t *page, unsigned offset, const char *s,
                           unsigned len)
{
    unsigned i;

    /*
     * CMIS strings are space padded, not NUL terminated. A NUL terminated
     * field reads back with trailing garbage on most decoders.
     */
    for (i = 0; i < len; i++) {
        page[offset + i] = (s && s[i]) ? (uint8_t)s[i] : ' ';
        if (s && !s[i]) {
            s = NULL;
        }
    }
}

static void cmis_put_be16(uint8_t *page, unsigned offset, uint16_t v)
{
    page[offset] = v >> 8;
    page[offset + 1] = v & 0xff;
}

/* 1/256 of a degree C, two's complement, as CMIS states it. */
static uint16_t cmis_encode_temp(int32_t millicelsius)
{
    int32_t raw = (millicelsius * 256) / 1000;

    if (raw > 32767) {
        raw = 32767;
    } else if (raw < -32768) {
        raw = -32768;
    }
    return (uint16_t)raw;
}

/* 100 uV units. */
static uint16_t cmis_encode_voltage(uint32_t millivolts)
{
    uint32_t raw = millivolts * 10;

    return raw > 0xffff ? 0xffff : (uint16_t)raw;
}

/* 0.1 uW units. Zero is a legitimate reading and means the laser is off. */
static uint16_t cmis_encode_power(uint32_t microwatts)
{
    uint32_t raw = microwatts * 10;

    return raw > 0xffff ? 0xffff : (uint16_t)raw;
}

/* 2 uA units. */
static uint16_t cmis_encode_bias(uint32_t microamps)
{
    uint32_t raw = microamps / 2;

    return raw > 0xffff ? 0xffff : (uint16_t)raw;
}

static bool cmis_lane_enabled(CmisModuleState *s, unsigned lane)
{
    if (lane >= s->lanes) {
        return false;
    }
    /* TxDisable is per lane, one bit each, and is the only control that
     * changes what the diagnostics report. */
    return !(s->page10[CMIS_REG_TX_DISABLE - CMIS_PAGE_SIZE] & (1u << lane));
}

static const uint8_t *cmis_select_page(CmisModuleState *s)
{
    switch (s->lower[CMIS_REG_PAGE_SELECT]) {
    case CMIS_PAGE_ID_00:
        return s->page00;
    case CMIS_PAGE_ID_01:
        return s->page01;
    case CMIS_PAGE_ID_02:
        return s->page02;
    case CMIS_PAGE_ID_10:
        return s->page10;
    case CMIS_PAGE_ID_11:
        return s->page11;
    default:
        /*
         * An unimplemented page reads as zero rather than NACKing. That is
         * what CMIS requires, and it is also what keeps a BMC that walks every
         * page from concluding the module has fallen off the bus.
         */
        return NULL;
    }
}

static uint8_t cmis_read(CmisModuleState *s, uint8_t addr)
{
    unsigned lane;

    if (addr < CMIS_PAGE_SIZE) {
        switch (addr) {
        case CMIS_REG_TEMPERATURE:
        case CMIS_REG_TEMPERATURE + 1:
            return (cmis_encode_temp(s->temperature) >>
                    (addr == CMIS_REG_TEMPERATURE ? 8 : 0)) & 0xff;
        case CMIS_REG_VOLTAGE:
        case CMIS_REG_VOLTAGE + 1:
            return (cmis_encode_voltage(s->voltage) >>
                    (addr == CMIS_REG_VOLTAGE ? 8 : 0)) & 0xff;
        default:
            return s->lower[addr];
        }
    }

    if (s->lower[CMIS_REG_PAGE_SELECT] == CMIS_PAGE_ID_11) {
        if (addr >= CMIS_REG_TX_BIAS && addr < CMIS_REG_TX_BIAS + 16) {
            lane = (addr - CMIS_REG_TX_BIAS) / 2;
            return (cmis_encode_bias(cmis_lane_enabled(s, lane) ?
                                     s->tx_bias : 0) >>
                    ((addr & 1) ? 0 : 8)) & 0xff;
        }
        if (addr >= CMIS_REG_TX_POWER && addr < CMIS_REG_TX_POWER + 16) {
            lane = (addr - CMIS_REG_TX_POWER) / 2;
            return (cmis_encode_power(cmis_lane_enabled(s, lane) ?
                                      s->tx_power : 0) >>
                    ((addr & 1) ? 0 : 8)) & 0xff;
        }
        if (addr >= CMIS_REG_RX_POWER && addr < CMIS_REG_RX_POWER + 16) {
            lane = (addr - CMIS_REG_RX_POWER) / 2;
            /*
             * Receive power does not depend on this module's TxDisable. It
             * depends on whether the module at the far end is transmitting,
             * which nothing here models, so a lane that exists reports light.
             */
            return (cmis_encode_power(lane < s->lanes ? s->rx_power : 0) >>
                    ((addr & 1) ? 0 : 8)) & 0xff;
        }
    }

    const uint8_t *page = cmis_select_page(s);

    return page ? page[addr - CMIS_PAGE_SIZE] : 0;
}

static void cmis_write(CmisModuleState *s, uint8_t addr, uint8_t data)
{
    if (addr == CMIS_REG_PAGE_SELECT || addr == CMIS_REG_BANK_SELECT) {
        s->lower[addr] = data;
        return;
    }

    /*
     * Page 10h is the only writable page here, and TxDisable the only byte in
     * it that does anything. Everything else in a module's memory is read-only
     * to the host, so silently dropping the write is the correct behaviour
     * rather than an omission.
     */
    if (s->lower[CMIS_REG_PAGE_SELECT] == CMIS_PAGE_ID_10 &&
        addr >= CMIS_PAGE_SIZE) {
        s->page10[addr - CMIS_PAGE_SIZE] = data;
    }
}

static int cmis_event(I2CSlave *i2c, enum i2c_event event)
{
    CmisModuleState *s = CMIS_MODULE(i2c);

    switch (event) {
    case I2C_START_SEND:
        s->have_pointer = false;
        break;
    case I2C_START_RECV:
    case I2C_FINISH:
    case I2C_NACK:
        break;
    default:
        return -1;
    }
    return 0;
}

static uint8_t cmis_recv(I2CSlave *i2c)
{
    CmisModuleState *s = CMIS_MODULE(i2c);
    uint8_t ret = cmis_read(s, s->pointer);

    /*
     * The address counter wraps within the 256 byte window rather than running
     * on into the next page, which is what lets i2cdump read a whole page in
     * one transaction.
     */
    s->pointer++;
    return ret;
}

static int cmis_send(I2CSlave *i2c, uint8_t data)
{
    CmisModuleState *s = CMIS_MODULE(i2c);

    if (!s->have_pointer) {
        s->pointer = data;
        s->have_pointer = true;
        return 0;
    }

    cmis_write(s, s->pointer, data);
    s->pointer++;
    return 0;
}

static void cmis_build_memory(CmisModuleState *s)
{
    unsigned i;
    uint8_t sum = 0;

    memset(s->lower, 0, sizeof(s->lower));
    memset(s->page00, 0, sizeof(s->page00));
    memset(s->page01, 0, sizeof(s->page01));
    memset(s->page02, 0, sizeof(s->page02));
    memset(s->page10, 0, sizeof(s->page10));
    memset(s->page11, 0, sizeof(s->page11));

    s->lower[CMIS_REG_IDENTIFIER] = 0x18;   /* QSFP-DD */
    s->lower[CMIS_REG_REVISION] = 0x50;     /* CMIS 5.0 */
    s->lower[CMIS_REG_MEMORY_MODEL] = 0x00; /* paged, not flat */
    /*
     * Module state, bits 3:1 of byte 3. 0x3 is ModuleReady, which is what a
     * module that has finished initialising reports and what a BMC waits for
     * before believing anything else it reads.
     */
    s->lower[CMIS_REG_MODULE_STATE] = 0x3 << 1;
    s->lower[CMIS_REG_MEDIA_TYPE] = 0x02;   /* single mode fibre */
    s->lower[CMIS_REG_PAGE_SELECT] = CMIS_PAGE_ID_00;

    s->page00[CMIS_REG_IDENTIFIER] = 0x18;
    cmis_put_ascii(s->page00, CMIS_REG_VENDOR_NAME - CMIS_PAGE_SIZE,
                   s->vendor_name, 16);
    cmis_put_ascii(s->page00, CMIS_REG_VENDOR_PN - CMIS_PAGE_SIZE,
                   s->vendor_pn, 16);
    cmis_put_ascii(s->page00, CMIS_REG_VENDOR_SN - CMIS_PAGE_SIZE,
                   s->vendor_sn, 16);
    cmis_put_ascii(s->page00, CMIS_REG_VENDOR_REV - CMIS_PAGE_SIZE,
                   s->vendor_rev, 2);
    cmis_put_ascii(s->page00, CMIS_REG_DATE_CODE - CMIS_PAGE_SIZE,
                   s->date_code, 8);

    /* An unregistered OUI, because inventing a real vendor's would be worse. */
    s->page00[CMIS_REG_VENDOR_OUI - CMIS_PAGE_SIZE] = 0x00;
    s->page00[CMIS_REG_VENDOR_OUI - CMIS_PAGE_SIZE + 1] = 0x00;
    s->page00[CMIS_REG_VENDOR_OUI - CMIS_PAGE_SIZE + 2] = 0x00;

    for (i = CMIS_PAGE_SIZE; i < CMIS_REG_PAGE00_CSUM; i++) {
        sum += s->page00[i - CMIS_PAGE_SIZE];
    }
    s->page00[CMIS_REG_PAGE00_CSUM - CMIS_PAGE_SIZE] = sum;

    /*
     * Thresholds. High alarm, low alarm, high warning, low warning, in that
     * order, in the same encoding as the monitor they guard. A BMC compares
     * the monitors against these, so shipping zeros would make every reading
     * look like an alarm.
     */
    cmis_put_be16(s->page02, CMIS_REG_TEMP_THRESH - CMIS_PAGE_SIZE,
                  cmis_encode_temp(75000));
    cmis_put_be16(s->page02, CMIS_REG_TEMP_THRESH - CMIS_PAGE_SIZE + 2,
                  cmis_encode_temp(-5000));
    cmis_put_be16(s->page02, CMIS_REG_TEMP_THRESH - CMIS_PAGE_SIZE + 4,
                  cmis_encode_temp(70000));
    cmis_put_be16(s->page02, CMIS_REG_TEMP_THRESH - CMIS_PAGE_SIZE + 6,
                  cmis_encode_temp(0));

    cmis_put_be16(s->page02, CMIS_REG_VOLT_THRESH - CMIS_PAGE_SIZE,
                  cmis_encode_voltage(3600));
    cmis_put_be16(s->page02, CMIS_REG_VOLT_THRESH - CMIS_PAGE_SIZE + 2,
                  cmis_encode_voltage(3000));
    cmis_put_be16(s->page02, CMIS_REG_VOLT_THRESH - CMIS_PAGE_SIZE + 4,
                  cmis_encode_voltage(3500));
    cmis_put_be16(s->page02, CMIS_REG_VOLT_THRESH - CMIS_PAGE_SIZE + 6,
                  cmis_encode_voltage(3100));
}

static void cmis_reset(DeviceState *dev)
{
    CmisModuleState *s = CMIS_MODULE(dev);

    s->pointer = 0;
    s->have_pointer = false;
    cmis_build_memory(s);
}

static void cmis_realize(DeviceState *dev, Error **errp)
{
    CmisModuleState *s = CMIS_MODULE(dev);

    if (s->lanes == 0 || s->lanes > CMIS_MAX_LANES) {
        error_setg(errp, "lanes must be between 1 and %d", CMIS_MAX_LANES);
        return;
    }
    cmis_build_memory(s);
}

static const Property cmis_props[] = {
    DEFINE_PROP_INT32("temperature", CmisModuleState, temperature, 35000),
    DEFINE_PROP_UINT32("voltage", CmisModuleState, voltage, 3300),
    DEFINE_PROP_UINT32("tx-power", CmisModuleState, tx_power, 1000),
    DEFINE_PROP_UINT32("rx-power", CmisModuleState, rx_power, 900),
    DEFINE_PROP_UINT32("tx-bias", CmisModuleState, tx_bias, 7000),
    DEFINE_PROP_UINT8("lanes", CmisModuleState, lanes, 8),
    DEFINE_PROP_STRING("vendor-name", CmisModuleState, vendor_name),
    DEFINE_PROP_STRING("part-number", CmisModuleState, vendor_pn),
    DEFINE_PROP_STRING("serial-number", CmisModuleState, vendor_sn),
    DEFINE_PROP_STRING("revision", CmisModuleState, vendor_rev),
    DEFINE_PROP_STRING("date-code", CmisModuleState, date_code),
};

static const VMStateDescription cmis_vmstate = {
    .name = "cmis-module",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_I2C_SLAVE(parent_obj, CmisModuleState),
        VMSTATE_UINT8(pointer, CmisModuleState),
        VMSTATE_BOOL(have_pointer, CmisModuleState),
        VMSTATE_UINT8_ARRAY(lower, CmisModuleState, CMIS_PAGE_SIZE),
        VMSTATE_UINT8_ARRAY(page10, CmisModuleState, CMIS_PAGE_SIZE),
        VMSTATE_END_OF_LIST()
    }
};

static void cmis_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    I2CSlaveClass *k = I2C_SLAVE_CLASS(klass);

    dc->desc = "CMIS optical module (QSFP-DD)";
    dc->realize = cmis_realize;
    dc->vmsd = &cmis_vmstate;
    device_class_set_legacy_reset(dc, cmis_reset);
    device_class_set_props(dc, cmis_props);

    k->event = cmis_event;
    k->recv = cmis_recv;
    k->send = cmis_send;
}

static void cmis_init(Object *obj)
{
    CmisModuleState *s = CMIS_MODULE(obj);

    s->vendor_name = g_strdup("PacketFive");
    s->vendor_pn = g_strdup("CNUAS-QDD-400G-DR4");
    s->vendor_sn = g_strdup("CNUAS0000000000");
    s->vendor_rev = g_strdup("01");
    s->date_code = g_strdup("250101  ");
}

static const TypeInfo cmis_types[] = {
    {
        .name          = TYPE_CMIS_MODULE,
        .parent        = TYPE_I2C_SLAVE,
        .instance_size = sizeof(CmisModuleState),
        .instance_init = cmis_init,
        .class_init    = cmis_class_init,
    },
};

DEFINE_TYPES(cmis_types)
