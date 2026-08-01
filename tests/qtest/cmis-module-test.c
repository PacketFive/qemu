/*
 * QTest testcase for the CMIS optical module
 *
 * Copyright (c) 2026 Weqaar Janjua <weqaar.janjua@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"

#include "libqtest.h"
#include "libqos/qgraph.h"
#include "libqos/i2c.h"

#define CMIS_TEST_ADDR          0x50

#define CMIS_REG_IDENTIFIER     0
#define CMIS_REG_MODULE_STATE   3
#define CMIS_REG_TEMPERATURE    14
#define CMIS_REG_VOLTAGE        16
#define CMIS_REG_MEDIA_TYPE     85
#define CMIS_REG_PAGE_SELECT    127
#define CMIS_REG_VENDOR_NAME    129
#define CMIS_REG_PAGE00_CSUM    222
#define CMIS_REG_TX_DISABLE     130
#define CMIS_REG_TX_BIAS        138
#define CMIS_REG_TX_POWER       154
#define CMIS_REG_RX_POWER       170

#define CMIS_PAGE_ID_00         0x00
#define CMIS_PAGE_ID_10         0x10
#define CMIS_PAGE_ID_11         0x11

static uint16_t cmis_get16(QI2CDevice *i2cdev, uint8_t reg)
{
    return (i2c_get8(i2cdev, reg) << 8) | i2c_get8(i2cdev, reg + 1);
}

static void select_page(QI2CDevice *i2cdev, uint8_t page)
{
    i2c_set8(i2cdev, CMIS_REG_PAGE_SELECT, page);
}

static void test_lower_page(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = (QI2CDevice *)obj;

    /* QSFP-DD, and a module that has finished bringing itself up. */
    g_assert_cmphex(i2c_get8(i2cdev, CMIS_REG_IDENTIFIER), ==, 0x18);
    g_assert_cmphex(i2c_get8(i2cdev, CMIS_REG_MODULE_STATE), ==, 0x06);
    g_assert_cmphex(i2c_get8(i2cdev, CMIS_REG_MEDIA_TYPE), ==, 0x02);

    /* 35000 millidegrees is 35.0 C, which CMIS states in 1/256 C. */
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_TEMPERATURE), ==, 35 * 256);

    /* 3300 mV in units of 100 uV. */
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_VOLTAGE), ==, 33000);
}

static void test_identity_page(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = (QI2CDevice *)obj;
    uint8_t sum = 0;
    int i;

    select_page(i2cdev, CMIS_PAGE_ID_00);

    /* The vendor name is ASCII, space padded rather than NUL terminated. */
    for (i = 0; i < 16; i++) {
        uint8_t c = i2c_get8(i2cdev, CMIS_REG_VENDOR_NAME + i);

        g_assert_cmpint(c, >=, 0x20);
        g_assert_cmpint(c, <=, 0x7e);
    }

    /*
     * Firmware validates the identity page before trusting it, so the
     * checksum over bytes 128 to 221 has to be right.
     */
    for (i = 128; i <= 221; i++) {
        sum += i2c_get8(i2cdev, i);
    }
    g_assert_cmphex(i2c_get8(i2cdev, CMIS_REG_PAGE00_CSUM), ==, sum);
}

static void test_tx_disable(void *obj, void *data, QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = (QI2CDevice *)obj;

    /* Defaults: 7000 uA in units of 2 uA, 1000 uW and 900 uW in 0.1 uW. */
    select_page(i2cdev, CMIS_PAGE_ID_11);
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_TX_BIAS), ==, 3500);
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_TX_POWER), ==, 10000);
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_RX_POWER), ==, 9000);

    /* Disabling lane 0 must stop its transmitter, and only its transmitter. */
    select_page(i2cdev, CMIS_PAGE_ID_10);
    i2c_set8(i2cdev, CMIS_REG_TX_DISABLE, 0x01);

    select_page(i2cdev, CMIS_PAGE_ID_11);
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_TX_BIAS), ==, 0);
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_TX_POWER), ==, 0);

    /*
     * Light still arrives from the far end, so the receiver is unaffected,
     * and lane 1 was never disabled.
     */
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_RX_POWER), ==, 9000);
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_TX_POWER + 2), ==, 10000);

    /* Re-enabling brings it back. */
    select_page(i2cdev, CMIS_PAGE_ID_10);
    i2c_set8(i2cdev, CMIS_REG_TX_DISABLE, 0x00);

    select_page(i2cdev, CMIS_PAGE_ID_11);
    g_assert_cmphex(cmis_get16(i2cdev, CMIS_REG_TX_POWER), ==, 10000);
}

static void test_unimplemented_page(void *obj, void *data,
                                    QGuestAllocator *alloc)
{
    QI2CDevice *i2cdev = (QI2CDevice *)obj;

    /*
     * Firmware walks pages speculatively, so an unimplemented one reads as
     * zeroes rather than failing the transaction.
     */
    select_page(i2cdev, 0x25);
    g_assert_cmphex(i2c_get8(i2cdev, 128), ==, 0);
    g_assert_cmphex(i2c_get8(i2cdev, 200), ==, 0);

    /* The lower page is always visible, whatever page is selected. */
    g_assert_cmphex(i2c_get8(i2cdev, CMIS_REG_IDENTIFIER), ==, 0x18);
}

static void cmis_module_register_nodes(void)
{
    QOSGraphEdgeOptions opts = {
        .extra_device_opts = "address=0x50"
    };
    add_qi2c_address(&opts, &(QI2CAddress) { CMIS_TEST_ADDR });

    qos_node_create_driver("cmis-module", i2c_device_create);
    qos_node_consumes("cmis-module", "i2c-bus", &opts);

    qos_add_test("lower-page", "cmis-module", test_lower_page, NULL);
    qos_add_test("identity-page", "cmis-module", test_identity_page, NULL);
    qos_add_test("tx-disable", "cmis-module", test_tx_disable, NULL);
    qos_add_test("unimplemented-page", "cmis-module",
                 test_unimplemented_page, NULL);
}
libqos_init(cmis_module_register_nodes);
