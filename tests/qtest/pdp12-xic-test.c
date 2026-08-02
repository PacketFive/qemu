/*
 * PDP-V pdpv-virt XIC v1 conformance tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "libqtest.h"

#define XIC_BASE               0x0c000000ULL
#define XIC_CAPABILITY         (XIC_BASE + 0x0000)
#define XIC_GLOBAL_ERROR       (XIC_BASE + 0x0008)
#define XIC_SOURCE_CONFIG(s)   (XIC_BASE + 0x1000 + 8 * (s))
#define XIC_PENDING(w)         (XIC_BASE + 0x2000 + 8 * (w))
#define XIC_IN_FLIGHT(w)       (XIC_BASE + 0x2040 + 8 * (w))
#define XIC_ASSERTED(w)        (XIC_BASE + 0x2080 + 8 * (w))
#define XIC_ENABLE(w)          (XIC_BASE + 0x40000 + 8 * (w))
#define XIC_THRESHOLD          (XIC_BASE + 0x40020)
#define XIC_CLAIM_COMPLETE     (XIC_BASE + 0x40028)
#define XIC_ACTIVE             (XIC_BASE + 0x40030)
#define XIC_CONTEXT_ERROR      (XIC_BASE + 0x40038)
#define UART_BASE              0x10000000ULL
#define UART_IER               (UART_BASE + 1)
#define VIRTIO_BASE            0x10001000ULL
#define VIRTIO_MAGIC           (VIRTIO_BASE + 0x000)
#define VIRTIO_VERSION         (VIRTIO_BASE + 0x004)
#define VIRTIO_DEVICE_ID       (VIRTIO_BASE + 0x008)
#define VIRTIO_DEVICE_FEATURES (VIRTIO_BASE + 0x010)
#define VIRTIO_DEVICE_FEATURES_SEL (VIRTIO_BASE + 0x014)
#define VIRTIO_DRIVER_FEATURES (VIRTIO_BASE + 0x020)
#define VIRTIO_DRIVER_FEATURES_SEL (VIRTIO_BASE + 0x024)
#define VIRTIO_QUEUE_SEL       (VIRTIO_BASE + 0x030)
#define VIRTIO_QUEUE_NUM_MAX   (VIRTIO_BASE + 0x034)
#define VIRTIO_QUEUE_NUM       (VIRTIO_BASE + 0x038)
#define VIRTIO_QUEUE_READY     (VIRTIO_BASE + 0x044)
#define VIRTIO_QUEUE_NOTIFY    (VIRTIO_BASE + 0x050)
#define VIRTIO_INTERRUPT_STATUS (VIRTIO_BASE + 0x060)
#define VIRTIO_INTERRUPT_ACK   (VIRTIO_BASE + 0x064)
#define VIRTIO_STATUS          (VIRTIO_BASE + 0x070)
#define VIRTIO_QUEUE_DESC_LOW  (VIRTIO_BASE + 0x080)
#define VIRTIO_QUEUE_DESC_HIGH (VIRTIO_BASE + 0x084)
#define VIRTIO_QUEUE_AVAIL_LOW (VIRTIO_BASE + 0x090)
#define VIRTIO_QUEUE_AVAIL_HIGH (VIRTIO_BASE + 0x094)
#define VIRTIO_QUEUE_USED_LOW  (VIRTIO_BASE + 0x0a0)
#define VIRTIO_QUEUE_USED_HIGH (VIRTIO_BASE + 0x0a4)
#define VIRTIO_BLOCK_SOURCE    2
#define NPU_DOORBELL           0x10008000ULL
#define NPU_SOURCE             32
#define IRQ_EXTERNAL           9

#define SOURCE_BIT(s)          (1ULL << ((s) % 64))

static QTestState *xic_start(void)
{
    QTestState *qts = qtest_init("-M pdp12-virt -display none "
                                 "-audio none -serial null");

    g_assert(qtest_readq(qts, XIC_CAPABILITY) ==
             (1ULL | (7ULL << 8) | (255ULL << 16) | (1ULL << 32)));
    return qts;
}

static void xic_input(QTestState *qts, unsigned int source, bool level)
{
    qtest_set_irq_in(qts, "/machine/xic", "unnamed-gpio-in",
                     source, level);
}

static void xic_configure(QTestState *qts, unsigned int source,
                          unsigned int priority, unsigned int trigger)
{
    qtest_writeq(qts, XIC_SOURCE_CONFIG(source),
                 priority | ((uint64_t)trigger << 3));
}

static void xic_enable(QTestState *qts, unsigned int source)
{
    unsigned int word = source / 64;
    uint64_t value = qtest_readq(qts, XIC_ENABLE(word));

    qtest_writeq(qts, XIC_ENABLE(word), value | SOURCE_BIT(source));
}

static uint64_t cpu_ip(QTestState *qts)
{
    g_autofree char *registers = qtest_hmp(qts, "info registers");
    const char *field = strstr(registers, " IP=0x");
    char *end;
    uint64_t value;

    g_assert(field);
    value = g_ascii_strtoull(field + strlen(" IP=0x"), &end, 16);
    g_assert(end != field + strlen(" IP=0x"));
    return value;
}

static void assert_external_pending(QTestState *qts, bool expected)
{
    g_assert(((cpu_ip(qts) & (1ULL << IRQ_EXTERNAL)) != 0) == expected);
}

static void test_priority_tie_threshold(void)
{
    QTestState *qts = xic_start();

    xic_configure(qts, 2, 6, 0);
    xic_configure(qts, 3, 7, 0);
    xic_configure(qts, 4, 7, 0);
    xic_enable(qts, 2);
    xic_enable(qts, 3);
    xic_enable(qts, 4);
    xic_input(qts, 2, true);
    xic_input(qts, 3, true);
    xic_input(qts, 4, true);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) ==
             (SOURCE_BIT(2) | SOURCE_BIT(3) | SOURCE_BIT(4)));
    assert_external_pending(qts, true);

    qtest_writeq(qts, XIC_THRESHOLD, 7);
    assert_external_pending(qts, false);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 0);
    qtest_writeq(qts, XIC_THRESHOLD, 6);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 3);
    g_assert(qtest_readq(qts, XIC_ACTIVE) == 3);

    qtest_quit(qts);
}

static void test_disabled_source(void)
{
    QTestState *qts = xic_start();

    xic_configure(qts, 5, 4, 0);
    xic_input(qts, 5, true);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == SOURCE_BIT(5));
    assert_external_pending(qts, false);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 0);

    xic_enable(qts, 5);
    assert_external_pending(qts, true);
    qtest_quit(qts);
}

static void test_exclusive_claim(void)
{
    QTestState *qts = xic_start();

    xic_configure(qts, 5, 7, 0);
    xic_enable(qts, 5);
    xic_input(qts, 5, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 5);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == 0);
    g_assert(qtest_readq(qts, XIC_IN_FLIGHT(0)) == SOURCE_BIT(5));
    g_assert(qtest_readq(qts, XIC_ACTIVE) == 5);
    g_assert(qtest_readq(qts, XIC_ASSERTED(0)) == SOURCE_BIT(5));

    /*
     * A real level producer and the XIC both return to an inactive state
     * across system reset; stale producer state must not be lost in XIC.
     */
    xic_configure(qts, NPU_SOURCE, 1, 0);
    xic_enable(qts, NPU_SOURCE);
    qtest_writel(qts, NPU_DOORBELL, 1);
    g_assert(qtest_readq(qts, XIC_ASSERTED(0)) & SOURCE_BIT(NPU_SOURCE));
    qtest_system_reset(qts);
    g_assert(qtest_readq(qts, XIC_ASSERTED(0)) == 0);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == 0);
    assert_external_pending(qts, false);

    qtest_quit(qts);
}

static void test_active_suppression(void)
{
    QTestState *qts = xic_start();

    xic_configure(qts, 1, 7, 0);
    xic_configure(qts, 2, 7, 0);
    xic_enable(qts, 1);
    xic_enable(qts, 2);
    xic_input(qts, 1, true);
    xic_input(qts, 2, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 1);
    assert_external_pending(qts, false);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 0);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == SOURCE_BIT(2));

    qtest_quit(qts);
}

static void test_level_lifecycle(void)
{
    QTestState *qts = xic_start();

    xic_configure(qts, 1, 1, 0);
    xic_enable(qts, 1);
    xic_input(qts, 1, true);
    xic_input(qts, 1, false);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == 0);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 0);

    xic_input(qts, 1, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 1);
    xic_input(qts, 1, false);
    qtest_writeq(qts, XIC_CLAIM_COMPLETE, 1);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == 0);
    g_assert(qtest_readq(qts, XIC_ACTIVE) == 0);

    xic_input(qts, 1, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 1);
    qtest_writeq(qts, XIC_CLAIM_COMPLETE, 1);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == SOURCE_BIT(1));
    assert_external_pending(qts, true);

    qtest_quit(qts);
}

static void test_edge_during_flight(void)
{
    QTestState *qts = xic_start();

    xic_configure(qts, 2, 1, 1);
    xic_enable(qts, 2);
    xic_input(qts, 2, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 2);
    xic_input(qts, 2, false);
    xic_input(qts, 2, true);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == 0);
    qtest_writeq(qts, XIC_CLAIM_COMPLETE, 2);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == SOURCE_BIT(2));
    assert_external_pending(qts, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 2);

    qtest_quit(qts);
}

static void test_invalid_operations(void)
{
    QTestState *qts = xic_start();

    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 0);
    xic_configure(qts, 1, 1, 0);
    xic_configure(qts, 1, 1, 1);
    g_assert(qtest_readq(qts, XIC_GLOBAL_ERROR) == 1);
    g_assert(qtest_readq(qts, XIC_SOURCE_CONFIG(1)) == 1);
    qtest_writeq(qts, XIC_GLOBAL_ERROR, 1);
    g_assert(qtest_readq(qts, XIC_GLOBAL_ERROR) == 0);

    qtest_writeq(qts, XIC_SOURCE_CONFIG(2), 2ULL << 3);
    g_assert(qtest_readq(qts, XIC_GLOBAL_ERROR) == 1);
    qtest_writeq(qts, XIC_THRESHOLD, 8);
    g_assert(qtest_readq(qts, XIC_CONTEXT_ERROR) == 1);
    g_assert(qtest_readq(qts, XIC_THRESHOLD) == 0);
    qtest_writeq(qts, XIC_CONTEXT_ERROR, 1);

    xic_enable(qts, 1);
    xic_input(qts, 1, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 1);
    qtest_writeq(qts, XIC_CLAIM_COMPLETE, 0);
    g_assert(qtest_readq(qts, XIC_CONTEXT_ERROR) == 1);
    g_assert(qtest_readq(qts, XIC_ACTIVE) == 1);
    qtest_writeq(qts, XIC_CONTEXT_ERROR, 1);
    qtest_writeq(qts, XIC_CLAIM_COMPLETE, 2);
    g_assert(qtest_readq(qts, XIC_CONTEXT_ERROR) == 1);
    g_assert(qtest_readq(qts, XIC_ACTIVE) == 1);

    qtest_quit(qts);
}

static void test_uart_source_one(void)
{
    QTestState *qts = xic_start();

    xic_configure(qts, 1, 1, 0);
    xic_enable(qts, 1);
    qtest_writeb(qts, UART_IER, 2);
    g_assert(qtest_readq(qts, XIC_ASSERTED(0)) == SOURCE_BIT(1));
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == SOURCE_BIT(1));
    assert_external_pending(qts, true);
    g_assert(qtest_readq(qts, XIC_CLAIM_COMPLETE) == 1);
    assert_external_pending(qts, false);

    qtest_writeb(qts, UART_IER, 0);
    qtest_writeq(qts, XIC_CLAIM_COMPLETE, 1);
    g_assert(qtest_readq(qts, XIC_ACTIVE) == 0);
    g_assert(qtest_readq(qts, XIC_PENDING(0)) == 0);
    assert_external_pending(qts, false);

    qtest_quit(qts);
}

static void write_descriptor(QTestState *qts, uint64_t address,
                             uint64_t buffer, uint32_t length,
                             uint16_t flags, uint16_t next)
{
    uint8_t descriptor[16];

    stq_le_p(descriptor + 0, buffer);
    stl_le_p(descriptor + 8, length);
    stw_le_p(descriptor + 12, flags);
    stw_le_p(descriptor + 14, next);
    qtest_memwrite(qts, address, descriptor, sizeof(descriptor));
}

static void test_virtio_block_source_two(void)
{
    const uint64_t descriptor_table = 0x80010000;
    const uint64_t available_ring = 0x80011000;
    const uint64_t used_ring = 0x80012000;
    const uint64_t request_header = 0x80013000;
    const uint64_t data_buffer = 0x80014000;
    const uint64_t request_status = 0x80015000;
    g_autofree char *disk_path = NULL;
    g_autoptr(GError) error = NULL;
    QTestState *qts;
    uint8_t header[16] = {};
    uint8_t available[6] = {};
    uint8_t status = 0xff;
    uint32_t features_high;
    uint32_t interrupt_status = 0;
    int fd;
    int attempt;

    fd = g_file_open_tmp("pdp12-virtio-block-XXXXXX",
                         &disk_path, &error);
    g_assert_no_error(error);
    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(ftruncate(fd, 1024 * 1024), ==, 0);
    close(fd);

    qts = qtest_initf("-M pdp12-virt -display none -audio none "
                      "-serial null "
                      "-drive if=none,file=%s,format=raw,id=vd0 "
                      "-device virtio-blk-device,drive=vd0",
                      disk_path);

    g_assert_cmphex(qtest_readl(qts, VIRTIO_MAGIC), ==, 0x74726976);
    g_assert_cmphex(qtest_readl(qts, VIRTIO_VERSION), ==, 2);
    g_assert_cmphex(qtest_readl(qts, VIRTIO_DEVICE_ID), ==, 2);

    qtest_writel(qts, VIRTIO_STATUS, 0);
    qtest_writel(qts, VIRTIO_STATUS, 1);
    qtest_writel(qts, VIRTIO_STATUS, 3);
    qtest_writel(qts, VIRTIO_DEVICE_FEATURES_SEL, 1);
    features_high = qtest_readl(qts, VIRTIO_DEVICE_FEATURES);
    g_assert(features_high & 1);
    qtest_writel(qts, VIRTIO_DRIVER_FEATURES_SEL, 0);
    qtest_writel(qts, VIRTIO_DRIVER_FEATURES, 0);
    qtest_writel(qts, VIRTIO_DRIVER_FEATURES_SEL, 1);
    qtest_writel(qts, VIRTIO_DRIVER_FEATURES, 1);
    qtest_writel(qts, VIRTIO_STATUS, 11);
    g_assert(qtest_readl(qts, VIRTIO_STATUS) & 8);

    qtest_writel(qts, VIRTIO_QUEUE_SEL, 0);
    g_assert_cmpuint(qtest_readl(qts, VIRTIO_QUEUE_NUM_MAX), >=, 8);
    qtest_writel(qts, VIRTIO_QUEUE_NUM, 8);
    qtest_writel(qts, VIRTIO_QUEUE_DESC_LOW, (uint32_t)descriptor_table);
    qtest_writel(qts, VIRTIO_QUEUE_DESC_HIGH, descriptor_table >> 32);
    qtest_writel(qts, VIRTIO_QUEUE_AVAIL_LOW, (uint32_t)available_ring);
    qtest_writel(qts, VIRTIO_QUEUE_AVAIL_HIGH, available_ring >> 32);
    qtest_writel(qts, VIRTIO_QUEUE_USED_LOW, (uint32_t)used_ring);
    qtest_writel(qts, VIRTIO_QUEUE_USED_HIGH, used_ring >> 32);
    qtest_writel(qts, VIRTIO_QUEUE_READY, 1);
    qtest_writel(qts, VIRTIO_STATUS, 15);

    write_descriptor(qts, descriptor_table, request_header, 16, 1, 1);
    write_descriptor(qts, descriptor_table + 16, data_buffer, 512, 3, 2);
    write_descriptor(qts, descriptor_table + 32, request_status, 1, 2, 0);
    qtest_memwrite(qts, request_header, header, sizeof(header));
    stw_le_p(available + 2, 1);
    qtest_memwrite(qts, available_ring, available, sizeof(available));
    qtest_writeb(qts, request_status, status);

    xic_configure(qts, VIRTIO_BLOCK_SOURCE, 1, 0);
    xic_enable(qts, VIRTIO_BLOCK_SOURCE);
    qtest_writel(qts, VIRTIO_QUEUE_NOTIFY, 0);
    for (attempt = 0; attempt < 1000; attempt++) {
        interrupt_status = qtest_readl(qts, VIRTIO_INTERRUPT_STATUS);
        if (interrupt_status & 1) {
            break;
        }
        g_usleep(1000);
    }
    g_assert(interrupt_status & 1);
    g_assert(qtest_readq(qts, XIC_ASSERTED(0)) &
             SOURCE_BIT(VIRTIO_BLOCK_SOURCE));
    g_assert(qtest_readq(qts, XIC_PENDING(0)) &
             SOURCE_BIT(VIRTIO_BLOCK_SOURCE));
    assert_external_pending(qts, true);
    g_assert_cmpuint(qtest_readq(qts, XIC_CLAIM_COMPLETE), ==,
                     VIRTIO_BLOCK_SOURCE);

    status = qtest_readb(qts, request_status);
    g_assert_cmphex(status, ==, 0);
    g_assert_cmphex(qtest_readw(qts, used_ring + 2), ==, 1);
    qtest_writel(qts, VIRTIO_INTERRUPT_ACK, 1);
    qtest_writeq(qts, XIC_CLAIM_COMPLETE, VIRTIO_BLOCK_SOURCE);
    g_assert((qtest_readq(qts, XIC_ASSERTED(0)) &
              SOURCE_BIT(VIRTIO_BLOCK_SOURCE)) == 0);
    g_assert((qtest_readq(qts, XIC_PENDING(0)) &
              SOURCE_BIT(VIRTIO_BLOCK_SOURCE)) == 0);

    qtest_quit(qts);
    g_assert_cmpint(unlink(disk_path), ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/pdp12/xic/priority-tie-threshold",
                   test_priority_tie_threshold);
    qtest_add_func("/pdp12/xic/disabled-source", test_disabled_source);
    qtest_add_func("/pdp12/xic/exclusive-claim", test_exclusive_claim);
    qtest_add_func("/pdp12/xic/active-suppression",
                   test_active_suppression);
    qtest_add_func("/pdp12/xic/level-lifecycle", test_level_lifecycle);
    qtest_add_func("/pdp12/xic/edge-during-flight",
                   test_edge_during_flight);
    qtest_add_func("/pdp12/xic/invalid-operations",
                   test_invalid_operations);
    qtest_add_func("/pdp12/xic/uart-source-one", test_uart_source_one);
    qtest_add_func("/pdp12/xic/virtio-block-source-two",
                   test_virtio_block_source_two);
    return g_test_run();
}
