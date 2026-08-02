/*
 * PDP-V pdpv-virt reset, power, and hart-control tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#define CONTROL_BASE       0x10010000ULL
#define COLD_RESET         (CONTROL_BASE + 0x000)
#define POWER_OFF          (CONTROL_BASE + 0x004)
#define HART_CAPABILITY    (CONTROL_BASE + 0x100)
#define HART_PRESENT       (CONTROL_BASE + 0x108)
#define HART_RUNNING       (CONTROL_BASE + 0x110)
#define HART_ERROR         (CONTROL_BASE + 0x118)
#define HART_ENTRY(h)      (CONTROL_BASE + 0x200 + 8 * (h))
#define HART_START(h)      (CONTROL_BASE + 0x400 + 8 * (h))
#define HART_ARGUMENT(h)   (CONTROL_BASE + 0x600 + 8 * (h))

static QTestState *platform_control_start(void)
{
    return qtest_init("-M pdp12-virt -display none -audio none "
                      "-serial null");
}

static void test_hart_control_single_hart(void)
{
    QTestState *qts = platform_control_start();

    g_assert_cmphex(qtest_readq(qts, HART_CAPABILITY), ==, 0x100);
    g_assert_cmphex(qtest_readq(qts, HART_PRESENT), ==, 1);
    g_assert_cmphex(qtest_readq(qts, HART_RUNNING), ==, 1);
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 0);

    qtest_writeq(qts, HART_ENTRY(0), 0x80001000);
    qtest_writeq(qts, HART_ARGUMENT(0), 0x1234);
    g_assert_cmphex(qtest_readq(qts, HART_ENTRY(0)), ==, 0);
    g_assert_cmphex(qtest_readq(qts, HART_ARGUMENT(0)), ==, 0);

    qtest_writeq(qts, HART_START(0), 1);
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 1);
    qtest_writeq(qts, HART_ERROR, 1);
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 0);

    qtest_writeq(qts, HART_START(1), 1);
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 2);
    qtest_writeq(qts, HART_ERROR, 2);
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 0);

    qtest_quit(qts);
}

static void test_cold_reset_magic(void)
{
    QTestState *qts = platform_control_start();

    g_assert_cmphex(qtest_readl(qts, COLD_RESET), ==, 0);
    qtest_writeq(qts, HART_START(0), 1);
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 1);
    qtest_writel(qts, COLD_RESET, 0);
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 1);
    qtest_writel(qts, COLD_RESET, 0x5555);
    qtest_qmp_eventwait(qts, "RESET");
    g_assert_cmphex(qtest_readq(qts, HART_ERROR), ==, 0);

    qtest_quit(qts);
}

static void test_power_off_magic(void)
{
    QTestState *qts = platform_control_start();

    g_assert_cmphex(qtest_readl(qts, POWER_OFF), ==, 0);
    qtest_writel(qts, POWER_OFF, 0);
    g_assert_cmphex(qtest_readq(qts, HART_RUNNING), ==, 1);
    qtest_writel(qts, POWER_OFF, 0x3333);
    qtest_qmp_eventwait(qts, "SHUTDOWN");

    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/pdp12/platform-control/single-hart",
                   test_hart_control_single_hart);
    qtest_add_func("/pdp12/platform-control/cold-reset",
                   test_cold_reset_magic);
    qtest_add_func("/pdp12/platform-control/power-off",
                   test_power_off_magic);
    return g_test_run();
}
