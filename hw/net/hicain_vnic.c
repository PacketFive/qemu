/*
 * HiCAIN RoCE-IB-vNIC — Educational RDMA virtual NIC for Project HiCAIN
 *
 * Copyright (c) 2026 PacketFive / Project HiCAIN
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/main-loop.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/core/qdev-properties.h"
#include "qom/object.h"
#include "qapi/visitor.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>

#define TYPE_HICAIN_VNIC "hicain-vnic"
typedef struct HicainVnicState HicainVnicState;
DECLARE_INSTANCE_CHECKER(HicainVnicState, HICAIN_VNIC,
                         TYPE_HICAIN_VNIC)

#define HICAIN_VENDOR_ID     0x1ED5
#define HICAIN_DEVICE_ID     0xCA10

#define HICAIN_MAX_FRAME     9216
#define HICAIN_MMIO_SIZE     4096

#define REG_TX_ADDR_LO       0x00
#define REG_TX_ADDR_HI       0x04
#define REG_TX_LEN            0x08
#define REG_TX_DOORBELL       0x0C
#define REG_RX_ADDR_LO       0x10
#define REG_RX_ADDR_HI       0x14
#define REG_RX_LEN            0x18
#define REG_RX_STATUS         0x1C
#define REG_IRQ_STATUS        0x20
#define REG_IRQ_MASK          0x24
#define REG_LINK_STATUS       0x28
#define REG_MAC_LO            0x2C
#define REG_MAC_HI            0x30

#define IRQ_RX_COMPLETE      0x01
#define IRQ_TX_COMPLETE      0x02
#define IRQ_LINK_CHANGE      0x04

#define LINK_STATUS_UP       0x01
#define LINK_STATUS_DOWN     0x00

#define RX_STATUS_EMPTY      0x00
#define RX_STATUS_READY      0x01

struct HicainVnicState {
    PCIDevice pdev;
    MemoryRegion mmio;

    char *socket_path;
    int sock_fd;

    uint32_t tx_addr_lo;
    uint32_t tx_addr_hi;
    uint32_t tx_len;

    uint32_t rx_addr_lo;
    uint32_t rx_addr_hi;
    uint32_t rx_len;
    uint32_t rx_status;

    uint32_t irq_status;
    uint32_t irq_mask;
    uint32_t link_status;

    uint8_t mac[6];

    uint8_t rx_buf[HICAIN_MAX_FRAME];
    uint32_t rx_buf_len;
};

static void hicain_vnic_update_irq(HicainVnicState *s)
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

static void hicain_vnic_tx(HicainVnicState *s)
{
    uint8_t buf[HICAIN_MAX_FRAME];
    uint64_t addr;
    uint32_t len;

    addr = ((uint64_t)s->tx_addr_hi << 32) | s->tx_addr_lo;
    len = s->tx_len;

    if (len == 0 || len > HICAIN_MAX_FRAME) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "hicain-vnic: invalid TX len %u\n", len);
        return;
    }

    pci_dma_read(&s->pdev, addr, buf, len);

    if (s->sock_fd >= 0 && s->link_status == LINK_STATUS_UP) {
        ssize_t sent = send(s->sock_fd, buf, len, MSG_NOSIGNAL);
        if (sent < 0) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "hicain-vnic: TX send failed: %s\n",
                          strerror(errno));
        }
    }

    s->irq_status |= IRQ_TX_COMPLETE;
    hicain_vnic_update_irq(s);
}

static void hicain_vnic_check_rx(HicainVnicState *s)
{
    ssize_t len;
    uint64_t addr;

    if (s->sock_fd < 0 || s->rx_status == RX_STATUS_READY) {
        return;
    }

    len = recv(s->sock_fd, s->rx_buf, HICAIN_MAX_FRAME, MSG_DONTWAIT);
    if (len <= 0) {
        return;
    }

    s->rx_buf_len = len;

    addr = ((uint64_t)s->rx_addr_hi << 32) | s->rx_addr_lo;
    if (addr == 0) {
        return;
    }

    pci_dma_write(&s->pdev, addr, s->rx_buf, len);
    s->rx_len = len;
    s->rx_status = RX_STATUS_READY;

    s->irq_status |= IRQ_RX_COMPLETE;
    hicain_vnic_update_irq(s);
}

static uint64_t hicain_vnic_mmio_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    HicainVnicState *s = opaque;

    switch (addr) {
    case REG_TX_ADDR_LO:
        return s->tx_addr_lo;
    case REG_TX_ADDR_HI:
        return s->tx_addr_hi;
    case REG_TX_LEN:
        return s->tx_len;
    case REG_RX_ADDR_LO:
        return s->rx_addr_lo;
    case REG_RX_ADDR_HI:
        return s->rx_addr_hi;
    case REG_RX_LEN:
        return s->rx_len;
    case REG_RX_STATUS:
        hicain_vnic_check_rx(s);
        return s->rx_status;
    case REG_IRQ_STATUS:
        return s->irq_status;
    case REG_IRQ_MASK:
        return s->irq_mask;
    case REG_LINK_STATUS:
        return s->link_status;
    case REG_MAC_LO:
        return (uint32_t)s->mac[0] |
               ((uint32_t)s->mac[1] << 8) |
               ((uint32_t)s->mac[2] << 16) |
               ((uint32_t)s->mac[3] << 24);
    case REG_MAC_HI:
        return (uint32_t)s->mac[4] |
               ((uint32_t)s->mac[5] << 8);
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "hicain-vnic: read from unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        return 0;
    }
}

static void hicain_vnic_mmio_write(void *opaque, hwaddr addr,
                                    uint64_t val, unsigned size)
{
    HicainVnicState *s = opaque;

    switch (addr) {
    case REG_TX_ADDR_LO:
        s->tx_addr_lo = val;
        break;
    case REG_TX_ADDR_HI:
        s->tx_addr_hi = val;
        break;
    case REG_TX_LEN:
        s->tx_len = val;
        break;
    case REG_TX_DOORBELL:
        hicain_vnic_tx(s);
        break;
    case REG_RX_ADDR_LO:
        s->rx_addr_lo = val;
        break;
    case REG_RX_ADDR_HI:
        s->rx_addr_hi = val;
        break;
    case REG_RX_STATUS:
        if (val == 0) {
            s->rx_status = RX_STATUS_EMPTY;
        }
        break;
    case REG_IRQ_STATUS:
        s->irq_status &= ~val;
        hicain_vnic_update_irq(s);
        break;
    case REG_IRQ_MASK:
        s->irq_mask = val;
        hicain_vnic_update_irq(s);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "hicain-vnic: write to unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        break;
    }
}

static const MemoryRegionOps hicain_vnic_mmio_ops = {
    .read = hicain_vnic_mmio_read,
    .write = hicain_vnic_mmio_write,
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

static int hicain_vnic_connect(HicainVnicState *s)
{
    struct sockaddr_un addr;
    int fd;

    if (!s->socket_path || s->socket_path[0] == '\0') {
        s->link_status = LINK_STATUS_DOWN;
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        qemu_log_mask(LOG_UNIMP,
                      "hicain-vnic: socket() failed: %s\n", strerror(errno));
        s->link_status = LINK_STATUS_DOWN;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, s->socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        qemu_log_mask(LOG_UNIMP,
                      "hicain-vnic: connect(%s) failed: %s\n",
                      s->socket_path, strerror(errno));
        close(fd);
        s->link_status = LINK_STATUS_DOWN;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    s->sock_fd = fd;
    s->link_status = LINK_STATUS_UP;

    return 0;
}

static void hicain_vnic_realize(PCIDevice *pdev, Error **errp)
{
    HicainVnicState *s = HICAIN_VNIC(pdev);

    pci_config_set_interrupt_pin(pdev->config, 1);
    msi_init(pdev, 0, 1, true, false, errp);

    memory_region_init_io(&s->mmio, OBJECT(s), &hicain_vnic_mmio_ops, s,
                          "hicain-vnic-mmio", HICAIN_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

    s->sock_fd = -1;
    s->link_status = LINK_STATUS_DOWN;
    s->rx_status = RX_STATUS_EMPTY;
    s->irq_status = 0;
    s->irq_mask = 0;

    s->mac[0] = 0x02;
    s->mac[1] = 0x48;
    s->mac[2] = 0x43;
    s->mac[3] = 0x41;
    s->mac[4] = 0x49;
    s->mac[5] = 0x00;

    hicain_vnic_connect(s);
}

static void hicain_vnic_exit(PCIDevice *pdev)
{
    HicainVnicState *s = HICAIN_VNIC(pdev);

    if (s->sock_fd >= 0) {
        close(s->sock_fd);
        s->sock_fd = -1;
    }

    msi_uninit(pdev);
}

static const Property hicain_vnic_properties[] = {
    DEFINE_PROP_STRING("socket_path", HicainVnicState, socket_path),
};

static void hicain_vnic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = hicain_vnic_realize;
    k->exit = hicain_vnic_exit;
    k->vendor_id = HICAIN_VENDOR_ID;
    k->device_id = HICAIN_DEVICE_ID;
    k->class_id = PCI_CLASS_NETWORK_OTHER;
    k->revision = 0x01;

    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "HiCAIN RoCE-IB-vNIC (Educational RDMA NIC)";
    device_class_set_props(dc, hicain_vnic_properties);
}

static const TypeInfo hicain_vnic_info = {
    .name          = TYPE_HICAIN_VNIC,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(HicainVnicState),
    .class_init    = hicain_vnic_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void hicain_vnic_register_types(void)
{
    type_register_static(&hicain_vnic_info);
}

type_init(hicain_vnic_register_types)
