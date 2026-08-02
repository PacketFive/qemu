/*
 * Cnuas RoCE-IB-vNIC - Educational RDMA virtual NIC for Project Cnuas
 *
 * Copyright (c) 2026 PacketFive / Project Cnuas
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
#include "hw/pci/pcie.h"
#include "qapi/error.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "net/net.h"
#include "qom/object.h"
#include "qapi/visitor.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>

#define TYPE_CNUAS_VNIC "cnuas-vnic"
typedef struct CnuasVnicState CnuasVnicState;
DECLARE_INSTANCE_CHECKER(CnuasVnicState, CNUAS_VNIC,
                         TYPE_CNUAS_VNIC)

/*
 * PCI identity.
 *
 * EXPERIMENTAL IDs. cnuas-vnic is a purely emulated device, so it uses the
 * Red Hat / Qumranet vendor ID (0x1af4) with a device ID from the range
 * 1af4:10f0-10ff that QEMU reserves for experimental use without
 * registration (see docs/specs/pci-ids.rst). These MUST be replaced with an
 * officially assigned 1b36 device ID (contact the QEMU PCI ID maintainer)
 * before this device is submitted upstream or shipped in a product.
 */
#define CNUAS_VENDOR_ID     PCI_VENDOR_ID_REDHAT_QUMRANET
#define CNUAS_DEVICE_ID     0x10F0

#define CNUAS_MAX_FRAME     9216
#define CNUAS_MMIO_SIZE     4096

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

struct CnuasVnicState {
    PCIDevice pdev;
    MemoryRegion mmio;

    char *socket_path;
    int sock_fd;

    /*
     * MAC address.
     *
     * Exposed as a qdev property so each instance of -device
     * cnuas-vnic can be given a distinct address from the command
     * line (mac=02:48:43:41:49:NN).  If not supplied the realize
     * callback falls back to a deterministic per-PCI-slot value so
     * we never default two VMs to the same address.
     */
    MACAddr conf_mac;
    uint8_t mac[6];

    /*
     * Advertised PCI Express link. These populate the Link Capabilities
     * register so lspci -vv reports a realistic generation and width for
     * a modern RDMA NIC. No serdes link is simulated; the values are for
     * enumeration and teaching fidelity only. Defaults are Gen5 x16.
     */
    PCIExpLinkSpeed pcie_speed;
    PCIExpLinkWidth pcie_width;

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

    uint8_t rx_buf[CNUAS_MAX_FRAME];
    uint32_t rx_buf_len;
};

static void cnuas_vnic_update_irq(CnuasVnicState *s)
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

static void cnuas_vnic_tx(CnuasVnicState *s)
{
    uint8_t buf[CNUAS_MAX_FRAME];
    uint64_t addr;
    uint32_t len;

    addr = ((uint64_t)s->tx_addr_hi << 32) | s->tx_addr_lo;
    len = s->tx_len;

    if (len == 0 || len > CNUAS_MAX_FRAME) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuas-vnic: invalid TX len %u\n", len);
        return;
    }

    pci_dma_read(&s->pdev, addr, buf, len);

    if (s->sock_fd >= 0 && s->link_status == LINK_STATUS_UP) {
        ssize_t sent = send(s->sock_fd, buf, len, MSG_NOSIGNAL);
        if (sent < 0) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "cnuas-vnic: TX send failed: %s\n",
                          strerror(errno));
        }
    }

    s->irq_status |= IRQ_TX_COMPLETE;
    cnuas_vnic_update_irq(s);
}

/*
 * Drain one frame from the switch socket into the guest's pre-armed
 * RX buffer and raise an IRQ.  Called both from the QEMU main-loop
 * fd handler (event-driven; correct path) and from a guest read of
 * REG_RX_STATUS (polled; kept as a fallback for guests that haven't
 * yet enabled the IRQ_RX_COMPLETE mask).
 *
 * Returns true if a frame was consumed.  The single-buffer model
 * means we only drain ONE frame per call: the guest must clear
 * rx_status (by writing 0 to REG_RX_STATUS) before the next frame
 * can land.  The fd handler is level-triggered so it will keep
 * firing until the socket is drained, which gives the guest
 * back-pressure that matches a real NIC's RX ring full condition.
 */
static bool cnuas_vnic_drain_one_rx(CnuasVnicState *s)
{
    ssize_t len;
    uint64_t addr;

    if (s->sock_fd < 0) {
        return false;
    }
    if (s->rx_status == RX_STATUS_READY) {
        /*
         * Previous frame not yet consumed by the guest.  Don't
         * pull another off the wire or we'd lose it.
         */
        return false;
    }

    len = recv(s->sock_fd, s->rx_buf, CNUAS_MAX_FRAME, MSG_DONTWAIT);
    if (len <= 0) {
        return false;
    }

    s->rx_buf_len = len;

    addr = ((uint64_t)s->rx_addr_hi << 32) | s->rx_addr_lo;
    if (addr == 0) {
        /*
         * Guest has not posted an RX buffer yet -- drop the frame
         * (matches a real NIC's behaviour with an unarmed ring).
         */
        return true;
    }

    pci_dma_write(&s->pdev, addr, s->rx_buf, len);
    s->rx_len = len;
    s->rx_status = RX_STATUS_READY;

    s->irq_status |= IRQ_RX_COMPLETE;
    cnuas_vnic_update_irq(s);
    return true;
}

static void cnuas_vnic_rx_event(void *opaque)
{
    CnuasVnicState *s = opaque;

    /*
     * The fd handler is level-triggered: if we don't drain or stop
     * watching the socket while rx_status == RX_STATUS_READY, the
     * main loop will busy-spin re-invoking us.  Drain one frame
     * (capacity == 1) and let the next select(2) wake-up arrive
     * after the guest acks REG_RX_STATUS.
     */
    cnuas_vnic_drain_one_rx(s);
}

/* Kept for backwards compat with the polled callsite in
 * cnuas_vnic_mmio_read(REG_RX_STATUS).  The event-driven path
 * above is the canonical one.
 */
static void cnuas_vnic_check_rx(CnuasVnicState *s)
{
    cnuas_vnic_drain_one_rx(s);
}

static uint64_t cnuas_vnic_mmio_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    CnuasVnicState *s = opaque;

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
        cnuas_vnic_check_rx(s);
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
                      "cnuas-vnic: read from unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        return 0;
    }
}

static void cnuas_vnic_mmio_write(void *opaque, hwaddr addr,
                                    uint64_t val, unsigned size)
{
    CnuasVnicState *s = opaque;

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
        cnuas_vnic_tx(s);
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
            /*
             * Guest released the RX buffer: if the socket has
             * another frame already queued, deliver it now.  Saves
             * one wake-up round-trip per packet at high rates.
             */
            cnuas_vnic_drain_one_rx(s);
        }
        break;
    case REG_IRQ_STATUS:
        s->irq_status &= ~val;
        cnuas_vnic_update_irq(s);
        break;
    case REG_IRQ_MASK:
        s->irq_mask = val;
        cnuas_vnic_update_irq(s);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuas-vnic: write to unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        break;
    }
}

static const MemoryRegionOps cnuas_vnic_mmio_ops = {
    .read = cnuas_vnic_mmio_read,
    .write = cnuas_vnic_mmio_write,
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

static int cnuas_vnic_connect(CnuasVnicState *s)
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
                      "cnuas-vnic: socket() failed: %s\n", strerror(errno));
        s->link_status = LINK_STATUS_DOWN;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, s->socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        qemu_log_mask(LOG_UNIMP,
                      "cnuas-vnic: connect(%s) failed: %s\n",
                      s->socket_path, strerror(errno));
        close(fd);
        s->link_status = LINK_STATUS_DOWN;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /*
     * Bump the UDS socket buffers.  The vNIC <-> switch channel
     * has no flow control above the kernel socket buffer: once it
     * fills, send() returns EAGAIN and we silently drop the
     * frame.  At RoCEv2 RC line rate with multi-packet
     * fragmentation a 64 KiB message produces 16 fragments
     * back-to-back, so a default Linux UDS buffer (~208 KiB,
     * ~22 jumbo frames) can fill before NAPI has scheduled the
     * peer's drain handler.  Bump both directions to 8 MiB
     * (~900 jumbo frames) which is enough to absorb the
     * worst-case burst for our perftest gate (tx_depth=128 *
     * nfrags=16 = 2048 frags in flight).
     */
    {
        const int bufsz = 8 * 1024 * 1024;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    }

    s->sock_fd = fd;
    s->link_status = LINK_STATUS_UP;

    /*
     * Hook the socket into the QEMU main loop so we get an RX
     * callback as soon as the switch delivers a frame -- no need
     * for the guest to poll REG_RX_STATUS.  Read-only watch
     * (NULL write handler); level-triggered.
     */
    qemu_set_fd_handler(fd, cnuas_vnic_rx_event, NULL, s);

    return 0;
}

static void cnuas_vnic_realize(PCIDevice *pdev, Error **errp)
{
    CnuasVnicState *s = CNUAS_VNIC(pdev);

    pci_config_set_interrupt_pin(pdev->config, 1);
    msi_init(pdev, 0, 1, true, false, errp);

    if (pcie_endpoint_cap_init(pdev, 0x80) < 0) {
        error_setg(errp, "cnuas-vnic: failed to init PCIe endpoint capability");
        return;
    }
    pcie_cap_fill_link_ep_usp(pdev, s->pcie_width, s->pcie_speed, false);

    memory_region_init_io(&s->mmio, OBJECT(s), &cnuas_vnic_mmio_ops, s,
                          "cnuas-vnic-mmio", CNUAS_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);

    s->sock_fd = -1;
    s->link_status = LINK_STATUS_DOWN;
    s->rx_status = RX_STATUS_EMPTY;
    s->irq_status = 0;
    s->irq_mask = 0;

    /*
     * MAC address resolution.
     *
     *  - If the user passed mac=XX:XX:..  on -device, conf_mac.a is
     *    non-zero and we use it verbatim.
     *  - Otherwise derive a deterministic address from the PCI
     *    devfn so multiple instances never collide:
     *      02:48:43:41:49:<devfn>
     *    The 02: prefix is the OUI locally-administered bit per
     *    IEEE 802; the next 4 bytes spell "HCAI" in ASCII; devfn
     *    keeps it stable across boots.
     */
    if (s->conf_mac.a[0] || s->conf_mac.a[1] || s->conf_mac.a[2] ||
        s->conf_mac.a[3] || s->conf_mac.a[4] || s->conf_mac.a[5]) {
        memcpy(s->mac, s->conf_mac.a, 6);
    } else {
        s->mac[0] = 0x02;
        s->mac[1] = 0x48;
        s->mac[2] = 0x43;
        s->mac[3] = 0x41;
        s->mac[4] = 0x49;
        s->mac[5] = pdev->devfn & 0xff;
    }

    cnuas_vnic_connect(s);
}

static void cnuas_vnic_exit(PCIDevice *pdev)
{
    CnuasVnicState *s = CNUAS_VNIC(pdev);

    if (s->sock_fd >= 0) {
        qemu_set_fd_handler(s->sock_fd, NULL, NULL, NULL);
        close(s->sock_fd);
        s->sock_fd = -1;
    }

    pcie_cap_exit(pdev);
    msi_uninit(pdev);
}

static const Property cnuas_vnic_properties[] = {
    DEFINE_PROP_STRING("socket_path", CnuasVnicState, socket_path),
    DEFINE_PROP_MACADDR("mac", CnuasVnicState, conf_mac),
    DEFINE_PROP_PCIE_LINK_SPEED("x-speed", CnuasVnicState,
                                pcie_speed, PCIE_LINK_SPEED_32),
    DEFINE_PROP_PCIE_LINK_WIDTH("x-width", CnuasVnicState,
                                pcie_width, PCIE_LINK_WIDTH_16),
};

static void cnuas_vnic_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = cnuas_vnic_realize;
    k->exit = cnuas_vnic_exit;
    k->vendor_id = CNUAS_VENDOR_ID;
    k->device_id = CNUAS_DEVICE_ID;
    k->class_id = PCI_CLASS_NETWORK_OTHER;
    k->revision = 0x01;

    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Cnuas RoCE-IB-vNIC (Educational RDMA NIC)";
    device_class_set_props(dc, cnuas_vnic_properties);
}

static const TypeInfo cnuas_vnic_info = {
    .name          = TYPE_CNUAS_VNIC,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(CnuasVnicState),
    .class_init    = cnuas_vnic_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void cnuas_vnic_register_types(void)
{
    type_register_static(&cnuas_vnic_info);
}

type_init(cnuas_vnic_register_types)
