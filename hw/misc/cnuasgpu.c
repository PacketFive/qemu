/*
 * CnuasGPU - Virtual GPU PCIe device for QEMU.
 *
 * Phase 1: PCI identifiers, BAR0 (control MMIO), BAR1 (device memory),
 *          MSI.
 * Phase 2 (CnuasLink): optional SOCK_SEQPACKET connection to
 *          cnuasgpu-link-switchd. When enabled, BAR0 exposes TX/RX
 *          rings (single-frame for v1) and the device forwards
 *          CnuasLink frames between BAR1 and the switch.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/pcie.h"
#include "qapi/error.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "qom/object.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define TYPE_CNUAS_CNUASGPU "cnuasgpu"
typedef struct CnuasGpuState CnuasGpuState;
DECLARE_INSTANCE_CHECKER(CnuasGpuState, CNUASGPU, TYPE_CNUAS_CNUASGPU)

/*
 * PCI identity.
 *
 * EXPERIMENTAL IDs. cnuasgpu is a purely emulated device, so it uses the Red Hat
 * / Qumranet vendor ID (0x1af4) with a device ID from the range
 * 1af4:10f0-10ff that QEMU reserves for experimental use without registration
 * (see docs/specs/pci-ids.rst). These MUST be replaced with an officially
 * assigned 1b36 device ID (contact the QEMU PCI ID maintainer) before this
 * device is submitted upstream or shipped in a product.
 */
#define CNUAS_VENDOR_ID    PCI_VENDOR_ID_REDHAT_QUMRANET
#define CNUASGPU_DEVICE_ID     0x10F1

#define CNUASGPU_BAR0_SIZE     (64 * KiB)
#define CNUASGPU_BAR1_SIZE_DEFAULT  (256 * MiB)
#define CNUASGPU_LINK_MAX_FRAME (64u * 1024u)

#define REG_VENDOR_ID       0x000
#define REG_DEVICE_ID       0x004
#define REG_REVISION        0x008
#define REG_FW_VERSION      0x00C
#define REG_GPU_ID          0x010
#define REG_SM_COUNT        0x014
#define REG_LANES_PER_SM    0x018
#define REG_TENSOR_SIZE     0x01C
#define REG_DEVMEM_SIZE_LO  0x020
#define REG_DEVMEM_SIZE_HI  0x024
#define REG_IRQ_STATUS      0x100
#define REG_IRQ_MASK        0x104

/* CnuasLink ring registers */
#define REG_LINK_STATUS         0x200  /* RO: bit0=link_up, bit1=rx_ready */
#define REG_LINK_TX_OFFSET_LO   0x204  /* RW: BAR1 offset of TX frame */
#define REG_LINK_TX_OFFSET_HI   0x208
#define REG_LINK_TX_LEN         0x20C  /* RW: TX frame length in bytes */
#define REG_LINK_TX_DOORBELL    0x210  /* WO: write 1 to send */
#define REG_LINK_RX_OFFSET_LO   0x214  /* RW: BAR1 offset for RX landing */
#define REG_LINK_RX_OFFSET_HI   0x218
#define REG_LINK_RX_BUF_SIZE    0x21C  /* RW: max bytes the guest accepted */
#define REG_LINK_RX_LEN         0x220  /* RO: bytes of last received frame */
#define REG_LINK_RX_CONSUME     0x224  /* WO: write 1 after reading RX_LEN */

#define CNUASGPU_FW_VERSION    0x00010000   /* 0.1.0 */
#define CNUASGPU_REVISION      0x01

/* IRQ status bits */
#define IRQ_LINK_TX_DONE    (1u << 0)
#define IRQ_LINK_RX_AVAIL   (1u << 1)

/* LINK_STATUS bits */
#define LINK_STATUS_UP        (1u << 0)
#define LINK_STATUS_RX_READY  (1u << 1)

struct CnuasGpuState {
    PCIDevice pdev;
    MemoryRegion bar0;
    MemoryRegion bar1;

    uint32_t gpu_id;
    uint32_t sm_count;
    uint32_t lanes_per_sm;
    uint32_t tensor_size;
    uint64_t devmem_size;

    /*
     * Advertised PCI Express link, surfaced through the Link Capabilities
     * register so lspci -vv reports a realistic generation and width for a
     * modern accelerator. The link is not simulated; the values exist for
     * enumeration and teaching fidelity. Defaults are Gen5 x16.
     */
    PCIExpLinkSpeed pcie_speed;
    PCIExpLinkWidth pcie_width;

    uint32_t irq_status;
    uint32_t irq_mask;

    /* CnuasLink */
    char    *cnuaslink_socket;
    int      sock_fd;
    bool     link_up;

    uint32_t link_tx_off_lo;
    uint32_t link_tx_off_hi;
    uint32_t link_tx_len;

    uint32_t link_rx_off_lo;
    uint32_t link_rx_off_hi;
    uint32_t link_rx_buf_size;
    uint32_t link_rx_len;
    bool     link_rx_ready;
};

static void cnuasgpu_update_irq(CnuasGpuState *s)
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

/*
 * BAR1 access helpers: BAR1 is RAM-backed, so we can use the
 * MemoryRegion's host pointer for direct reads/writes from the QEMU
 * thread. Bound checks use s->devmem_size.
 */
static void *cnuasgpu_bar1_ptr(CnuasGpuState *s, uint64_t off, size_t len)
{
    if (off > s->devmem_size || len > s->devmem_size ||
        off + len > s->devmem_size) {
        return NULL;
    }
    return (uint8_t *)memory_region_get_ram_ptr(&s->bar1) + off;
}

static void cnuasgpu_link_disconnect(CnuasGpuState *s)
{
    if (s->sock_fd >= 0) {
        qemu_set_fd_handler(s->sock_fd, NULL, NULL, NULL);
        close(s->sock_fd);
        s->sock_fd = -1;
    }
    s->link_up = false;
    s->link_rx_ready = false;
}

static void cnuasgpu_link_rx_ready(void *opaque)
{
    CnuasGpuState *s = opaque;
    uint8_t buf[CNUASGPU_LINK_MAX_FRAME];

    if (s->link_rx_ready) {
        /* Guest hasn't drained previous frame yet. Pause RX. */
        qemu_set_fd_handler(s->sock_fd, NULL, NULL, NULL);
        return;
    }

    ssize_t n = recv(s->sock_fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n == 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: peer closed socket\n");
        cnuasgpu_link_disconnect(s);
        return;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return;
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: recv failed: %s\n", strerror(errno));
        cnuasgpu_link_disconnect(s);
        return;
    }

    uint64_t off = ((uint64_t)s->link_rx_off_hi << 32) | s->link_rx_off_lo;
    uint32_t cap = s->link_rx_buf_size;

    if (cap == 0 || (size_t)n > cap) {
        /* Guest hasn't posted a buffer yet, or buffer too small.
         * For v1 we just drop. */
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: dropped RX frame (%zd bytes, "
                      "guest buf=%u)\n", n, cap);
        return;
    }

    void *dst = cnuasgpu_bar1_ptr(s, off, (size_t)n);
    if (!dst) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: RX offset 0x%" PRIx64 " + %zd "
                      "exceeds BAR1\n", off, n);
        return;
    }
    memcpy(dst, buf, (size_t)n);

    s->link_rx_len = (uint32_t)n;
    s->link_rx_ready = true;
    s->irq_status |= IRQ_LINK_RX_AVAIL;
    cnuasgpu_update_irq(s);
}

static int cnuasgpu_link_connect(CnuasGpuState *s)
{
    if (!s->cnuaslink_socket || s->cnuaslink_socket[0] == '\0') {
        return 0;
    }

    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: socket() failed: %s\n",
                      strerror(errno));
        return -1;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (strlen(s->cnuaslink_socket) >= sizeof(addr.sun_path)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: socket path too long: %s\n",
                      s->cnuaslink_socket);
        close(fd);
        return -1;
    }
    strcpy(addr.sun_path, s->cnuaslink_socket);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: connect(%s) failed: %s\n",
                      s->cnuaslink_socket, strerror(errno));
        close(fd);
        return -1;
    }

    s->sock_fd = fd;
    s->link_up = true;
    qemu_set_fd_handler(fd, cnuasgpu_link_rx_ready, NULL, s);
    return 0;
}

static void cnuasgpu_link_doorbell(CnuasGpuState *s)
{
    if (!s->link_up || s->sock_fd < 0) {
        return;
    }
    uint64_t off = ((uint64_t)s->link_tx_off_hi << 32) | s->link_tx_off_lo;
    uint32_t len = s->link_tx_len;
    if (len == 0 || len > CNUASGPU_LINK_MAX_FRAME) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: TX bad length %u\n", len);
        return;
    }
    void *src = cnuasgpu_bar1_ptr(s, off, len);
    if (!src) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: TX offset 0x%" PRIx64 " + %u "
                      "exceeds BAR1\n", off, len);
        return;
    }

    ssize_t n = send(s->sock_fd, src, len, MSG_NOSIGNAL);
    if (n < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu/cnuaslink: send failed: %s\n", strerror(errno));
        cnuasgpu_link_disconnect(s);
        return;
    }

    s->irq_status |= IRQ_LINK_TX_DONE;
    cnuasgpu_update_irq(s);
}

static uint64_t cnuasgpu_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    CnuasGpuState *s = opaque;

    switch (addr) {
    case REG_VENDOR_ID:
        return CNUAS_VENDOR_ID;
    case REG_DEVICE_ID:
        return CNUASGPU_DEVICE_ID;
    case REG_REVISION:
        return CNUASGPU_REVISION;
    case REG_FW_VERSION:
        return CNUASGPU_FW_VERSION;
    case REG_GPU_ID:
        return s->gpu_id;
    case REG_SM_COUNT:
        return s->sm_count;
    case REG_LANES_PER_SM:
        return s->lanes_per_sm;
    case REG_TENSOR_SIZE:
        return s->tensor_size;
    case REG_DEVMEM_SIZE_LO:
        return (uint32_t)s->devmem_size;
    case REG_DEVMEM_SIZE_HI:
        return (uint32_t)(s->devmem_size >> 32);
    case REG_IRQ_STATUS:
        return s->irq_status;
    case REG_IRQ_MASK:
        return s->irq_mask;
    case REG_LINK_STATUS:
        return (s->link_up ? LINK_STATUS_UP : 0) |
               (s->link_rx_ready ? LINK_STATUS_RX_READY : 0);
    case REG_LINK_TX_OFFSET_LO:
        return s->link_tx_off_lo;
    case REG_LINK_TX_OFFSET_HI:
        return s->link_tx_off_hi;
    case REG_LINK_TX_LEN:
        return s->link_tx_len;
    case REG_LINK_RX_OFFSET_LO:
        return s->link_rx_off_lo;
    case REG_LINK_RX_OFFSET_HI:
        return s->link_rx_off_hi;
    case REG_LINK_RX_BUF_SIZE:
        return s->link_rx_buf_size;
    case REG_LINK_RX_LEN:
        return s->link_rx_len;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu: read from unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        return 0;
    }
}

static void cnuasgpu_bar0_write(void *opaque, hwaddr addr,
                             uint64_t val, unsigned size)
{
    CnuasGpuState *s = opaque;

    switch (addr) {
    case REG_IRQ_STATUS:
        s->irq_status &= ~val;
        cnuasgpu_update_irq(s);
        break;
    case REG_IRQ_MASK:
        s->irq_mask = val;
        cnuasgpu_update_irq(s);
        break;
    case REG_LINK_TX_OFFSET_LO:
        s->link_tx_off_lo = (uint32_t)val;
        break;
    case REG_LINK_TX_OFFSET_HI:
        s->link_tx_off_hi = (uint32_t)val;
        break;
    case REG_LINK_TX_LEN:
        s->link_tx_len = (uint32_t)val;
        break;
    case REG_LINK_TX_DOORBELL:
        if (val) {
            cnuasgpu_link_doorbell(s);
        }
        break;
    case REG_LINK_RX_OFFSET_LO:
        s->link_rx_off_lo = (uint32_t)val;
        break;
    case REG_LINK_RX_OFFSET_HI:
        s->link_rx_off_hi = (uint32_t)val;
        break;
    case REG_LINK_RX_BUF_SIZE:
        s->link_rx_buf_size = (uint32_t)val;
        break;
    case REG_LINK_RX_CONSUME:
        if (val) {
            s->link_rx_ready = false;
            s->link_rx_len = 0;
            if (s->sock_fd >= 0 && s->link_up) {
                qemu_set_fd_handler(s->sock_fd, cnuasgpu_link_rx_ready,
                                    NULL, s);
            }
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "cnuasgpu: write to unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        break;
    }
}

static const MemoryRegionOps cnuasgpu_bar0_ops = {
    .read = cnuasgpu_bar0_read,
    .write = cnuasgpu_bar0_write,
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

static void cnuasgpu_realize(PCIDevice *pdev, Error **errp)
{
    CnuasGpuState *s = CNUASGPU(pdev);

    pci_config_set_interrupt_pin(pdev->config, 1);
    msi_init(pdev, 0, 1, true, false, errp);

    if (pcie_endpoint_cap_init(pdev, 0x80) < 0) {
        error_setg(errp, "cnuasgpu: failed to init PCIe endpoint capability");
        return;
    }
    pcie_cap_fill_link_ep_usp(pdev, s->pcie_width, s->pcie_speed, false);

    memory_region_init_io(&s->bar0, OBJECT(s), &cnuasgpu_bar0_ops, s,
                          "cnuasgpu-bar0", CNUASGPU_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar0);

    memory_region_init_ram(&s->bar1, OBJECT(s), "cnuasgpu-devmem",
                           s->devmem_size, errp);
    if (*errp) {
        return;
    }
    pci_register_bar(pdev, 1,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_PREFETCH,
                     &s->bar1);

    s->irq_status = 0;
    s->irq_mask = 0;
    s->sock_fd = -1;
    s->link_up = false;
    s->link_rx_ready = false;

    cnuasgpu_link_connect(s);
}

static void cnuasgpu_exit(PCIDevice *pdev)
{
    CnuasGpuState *s = CNUASGPU(pdev);
    cnuasgpu_link_disconnect(s);
    pcie_cap_exit(pdev);
    msi_uninit(pdev);
}

static const Property cnuasgpu_properties[] = {
    DEFINE_PROP_UINT32("gpu_id", CnuasGpuState, gpu_id, 0),
    DEFINE_PROP_UINT32("sm_count", CnuasGpuState, sm_count, 16),
    DEFINE_PROP_UINT32("lanes_per_sm", CnuasGpuState, lanes_per_sm, 32),
    DEFINE_PROP_UINT32("tensor_size", CnuasGpuState, tensor_size, 16),
    DEFINE_PROP_UINT64("devmem_size", CnuasGpuState, devmem_size,
                       CNUASGPU_BAR1_SIZE_DEFAULT),
    DEFINE_PROP_STRING("cnuaslink_socket", CnuasGpuState, cnuaslink_socket),
    DEFINE_PROP_PCIE_LINK_SPEED("x-speed", CnuasGpuState,
                                pcie_speed, PCIE_LINK_SPEED_32),
    DEFINE_PROP_PCIE_LINK_WIDTH("x-width", CnuasGpuState,
                                pcie_width, PCIE_LINK_WIDTH_16),
};

static void cnuasgpu_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = cnuasgpu_realize;
    k->exit = cnuasgpu_exit;
    k->vendor_id = CNUAS_VENDOR_ID;
    k->device_id = CNUASGPU_DEVICE_ID;
    k->class_id = PCI_CLASS_PROCESSOR_CO;
    k->revision = CNUASGPU_REVISION;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "CnuasGPU (virtual GPU)";
    device_class_set_props(dc, cnuasgpu_properties);
}

static const TypeInfo cnuasgpu_info = {
    .name          = TYPE_CNUAS_CNUASGPU,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(CnuasGpuState),
    .class_init    = cnuasgpu_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void cnuasgpu_register_types(void)
{
    type_register_static(&cnuasgpu_info);
}

type_init(cnuasgpu_register_types)
