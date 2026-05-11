/*
 * HiCAIN HiGPU - Virtual GPU PCIe device for QEMU.
 *
 * Phase 1: PCI identifiers, BAR0 (control MMIO), BAR1 (device memory),
 *          MSI.
 * Phase 2 (HiLink): optional SOCK_SEQPACKET connection to
 *          higpu-link-switchd. When enabled, BAR0 exposes TX/RX
 *          rings (single-frame for v1) and the device forwards
 *          HiLink frames between BAR1 and the switch.
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
#include "hw/core/qdev-properties.h"
#include "qom/object.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define TYPE_HICAIN_HIGPU "higpu"
typedef struct HigpuState HigpuState;
DECLARE_INSTANCE_CHECKER(HigpuState, HIGPU, TYPE_HICAIN_HIGPU)

#define HICAIN_VENDOR_ID    0x1ED5
#define HIGPU_DEVICE_ID     0xCA20

#define HIGPU_BAR0_SIZE     (64 * KiB)
#define HIGPU_BAR1_SIZE_DEFAULT  (256 * MiB)
#define HIGPU_LINK_MAX_FRAME (64u * 1024u)

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

/* HiLink ring registers */
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

#define HIGPU_FW_VERSION    0x00010000   /* 0.1.0 */
#define HIGPU_REVISION      0x01

/* IRQ status bits */
#define IRQ_LINK_TX_DONE    (1u << 0)
#define IRQ_LINK_RX_AVAIL   (1u << 1)

/* LINK_STATUS bits */
#define LINK_STATUS_UP        (1u << 0)
#define LINK_STATUS_RX_READY  (1u << 1)

struct HigpuState {
    PCIDevice pdev;
    MemoryRegion bar0;
    MemoryRegion bar1;

    uint32_t gpu_id;
    uint32_t sm_count;
    uint32_t lanes_per_sm;
    uint32_t tensor_size;
    uint64_t devmem_size;

    uint32_t irq_status;
    uint32_t irq_mask;

    /* HiLink */
    char    *hilink_socket;
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

static void higpu_update_irq(HigpuState *s)
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
static void *higpu_bar1_ptr(HigpuState *s, uint64_t off, size_t len)
{
    if (off > s->devmem_size || len > s->devmem_size ||
        off + len > s->devmem_size) {
        return NULL;
    }
    return (uint8_t *)memory_region_get_ram_ptr(&s->bar1) + off;
}

static void higpu_link_disconnect(HigpuState *s)
{
    if (s->sock_fd >= 0) {
        qemu_set_fd_handler(s->sock_fd, NULL, NULL, NULL);
        close(s->sock_fd);
        s->sock_fd = -1;
    }
    s->link_up = false;
    s->link_rx_ready = false;
}

static void higpu_link_rx_ready(void *opaque)
{
    HigpuState *s = opaque;
    uint8_t buf[HIGPU_LINK_MAX_FRAME];

    if (s->link_rx_ready) {
        /* Guest hasn't drained previous frame yet. Pause RX. */
        qemu_set_fd_handler(s->sock_fd, NULL, NULL, NULL);
        return;
    }

    ssize_t n = recv(s->sock_fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n == 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: peer closed socket\n");
        higpu_link_disconnect(s);
        return;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return;
        }
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: recv failed: %s\n", strerror(errno));
        higpu_link_disconnect(s);
        return;
    }

    uint64_t off = ((uint64_t)s->link_rx_off_hi << 32) | s->link_rx_off_lo;
    uint32_t cap = s->link_rx_buf_size;

    if (cap == 0 || (size_t)n > cap) {
        /* Guest hasn't posted a buffer yet, or buffer too small.
         * For v1 we just drop. */
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: dropped RX frame (%zd bytes, "
                      "guest buf=%u)\n", n, cap);
        return;
    }

    void *dst = higpu_bar1_ptr(s, off, (size_t)n);
    if (!dst) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: RX offset 0x%" PRIx64 " + %zd "
                      "exceeds BAR1\n", off, n);
        return;
    }
    memcpy(dst, buf, (size_t)n);

    s->link_rx_len = (uint32_t)n;
    s->link_rx_ready = true;
    s->irq_status |= IRQ_LINK_RX_AVAIL;
    higpu_update_irq(s);
}

static int higpu_link_connect(HigpuState *s)
{
    if (!s->hilink_socket || s->hilink_socket[0] == '\0') {
        return 0;
    }

    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: socket() failed: %s\n",
                      strerror(errno));
        return -1;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (strlen(s->hilink_socket) >= sizeof(addr.sun_path)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: socket path too long: %s\n",
                      s->hilink_socket);
        close(fd);
        return -1;
    }
    strcpy(addr.sun_path, s->hilink_socket);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: connect(%s) failed: %s\n",
                      s->hilink_socket, strerror(errno));
        close(fd);
        return -1;
    }

    s->sock_fd = fd;
    s->link_up = true;
    qemu_set_fd_handler(fd, higpu_link_rx_ready, NULL, s);
    return 0;
}

static void higpu_link_doorbell(HigpuState *s)
{
    if (!s->link_up || s->sock_fd < 0) {
        return;
    }
    uint64_t off = ((uint64_t)s->link_tx_off_hi << 32) | s->link_tx_off_lo;
    uint32_t len = s->link_tx_len;
    if (len == 0 || len > HIGPU_LINK_MAX_FRAME) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: TX bad length %u\n", len);
        return;
    }
    void *src = higpu_bar1_ptr(s, off, len);
    if (!src) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: TX offset 0x%" PRIx64 " + %u "
                      "exceeds BAR1\n", off, len);
        return;
    }

    ssize_t n = send(s->sock_fd, src, len, MSG_NOSIGNAL);
    if (n < 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu/hilink: send failed: %s\n", strerror(errno));
        higpu_link_disconnect(s);
        return;
    }

    s->irq_status |= IRQ_LINK_TX_DONE;
    higpu_update_irq(s);
}

static uint64_t higpu_bar0_read(void *opaque, hwaddr addr, unsigned size)
{
    HigpuState *s = opaque;

    switch (addr) {
    case REG_VENDOR_ID:
        return HICAIN_VENDOR_ID;
    case REG_DEVICE_ID:
        return HIGPU_DEVICE_ID;
    case REG_REVISION:
        return HIGPU_REVISION;
    case REG_FW_VERSION:
        return HIGPU_FW_VERSION;
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
                      "higpu: read from unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        return 0;
    }
}

static void higpu_bar0_write(void *opaque, hwaddr addr,
                             uint64_t val, unsigned size)
{
    HigpuState *s = opaque;

    switch (addr) {
    case REG_IRQ_STATUS:
        s->irq_status &= ~val;
        higpu_update_irq(s);
        break;
    case REG_IRQ_MASK:
        s->irq_mask = val;
        higpu_update_irq(s);
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
            higpu_link_doorbell(s);
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
                qemu_set_fd_handler(s->sock_fd, higpu_link_rx_ready,
                                    NULL, s);
            }
        }
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "higpu: write to unknown reg 0x%" HWADDR_PRIx "\n",
                      addr);
        break;
    }
}

static const MemoryRegionOps higpu_bar0_ops = {
    .read = higpu_bar0_read,
    .write = higpu_bar0_write,
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

static void higpu_realize(PCIDevice *pdev, Error **errp)
{
    HigpuState *s = HIGPU(pdev);

    pci_config_set_interrupt_pin(pdev->config, 1);
    msi_init(pdev, 0, 1, true, false, errp);

    memory_region_init_io(&s->bar0, OBJECT(s), &higpu_bar0_ops, s,
                          "higpu-bar0", HIGPU_BAR0_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar0);

    memory_region_init_ram(&s->bar1, OBJECT(s), "higpu-devmem",
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

    higpu_link_connect(s);
}

static void higpu_exit(PCIDevice *pdev)
{
    HigpuState *s = HIGPU(pdev);
    higpu_link_disconnect(s);
    msi_uninit(pdev);
}

static const Property higpu_properties[] = {
    DEFINE_PROP_UINT32("gpu_id", HigpuState, gpu_id, 0),
    DEFINE_PROP_UINT32("sm_count", HigpuState, sm_count, 16),
    DEFINE_PROP_UINT32("lanes_per_sm", HigpuState, lanes_per_sm, 32),
    DEFINE_PROP_UINT32("tensor_size", HigpuState, tensor_size, 16),
    DEFINE_PROP_UINT64("devmem_size", HigpuState, devmem_size,
                       HIGPU_BAR1_SIZE_DEFAULT),
    DEFINE_PROP_STRING("hilink_socket", HigpuState, hilink_socket),
};

static void higpu_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = higpu_realize;
    k->exit = higpu_exit;
    k->vendor_id = HICAIN_VENDOR_ID;
    k->device_id = HIGPU_DEVICE_ID;
    k->class_id = PCI_CLASS_PROCESSOR_CO;
    k->revision = HIGPU_REVISION;

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "HiCAIN HiGPU (virtual GPU)";
    device_class_set_props(dc, higpu_properties);
}

static const TypeInfo higpu_info = {
    .name          = TYPE_HICAIN_HIGPU,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(HigpuState),
    .class_init    = higpu_class_init,
    .interfaces    = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void higpu_register_types(void)
{
    type_register_static(&higpu_info);
}

type_init(higpu_register_types)
