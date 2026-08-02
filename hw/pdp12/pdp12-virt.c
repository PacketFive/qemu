// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QEMU PDP-12 Virt Board Initialization and Device Instantiations.
 * Copyright (C) 2026 QEMU authors.
 * Contributed by Weqaar Janjua.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "elf.h"
#include "hw/boards.h"
#include "hw/char/serial.h"
#include "hw/char/serial-mm.h"
#include "hw/sysbus.h"
#include "hw/loader.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio-mmio.h"
#include "exec/cpu-interrupt.h"
#include "system/system.h"
#include "system/device_tree.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "target/pdp12/cpu.h"
#include "qemu/error-report.h"
#include "trace/trace-hw_pdp12.h"

#include <libfdt.h>

typedef struct PDP12VirtState {
    MachineState parent;
    DeviceState *intc;
    void *fdt;
    int fdt_size;
    PDP12CPU *boot_cpu;
    hwaddr kernel_entry;
} PDP12VirtState;

#define TYPE_PDP12_VIRT_MACHINE MACHINE_TYPE_NAME("pdp12-virt")
#define PDP12_VIRT_MACHINE(obj) \
    OBJECT_CHECK(PDP12VirtState, (obj), TYPE_PDP12_VIRT_MACHINE)

#define PDP12_ROM_BASE              PDP12_RESET_VECTOR
#define PDP12_ROM_SIZE              0x0000f000ULL
#define PDP12_RAM_BASE              0x80000000ULL
#define PDP12_EARLY_OBJECT_BASE     0x80800000ULL
#define PDP12_EARLY_OBJECT_SIZE     0x00200000ULL
#define PDP12_FDT_ADDR              PDP12_EARLY_OBJECT_BASE
#define PDP12_HANDOFF_ADDR          0x80801000ULL
#define PDP12_HANDOFF_SIZE          72
#define PDP12_HANDOFF_MAGIC         0x46464f4856504450ULL
#define PDP12_HANDOFF_FLAGS         (BIT(0) | BIT(3))
#define PDP12_HANDOFF_INITRAMFS     BIT(1)
#define PDP12_INITRD_ALIGN          0x00001000ULL
#define PDP12_ELF_MACHINE           0xff50
#define PDP12_INTC_BASE             0x0c000000ULL
#define PDP12_INTC_SIZE             0x00100000ULL
#define PDP12_TIMER_BASE            0x02000000ULL
#define PDP12_TIMER_SIZE            0x00001000ULL
#define PDP12_UART_BASE             0x10000000ULL
#define PDP12_UART_SIZE             0x00001000ULL
#define PDP12_UART_CLOCK_HZ         1843200
#define PDP12_UART_BAUD             115200
#define PDP12_UART_IRQ              1
#define PDP12_VIRTIO_BLK_BASE       0x10001000ULL
#define PDP12_VIRTIO_BLK_SIZE       0x00001000ULL
#define PDP12_VIRTIO_BLK_IRQ        2
#define PDP12_PLATFORM_CONTROL_BASE 0x10010000ULL
#define PDP12_PLATFORM_CONTROL_SIZE 0x00001000ULL
#define PDP12_NPU_BASE              0x10008000ULL
#define PDP12_NPU_SIZE              0x00001000ULL
#define PDP12_NPU_IRQ               32
#define PDP12_XIC_PHANDLE           1
#define PDP12_XIC_MAX_SOURCE        255
#define PDP12_XIC_CONTEXT_COUNT     1

typedef struct PDP12LoadRange {
    uint64_t start;
    uint64_t end;
    unsigned int phdr;
} PDP12LoadRange;

static bool pdp12_ranges_overlap(uint64_t first_start, uint64_t first_end,
                                 uint64_t second_start, uint64_t second_end)
{
    return first_start < second_end && second_start < first_end;
}

static bool validate_kernel_elf(const char *filename, ram_addr_t ram_size,
                                size_t fdt_size, uint64_t initrd_start,
                                uint64_t initrd_end,
                                uint64_t *physical_entry)
{
    g_autofree char *image = NULL;
    g_autoptr(GError) error = NULL;
    g_autoptr(GArray) ranges = g_array_new(false, false,
                                           sizeof(PDP12LoadRange));
    const uint8_t *ehdr;
    gsize image_size;
    uint64_t file_size;
    uint64_t phoff;
    uint64_t virtual_entry;
    uint64_t ram_end;
    uint16_t phnum;
    unsigned int i;
    bool found_entry = false;

    if (!g_file_get_contents(filename, &image, &image_size, &error)) {
        error_report("PDP-12: cannot read kernel ELF '%s': %s",
                     filename, error->message);
        return false;
    }
    file_size = image_size;
    ehdr = (const uint8_t *)image;
    if (file_size < sizeof(Elf64_Ehdr) ||
        memcmp(ehdr, ELFMAG, SELFMAG) != 0) {
        error_report("PDP-12: kernel '%s' is not an ELF64 image", filename);
        return false;
    }
    if (ehdr[EI_CLASS] != ELFCLASS64 || ehdr[EI_DATA] != ELFDATA2LSB ||
        ehdr[EI_VERSION] != EV_CURRENT || ehdr[EI_OSABI] != ELFOSABI_NONE ||
        memcmp(ehdr + EI_PAD,
               (uint8_t[EI_NIDENT - EI_PAD]) { 0 },
               EI_NIDENT - EI_PAD) != 0 ||
        lduw_le_p(ehdr + offsetof(Elf64_Ehdr, e_type)) != ET_EXEC ||
        lduw_le_p(ehdr + offsetof(Elf64_Ehdr, e_machine)) !=
            PDP12_ELF_MACHINE ||
        ldl_le_p(ehdr + offsetof(Elf64_Ehdr, e_version)) != EV_CURRENT ||
        ldl_le_p(ehdr + offsetof(Elf64_Ehdr, e_flags)) != 0 ||
        lduw_le_p(ehdr + offsetof(Elf64_Ehdr, e_ehsize)) !=
            sizeof(Elf64_Ehdr) ||
        lduw_le_p(ehdr + offsetof(Elf64_Ehdr, e_phentsize)) !=
            sizeof(Elf64_Phdr)) {
        error_report("PDP-12: kernel '%s' does not match static PDP-V ABI0 "
                     "ELF64 (e_machine 0x%04x)", filename,
                     PDP12_ELF_MACHINE);
        return false;
    }

    phoff = ldq_le_p(ehdr + offsetof(Elf64_Ehdr, e_phoff));
    phnum = lduw_le_p(ehdr + offsetof(Elf64_Ehdr, e_phnum));
    if (phnum == 0 ||
        phoff > file_size ||
        phnum > (file_size - phoff) / sizeof(Elf64_Phdr)) {
        error_report("PDP-12: kernel '%s' has an invalid program-header table",
                     filename);
        return false;
    }
    if (ram_size > UINT64_MAX - PDP12_RAM_BASE) {
        error_report("PDP-12: RAM size overflows the physical address space");
        return false;
    }
    ram_end = PDP12_RAM_BASE + ram_size;
    virtual_entry = ldq_le_p(ehdr + offsetof(Elf64_Ehdr, e_entry));

    for (i = 0; i < phnum; i++) {
        const uint8_t *phdr = ehdr + phoff + i * sizeof(Elf64_Phdr);
        uint32_t type = ldl_le_p(phdr + offsetof(Elf64_Phdr, p_type));
        uint32_t flags;
        uint64_t offset;
        uint64_t vaddr;
        uint64_t paddr;
        uint64_t filesz;
        uint64_t memsz;
        uint64_t align;
        PDP12LoadRange range;
        unsigned int j;

        if (type != PT_LOAD) {
            continue;
        }
        flags = ldl_le_p(phdr + offsetof(Elf64_Phdr, p_flags));
        offset = ldq_le_p(phdr + offsetof(Elf64_Phdr, p_offset));
        vaddr = ldq_le_p(phdr + offsetof(Elf64_Phdr, p_vaddr));
        paddr = ldq_le_p(phdr + offsetof(Elf64_Phdr, p_paddr));
        filesz = ldq_le_p(phdr + offsetof(Elf64_Phdr, p_filesz));
        memsz = ldq_le_p(phdr + offsetof(Elf64_Phdr, p_memsz));
        align = ldq_le_p(phdr + offsetof(Elf64_Phdr, p_align));

        if (filesz > memsz || offset > file_size ||
            filesz > file_size - offset) {
            error_report("PDP-12: PT_LOAD %u has invalid file or memory size",
                         i);
            return false;
        }
        if (align > 1 &&
            ((!is_power_of_2(align)) ||
             ((vaddr - offset) & (align - 1)) != 0 ||
             ((paddr - offset) & (align - 1)) != 0)) {
            error_report("PDP-12: PT_LOAD %u has invalid alignment", i);
            return false;
        }
        if (memsz == 0) {
            continue;
        }
        if (paddr < PDP12_RAM_BASE || paddr >= ram_end ||
            memsz > ram_end - paddr) {
            error_report("PDP-12: PT_LOAD %u [0x%" PRIx64 ",0x%" PRIx64
                         ") is outside RAM", i, paddr,
                         memsz > UINT64_MAX - paddr ? UINT64_MAX :
                         paddr + memsz);
            return false;
        }
        range = (PDP12LoadRange) {
            .start = paddr,
            .end = paddr + memsz,
            .phdr = i,
        };
        for (j = 0; j < ranges->len; j++) {
            PDP12LoadRange *other = &g_array_index(ranges, PDP12LoadRange, j);

            if (pdp12_ranges_overlap(range.start, range.end,
                                     other->start, other->end)) {
                error_report("PDP-12: PT_LOAD %u overlaps PT_LOAD %u",
                             i, other->phdr);
                return false;
            }
        }
        if (pdp12_ranges_overlap(range.start, range.end, PDP12_FDT_ADDR,
                                 PDP12_FDT_ADDR + fdt_size) ||
            pdp12_ranges_overlap(range.start, range.end, PDP12_HANDOFF_ADDR,
                                 PDP12_HANDOFF_ADDR + PDP12_HANDOFF_SIZE) ||
            (initrd_start < initrd_end &&
             pdp12_ranges_overlap(range.start, range.end, initrd_start,
                                  initrd_end))) {
            error_report("PDP-12: PT_LOAD %u overlaps a fixed early "
                         "boot object", i);
            return false;
        }
        g_array_append_val(ranges, range);

        if ((flags & PF_X) && virtual_entry >= vaddr &&
            virtual_entry - vaddr < memsz) {
            uint64_t entry_offset = virtual_entry - vaddr;

            if (found_entry || entry_offset > UINT64_MAX - paddr) {
                error_report("PDP-12: ELF virtual entry has an ambiguous "
                             "physical mapping");
                return false;
            }
            *physical_entry = paddr + entry_offset;
            found_entry = true;
        }
    }

    if (ranges->len == 0) {
        error_report("PDP-12: kernel ELF has no non-empty PT_LOAD segments");
        return false;
    }
    if (!found_entry || (*physical_entry & 3) != 0) {
        error_report("PDP-12: ELF entry is not in an aligned executable "
                     "PT_LOAD segment");
        return false;
    }
    return true;
}

static void create_fdt(PDP12VirtState *s, const MachineState *mc)
{
    void *fdt = create_device_tree(&s->fdt_size);
    g_autofree char *mem_name = NULL;

    if (!fdt) {
        error_report("create_device_tree() failed");
        exit(1);
    }

    qemu_fdt_setprop_string(fdt, "/", "model", "pdp12-virt");
    qemu_fdt_setprop_string(fdt, "/", "compatible", "pdpv,pdpv-virt");
    qemu_fdt_setprop_cell(fdt, "/", "#address-cells", 0x2);
    qemu_fdt_setprop_cell(fdt, "/", "#size-cells", 0x2);

    /* CPU node */
    qemu_fdt_add_subnode(fdt, "/cpus");
    qemu_fdt_setprop_cell(fdt, "/cpus", "#address-cells", 1);
    qemu_fdt_setprop_cell(fdt, "/cpus", "#size-cells", 0);
    qemu_fdt_add_subnode(fdt, "/cpus/cpu@0");
    qemu_fdt_setprop_string(fdt, "/cpus/cpu@0", "device_type", "cpu");
    qemu_fdt_setprop_string(fdt, "/cpus/cpu@0", "compatible", "pdp12,cpu");
    qemu_fdt_setprop_cell(fdt, "/cpus/cpu@0", "reg", 0);

    /* RAM and chosen nodes */
    mem_name = g_strdup_printf("/memory@%" PRIx64,
                               (uint64_t)PDP12_RAM_BASE);
    qemu_fdt_add_subnode(fdt, mem_name);
    qemu_fdt_setprop_string(fdt, mem_name, "device_type", "memory");
    qemu_fdt_setprop_cells(fdt, mem_name, "reg",
                           0, PDP12_RAM_BASE,
                           (uint64_t)mc->ram_size >> 32,
                           (uint32_t)mc->ram_size);
    qemu_fdt_add_subnode(fdt, "/chosen");
    qemu_fdt_setprop_string(fdt, "/chosen", "stdout-path",
                            "/soc/serial@10000000");
    if (mc->kernel_cmdline && mc->kernel_cmdline[0]) {
        qemu_fdt_setprop_string(fdt, "/chosen", "bootargs",
                                mc->kernel_cmdline);
    }

    /* System Bus and PLIC node */
    qemu_fdt_add_subnode(fdt, "/soc");
    qemu_fdt_setprop_cell(fdt, "/soc", "#address-cells", 2);
    qemu_fdt_setprop_cell(fdt, "/soc", "#size-cells", 2);
    qemu_fdt_setprop_string(fdt, "/soc", "compatible", "simple-bus");
    /* Identity mapping: soc child addresses are physical addresses. */
    qemu_fdt_setprop(fdt, "/soc", "ranges", NULL, 0);

    /*
     * pdpv-virt v0.1 Section 12: the external interrupt controller is the
     * XIC and publishes the profile's compatible string, its phandle and
     * its interrupt-cell count.
     */
    qemu_fdt_add_subnode(fdt, "/soc/interrupt-controller@c000000");
    qemu_fdt_setprop_string(fdt,
                            "/soc/interrupt-controller@c000000",
                            "compatible", "pdpv,xic-v1");
    qemu_fdt_setprop_cells(fdt, "/soc/interrupt-controller@c000000", "reg",
                           0x0, PDP12_INTC_BASE, 0x0, PDP12_INTC_SIZE);
    qemu_fdt_setprop_cell(fdt,
                          "/soc/interrupt-controller@c000000",
                          "#interrupt-cells", 2);
    qemu_fdt_setprop(fdt, "/soc/interrupt-controller@c000000",
                     "interrupt-controller", NULL, 0);
    qemu_fdt_setprop_cell(fdt,
                          "/soc/interrupt-controller@c000000",
                          "phandle", PDP12_XIC_PHANDLE);
    qemu_fdt_setprop_cell(fdt,
                          "/soc/interrupt-controller@c000000",
                          "pdpv,maximum-source", PDP12_XIC_MAX_SOURCE);
    qemu_fdt_setprop_cell(fdt,
                          "/soc/interrupt-controller@c000000",
                          "pdpv,context-count", PDP12_XIC_CONTEXT_COUNT);

    /*
     * Timer and IPI node. pdpv-virt v0.1 Section 5 fixes the timebase at
     * 10 MHz and requires the frequency to be published, so the property is
     * derived from the same constant the CPU counter uses.
     */
    qemu_fdt_add_subnode(fdt, "/soc/timer@2000000");
    qemu_fdt_setprop_string(fdt, "/soc/timer@2000000",
                            "compatible", "pdpv,timer-ipi-v1");
    qemu_fdt_setprop_cells(fdt, "/soc/timer@2000000", "reg",
                           0x0, PDP12_TIMER_BASE, 0x0, PDP12_TIMER_SIZE);
    qemu_fdt_setprop_cell(fdt, "/soc/timer@2000000", "timebase-frequency",
                          PDP12_TIMEBASE_HZ);

    /* UART node */
    qemu_fdt_add_subnode(fdt, "/soc/serial@10000000");
    qemu_fdt_setprop_string(fdt, "/soc/serial@10000000",
                            "compatible", "ns16550a");
    qemu_fdt_setprop_cells(fdt, "/soc/serial@10000000", "reg",
                           0x0, PDP12_UART_BASE, 0x0, PDP12_UART_SIZE);
    qemu_fdt_setprop_cell(fdt, "/soc/serial@10000000", "clock-frequency",
                          PDP12_UART_CLOCK_HZ);
    qemu_fdt_setprop_cell(fdt, "/soc/serial@10000000", "current-speed",
                          PDP12_UART_BAUD);
    qemu_fdt_setprop_cell(fdt, "/soc/serial@10000000", "interrupt-parent",
                          PDP12_XIC_PHANDLE);
    qemu_fdt_setprop_cells(fdt, "/soc/serial@10000000", "interrupts",
                           PDP12_UART_IRQ, 0);

    /* Required virtio-block transport at XIC source 2. */
    qemu_fdt_add_subnode(fdt, "/soc/virtio_mmio@10001000");
    qemu_fdt_setprop_string(fdt, "/soc/virtio_mmio@10001000",
                            "compatible", "virtio,mmio");
    qemu_fdt_setprop_cells(fdt, "/soc/virtio_mmio@10001000", "reg",
                           0x0, PDP12_VIRTIO_BLK_BASE,
                           0x0, PDP12_VIRTIO_BLK_SIZE);
    qemu_fdt_setprop_cell(fdt, "/soc/virtio_mmio@10001000",
                          "interrupt-parent", PDP12_XIC_PHANDLE);
    qemu_fdt_setprop_cells(fdt, "/soc/virtio_mmio@10001000", "interrupts",
                           PDP12_VIRTIO_BLK_IRQ, 0);
    qemu_fdt_setprop(fdt, "/soc/virtio_mmio@10001000",
                     "dma-coherent", NULL, 0);

    qemu_fdt_add_subnode(fdt, "/soc/platform-control@10010000");
    qemu_fdt_setprop_string(fdt, "/soc/platform-control@10010000",
                            "compatible",
                            "pdpv,reset-power-hart-start-v1");
    qemu_fdt_setprop_cells(fdt, "/soc/platform-control@10010000", "reg",
                           0x0, PDP12_PLATFORM_CONTROL_BASE,
                           0x0, PDP12_PLATFORM_CONTROL_SIZE);

    /* Existing platform-extension producer, also described with two cells. */
    qemu_fdt_add_subnode(fdt, "/soc/npu@10008000");
    qemu_fdt_setprop_string(fdt, "/soc/npu@10008000",
                            "compatible", "pdp12,npu-stub");
    qemu_fdt_setprop_cells(fdt, "/soc/npu@10008000", "reg",
                           0x0, PDP12_NPU_BASE, 0x0, PDP12_NPU_SIZE);
    qemu_fdt_setprop_cell(fdt, "/soc/npu@10008000", "interrupt-parent",
                          PDP12_XIC_PHANDLE);
    qemu_fdt_setprop_cells(fdt, "/soc/npu@10008000", "interrupts",
                           PDP12_NPU_IRQ, 0);

    s->fdt = fdt;
}

/*
 * cpu_create() realizes the hart without a parent bus, so the CPU is not
 * reachable from the machine reset container and qemu_devices_reset() would
 * never re-run pdp12_cpu_reset(). Every boot mode therefore registers this
 * handler, which restores the architectural reset state of P0 Section 12 and
 * the pdpv-virt v0.1 Section 4 reset vector on cold start and on every
 * system_reset.
 */
static void pdp12_virt_cpu_reset(void *opaque)
{
    CPUState *cs = CPU(opaque);

    cpu_reset(cs);
    cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
}

/*
 * Direct-kernel boot only overrides the post-reset state. Reset handlers run
 * in registration order and pdp12_virt_cpu_reset() is registered first, in
 * pdp12_virt_init(), so the CPU is already in its architectural reset state
 * here and this callback just installs the entry contract.
 */
static void pdp12_direct_kernel_reset(void *opaque)
{
    PDP12VirtState *s = opaque;
    CPUPDP12State *env = &s->boot_cpu->env;

    env->pstatus = (uint64_t)PDP12_PRV_USER << PSTATUS_PPV_SHIFT;
    env->satp = 0;
    env->gprs[10] = 0;
    env->gprs[11] = PDP12_FDT_ADDR;
    env->gprs[12] = PDP12_HANDOFF_ADDR;
    env->pc = s->kernel_entry;

    trace_pdp12_virt_direct_kernel_reset(env->pc, env->gprs[10],
                                         env->gprs[11], env->gprs[12],
                                         env->pstatus, env->satp);
}

static void load_direct_kernel(PDP12VirtState *s, MachineState *machine)
{
    uint8_t handoff[PDP12_HANDOFF_SIZE] = {};
    uint64_t handoff_flags = PDP12_HANDOFF_FLAGS;
    uint64_t initrd_start = 0;
    uint64_t initrd_end = 0;
    uint64_t loader_entry;
    uint64_t physical_entry;
    uint64_t ram_end;
    int64_t initrd_size = 0;
    ssize_t kernel_size;
    int ret;

    /*
     * Install fixed-size placeholders before packing so the packed FDT size
     * used by the layout calculation already includes the initrd properties.
     */
    if (machine->initrd_filename) {
        initrd_size = get_image_size(machine->initrd_filename);
        if (initrd_size <= 0) {
            error_report("PDP-12: cannot read non-empty initrd '%s'",
                         machine->initrd_filename);
            exit(1);
        }
        qemu_fdt_setprop_u64(s->fdt, "/chosen", "linux,initrd-start", 0);
        qemu_fdt_setprop_u64(s->fdt, "/chosen", "linux,initrd-end", 0);
    }

    ret = fdt_pack(s->fdt);
    if (ret < 0) {
        error_report("PDP-12: cannot pack board FDT: %s",
                     fdt_strerror(ret));
        exit(1);
    }
    s->fdt_size = fdt_totalsize(s->fdt);
    if (s->fdt_size <= 0 ||
        s->fdt_size > PDP12_HANDOFF_ADDR - PDP12_FDT_ADDR ||
        PDP12_FDT_ADDR + s->fdt_size >
            PDP12_EARLY_OBJECT_BASE + PDP12_EARLY_OBJECT_SIZE) {
        error_report("PDP-12: packed FDT (%d bytes) does not fit before "
                     "the handoff record in the early boot-object window",
                     s->fdt_size);
        exit(1);
    }
    if (machine->ram_size > UINT64_MAX - PDP12_RAM_BASE) {
        error_report("PDP-12: RAM size overflows the physical address space");
        exit(1);
    }
    ram_end = PDP12_RAM_BASE + machine->ram_size;
    if (PDP12_FDT_ADDR < PDP12_RAM_BASE ||
        PDP12_HANDOFF_ADDR + PDP12_HANDOFF_SIZE > ram_end) {
        error_report("PDP-12: fixed early boot objects are outside RAM");
        exit(1);
    }

    if (machine->initrd_filename) {
        uint64_t first_free = MAX(PDP12_FDT_ADDR + s->fdt_size,
                                  PDP12_HANDOFF_ADDR + PDP12_HANDOFF_SIZE);
        uint64_t early_end = PDP12_EARLY_OBJECT_BASE +
                             PDP12_EARLY_OBJECT_SIZE;

        initrd_start = QEMU_ALIGN_UP(first_free, PDP12_INITRD_ALIGN);
        if (initrd_start < first_free ||
            initrd_start < PDP12_EARLY_OBJECT_BASE ||
            initrd_start > early_end ||
            (uint64_t)initrd_size > early_end - initrd_start) {
            error_report("PDP-12: initrd (%" PRId64 " bytes) does not fit "
                         "in the fixed early boot-object window",
                         initrd_size);
            exit(1);
        }
        initrd_end = initrd_start + initrd_size;
        if (initrd_end > ram_end ||
            pdp12_ranges_overlap(initrd_start, initrd_end, PDP12_FDT_ADDR,
                                 PDP12_FDT_ADDR + s->fdt_size) ||
            pdp12_ranges_overlap(initrd_start, initrd_end,
                                 PDP12_HANDOFF_ADDR,
                                 PDP12_HANDOFF_ADDR + PDP12_HANDOFF_SIZE)) {
            error_report("PDP-12: initrd range is outside RAM or overlaps "
                         "another early boot object");
            exit(1);
        }
        qemu_fdt_setprop_u64(s->fdt, "/chosen", "linux,initrd-start",
                             initrd_start);
        qemu_fdt_setprop_u64(s->fdt, "/chosen", "linux,initrd-end",
                             initrd_end);
        ret = fdt_pack(s->fdt);
        if (ret < 0) {
            error_report("PDP-12: cannot repack initrd FDT: %s",
                         fdt_strerror(ret));
            exit(1);
        }
        s->fdt_size = fdt_totalsize(s->fdt);
        if (PDP12_FDT_ADDR + s->fdt_size > PDP12_HANDOFF_ADDR) {
            error_report("PDP-12: initrd properties make the packed FDT "
                         "overlap the handoff record");
            exit(1);
        }
        handoff_flags |= PDP12_HANDOFF_INITRAMFS;
    }

    if (!validate_kernel_elf(machine->kernel_filename, machine->ram_size,
                             s->fdt_size, initrd_start, initrd_end,
                             &physical_entry)) {
        exit(1);
    }

    kernel_size = load_elf(machine->kernel_filename, NULL, NULL, NULL,
                           &loader_entry, NULL, NULL, NULL, ELFDATA2LSB,
                           PDP12_ELF_MACHINE, 0, 0);
    if (kernel_size <= 0) {
        error_report("PDP-12: could not load kernel ELF '%s': %s",
                     machine->kernel_filename,
                     load_elf_strerror(kernel_size));
        exit(1);
    }
    if (loader_entry != physical_entry) {
        error_report("PDP-12: ELF loader entry 0x%" PRIx64
                     " differs from derived physical entry 0x%" PRIx64,
                     loader_entry, physical_entry);
        exit(1);
    }
    if (machine->initrd_filename &&
        load_image_targphys(machine->initrd_filename, initrd_start,
                            initrd_end - initrd_start) != initrd_size) {
        error_report("PDP-12: could not load initrd '%s'",
                     machine->initrd_filename);
        exit(1);
    }

    stq_le_p(handoff + 0x00, PDP12_HANDOFF_MAGIC);
    stl_le_p(handoff + 0x08, 1);
    stl_le_p(handoff + 0x0c, PDP12_HANDOFF_SIZE);
    stq_le_p(handoff + 0x10, PDP12_FDT_ADDR);
    stq_le_p(handoff + 0x18, initrd_start);
    stq_le_p(handoff + 0x20, initrd_end);
    stq_le_p(handoff + 0x38, handoff_flags);

    rom_add_blob_fixed("pdp12.fdt", s->fdt, s->fdt_size,
                       PDP12_FDT_ADDR);
    rom_add_blob_fixed("pdp12.handoff", handoff, sizeof(handoff),
                       PDP12_HANDOFF_ADDR);

    s->kernel_entry = physical_entry;
    trace_pdp12_virt_direct_kernel_loaded(physical_entry, kernel_size,
                                          PDP12_FDT_ADDR, s->fdt_size,
                                          PDP12_HANDOFF_ADDR,
                                          handoff_flags);
    qemu_register_reset(pdp12_direct_kernel_reset, s);
}

/*
 * pdpv-virt v0.1 Sections 3 and 4: the immutable Boot ROM backs the reset
 * vector, so the first fetch after reset always lands on a real instruction.
 *
 *   0x1000  WFI      park the hart until a source becomes pending
 *   0x1004  BR .-4   resume the wait after a spurious wake-up
 *
 * Both words are architecturally valid C-Type and branch encodings that
 * execute in the Kernel mode reset establishes. Without a kernel to enter,
 * the stub is the whole firmware: the machine reaches a defined idle state
 * instead of trapping into an unmapped vector. Direct-kernel boot overrides
 * the reset PC, so the ROM stays present but unused in that mode.
 */
#define PDP12_ROM_INSN_WFI          0x9a000000u
#define PDP12_ROM_INSN_BR_BACK_ONE  0xc00ffffeu

static void install_boot_rom(MemoryRegion *sysmem)
{
    static const uint32_t boot_code[] = {
        PDP12_ROM_INSN_WFI,
        PDP12_ROM_INSN_BR_BACK_ONE,
    };
    MemoryRegion *rom = g_new(MemoryRegion, 1);
    uint8_t image[sizeof(boot_code)];
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(boot_code); i++) {
        stl_le_p(image + i * sizeof(uint32_t), boot_code[i]);
    }
    memory_region_init_rom(rom, NULL, "pdp12.rom", PDP12_ROM_SIZE,
                           &error_fatal);
    memory_region_add_subregion(sysmem, PDP12_ROM_BASE, rom);
    rom_add_blob_fixed("pdp12.bootrom", image, sizeof(image),
                       PDP12_ROM_BASE);
    trace_pdp12_virt_boot_rom_installed(PDP12_ROM_BASE, PDP12_ROM_SIZE,
                                        sizeof(image));
}

static void pdp12_virt_init(MachineState *machine)
{
    PDP12VirtState *s = PDP12_VIRT_MACHINE(machine);
    DeviceState *dev;
    DeviceState *npu;
    DeviceState *timer;
    DeviceState *virtio;
    DeviceState *platform_control;
    CPUState *cs;
    MemoryRegion *sysmem;
    MemoryRegion *ram;

    cs = cpu_create(TYPE_PDP12_CPU);
    s->boot_cpu = PDP12_CPU(cs);
    /*
     * Registered before any boot-mode handler so that a boot-mode override
     * such as pdp12_direct_kernel_reset() observes a freshly reset CPU.
     */
    qemu_register_reset(pdp12_virt_cpu_reset, s->boot_cpu);

    sysmem = get_system_memory();
    install_boot_rom(sysmem);
    ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, NULL, "pdp12.ram", machine->ram_size,
                           &error_fatal);
    memory_region_add_subregion(sysmem, PDP12_RAM_BASE, ram);

    dev = qdev_new("pdp12-intc");
    object_property_add_child(OBJECT(machine), "xic", OBJECT(dev));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    s->intc = dev;
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, PDP12_INTC_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(dev), 0,
                       qdev_get_gpio_in(DEVICE(cs), 0));

    serial_mm_init(sysmem, PDP12_UART_BASE, 0,
                  qdev_get_gpio_in(dev, PDP12_UART_IRQ),
                  PDP12_UART_BAUD, serial_hd(0), DEVICE_LITTLE_ENDIAN);

    virtio = qdev_new(TYPE_VIRTIO_MMIO);
    qdev_prop_set_bit(virtio, "force-legacy", false);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(virtio), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(virtio), 0, PDP12_VIRTIO_BLK_BASE);
    sysbus_connect_irq(SYS_BUS_DEVICE(virtio), 0,
                       qdev_get_gpio_in(dev, PDP12_VIRTIO_BLK_IRQ));

    platform_control = qdev_new("pdp12-platform-control");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(platform_control), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(platform_control), 0,
                    PDP12_PLATFORM_CONTROL_BASE);

    /* Timer and IPI block (pdpv-virt v0.1 Section 5). */
    timer = qdev_new("pdp12-timer");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(timer), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(timer), 0, PDP12_TIMER_BASE);

    /* 5. Instantiate NPU Stub Device */
    npu = qdev_new("pdp12-npu");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(npu), &error_fatal);
    /* Physical base */
    sysbus_mmio_map(SYS_BUS_DEVICE(npu), 0, PDP12_NPU_BASE);
    /* XIC platform-extension source 32. */
    sysbus_connect_irq(SYS_BUS_DEVICE(npu), 0,
                       qdev_get_gpio_in(dev, PDP12_NPU_IRQ));

    create_fdt(s, machine);
    if (machine->kernel_filename) {
        load_direct_kernel(s, machine);
    } else if (machine->initrd_filename) {
        error_report("PDP-12: -initrd requires -kernel");
        exit(1);
    } else {
        /*
         * pdpv-virt v0.1 Section 10 makes direct-kernel loading a distinct
         * boot mode; without a kernel the machine boots from the ROM the
         * reset vector already covers.
         */
        trace_pdp12_virt_boot_rom_reset(PDP12_ROM_BASE);
    }
}

static void pdp12_virt_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    mc->desc = "DEC PDP-12 64-bit Virt Board";
    mc->init = pdp12_virt_init;
    mc->max_cpus = 1;
    mc->default_ram_size = 512 * MiB;
}

static const TypeInfo pdp12_virt_type_info = {
    .name = TYPE_PDP12_VIRT_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(PDP12VirtState),
    .class_init = pdp12_virt_class_init,
};

static void pdp12_virt_register_types(void)
{
    type_register_static(&pdp12_virt_type_info);
}

type_init(pdp12_virt_register_types)
