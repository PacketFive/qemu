// SPDX-License-Identifier: GPL-2.0-or-later
/* QEMU PDP-12 Virt Board Initialization and Device Instantiations.
   Copyright (C) 2026 QEMU authors.
   Contributed by Weqaar Janjua. */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "hw/char/serial.h"
#include "hw/char/serial-mm.h"
#include "hw/sysbus.h"
#include "hw/loader.h"
#include "system/system.h"
#include "system/device_tree.h"
#include "system/address-spaces.h"
#include "target/pdp12/cpu.h"
#include "qemu/error-report.h"

typedef struct PDP12VirtState {
    MachineState parent;
    DeviceState *intc;
    void *fdt;
    int fdt_size;
} PDP12VirtState;

#define TYPE_PDP12_VIRT_MACHINE MACHINE_TYPE_NAME("pdp12-virt")
#define PDP12_VIRT_MACHINE(obj) \
    OBJECT_CHECK(PDP12VirtState, (obj), TYPE_PDP12_VIRT_MACHINE)

static void create_fdt(PDP12VirtState *s, const MachineState *mc)
{
    void *fdt = create_device_tree(&s->fdt_size);
    if (!fdt) {
        error_report("create_device_tree() failed");
        exit(1);
    }

    qemu_fdt_setprop_string(fdt, "/", "model", "pdp12-virt");
    qemu_fdt_setprop_string(fdt, "/", "compatible", "pdp12,virt");
    qemu_fdt_setprop_cell(fdt, "/", "#address-cells", 0x2);
    qemu_fdt_setprop_cell(fdt, "/", "#size-cells", 0x2);

    /* CPU node */
    qemu_fdt_add_subnode(fdt, "/cpus");
    qemu_fdt_setprop_cell(fdt, "/cpus", "#address-cells", 1);
    qemu_fdt_setprop_cell(fdt, "/cpus", "#size-cells", 0);
    qemu_fdt_add_subnode(fdt, "/cpus/cpu@0");
    qemu_fdt_setprop_string(fdt, "/cpus/cpu@0", "device_type", "cpu");
    qemu_fdt_setprop_string(fdt, "/cpus/cpu@0", "compatible", "pdp12,cpu");

    /* System Bus and PLIC node */
    qemu_fdt_add_subnode(fdt, "/soc");
    qemu_fdt_setprop_cell(fdt, "/soc", "#address-cells", 2);
    qemu_fdt_setprop_cell(fdt, "/soc", "#size-cells", 2);
    qemu_fdt_setprop_string(fdt, "/soc", "compatible", "simple-bus");

    qemu_fdt_add_subnode(fdt, "/soc/interrupt-controller@10009000");
    qemu_fdt_setprop_string(fdt, "/soc/interrupt-controller@10009000", "compatible", "pdp12,intc");
    qemu_fdt_setprop_cell(fdt, "/soc/interrupt-controller@10009000", "#interrupt-cells", 1);
    qemu_fdt_setprop_cell(fdt, "/soc/interrupt-controller@10009000", "interrupt-controller", 0);

    /* UART node */
    qemu_fdt_add_subnode(fdt, "/soc/serial@10000000");
    qemu_fdt_setprop_string(fdt, "/soc/serial@10000000", "compatible", "ns16550a");
    qemu_fdt_setprop_cells(fdt, "/soc/serial@10000000", "reg", 0x0, 0x10000000, 0x0, 0x1000);
    qemu_fdt_setprop_cell(fdt, "/soc/serial@10000000", "interrupts", 10);

    s->fdt = fdt;
}

static void write_boot_rom(hwaddr rom_addr, hwaddr kernel_entry, hwaddr fdt_addr)
{
    /* Emulate writing boot ROM code */
    uint32_t boot_code[] = {
        0x011e0000 | (fdt_addr & 0x3ff),      /* mov fdt_addr, x11 */
        0x01140000,                          /* mov 0, x10 */
        0x80000000 | (kernel_entry & 0xfff),  /* jmp kernel_entry */
    };
    rom_add_blob_fixed("pdp12.bootrom", boot_code, sizeof(boot_code), rom_addr);
}

static void pdp12_virt_init(MachineState *machine)
{
    PDP12VirtState *s = PDP12_VIRT_MACHINE(machine);
    DeviceState *dev;
    CPUState *cs;

    cs = cpu_create(TYPE_PDP12_CPU);
    
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram, NULL, "pdp12.ram", machine->ram_size, &error_fatal);
    memory_region_add_subregion(sysmem, 0x80000000ULL, ram);

    dev = qdev_new("pdp12-intc");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_connect_irq(SYS_BUS_DEVICE(dev), 0, qdev_get_gpio_in(DEVICE(cs), 0));

    serial_mm_init(sysmem, 0x10000000ULL, 0,
                  qdev_get_gpio_in(dev, 10),
                  115200, serial_hd(0), DEVICE_LITTLE_ENDIAN);

    /* 5. Instantiate NPU Stub Device */
    DeviceState *npu = qdev_new("pdp12-npu");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(npu), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(npu), 0, 0x10008000ULL); /* Physical base */
    sysbus_connect_irq(SYS_BUS_DEVICE(npu), 0, qdev_get_gpio_in(dev, 11)); /* Interrupt vector 11 */

    create_fdt(s, machine);
    write_boot_rom(0x00001000ULL, 0x80000000ULL, 0x84000000ULL);
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
