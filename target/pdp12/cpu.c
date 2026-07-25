// SPDX-License-Identifier: GPL-2.0-or-later
/* QEMU PDP-12 CPU Instantiation and reset configurations.
   Copyright (C) 2026 QEMU authors.
   Contributed by Weqaar Janjua. */

#include "qemu/osdep.h"
#include "cpu.h"
#include "migration/vmstate.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ops.h"
#include "hw/resettable.h"

void pdp12_cpu_reset(CPUState *cs)
{
    PDP12CPU *cpu = PDP12_CPU(cs);
    CPUPDP12State *env = &cpu->env;

    memset(env->gprs, 0, sizeof(env->gprs));
    env->pc = 0x00001000;    /* Boot Reset entry vector (Index 0 in SVT) */
    env->pstatus = 0x00;     /* Start in Ring 0 (Kernel Privilege) */
    env->satp = 0;           /* MMU paging disabled on reset */
    env->vcfg = 0;
    env->vl = 0;
    env->svt_base = 0;
}

static ResettablePhases pdp12_cpu_parent_phases;

static void pdp12_cpu_reset_hold(Object *obj, ResetType type)
{
    CPUState *cs = CPU(obj);
    
    if (pdp12_cpu_parent_phases.hold) {
        pdp12_cpu_parent_phases.hold(obj, type);
    }
    pdp12_cpu_reset(cs);
}

static TCGTBCPUState pdp12_get_tb_cpu_state(CPUState *cs)
{
    PDP12CPU *cpu = PDP12_CPU(cs);
    return (TCGTBCPUState){ .pc = cpu->env.pc, .flags = 0 };
}

static void pdp12_cpu_synchronize_from_tb(CPUState *cs,
                                          const TranslationBlock *tb)
{
    if (!(tb_cflags(tb) & CF_PCREL)) {
        PDP12CPU *cpu = PDP12_CPU(cs);
        cpu->env.pc = tb->pc;
    }
}

static void pdp12_restore_state_to_opc(CPUState *cs,
                                       const TranslationBlock *tb,
                                       const uint64_t *data)
{
    PDP12CPU *cpu = PDP12_CPU(cs);
    if (tb_cflags(tb) & CF_PCREL) {
        cpu->env.pc = (cpu->env.pc & TARGET_PAGE_MASK) | data[0];
    } else {
        cpu->env.pc = data[0];
    }
}

static const TCGCPUOps pdp12_tcg_ops = {
    .initialize = pdp12_translate_init,
    .translate_code = pdp12_translate_code,
    .get_tb_cpu_state = pdp12_get_tb_cpu_state,
    .synchronize_from_tb = pdp12_cpu_synchronize_from_tb,
    .restore_state_to_opc = pdp12_restore_state_to_opc,
    .mmu_index = pdp12_cpu_mmu_index,
    .tlb_fill = pdp12_cpu_tlb_fill,
};

static void pdp12_cpu_class_init(ObjectClass *c, const void *data)
{
    ResettableClass *rc = RESETTABLE_CLASS(c);

    resettable_class_set_parent_phases(rc, NULL, pdp12_cpu_reset_hold, NULL,
                                       &pdp12_cpu_parent_phases);

    CPU_CLASS(c)->tcg_ops = &pdp12_tcg_ops;
}

static const TypeInfo pdp12_cpu_type_info = {
    .name = TYPE_PDP12_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(PDP12CPU),
    .class_init = pdp12_cpu_class_init,
};

static void pdp12_cpu_register_types(void)
{
    type_register_static(&pdp12_cpu_type_info);
}

type_init(pdp12_cpu_register_types)

int pdp12_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    PDP12CPU *cpu = PDP12_CPU(cs);
    /* Return privilege index from status: Ring 0 (0), Ring 1 (1), Ring 2 (2) */
    return (cpu->env.pstatus >> 8) & 0x3;
}
