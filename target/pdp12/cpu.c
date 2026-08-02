// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QEMU PDP-12 CPU Instantiation and reset configurations.
 * Copyright (C) 2026 QEMU authors.
 * Contributed by Weqaar Janjua.
 */

#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "qapi/error.h"
#include "cpu.h"
#include "migration/vmstate.h"
#include "exec/cpu-interrupt.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ops.h"
#include "qemu/main-loop.h"
#include "hw/resettable.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "hw/qdev-properties.h"

static const Property pdp12_cpu_properties[] = {
    DEFINE_PROP_UINT64("stop-after-insns", PDP12CPU, stop_after_insns, 0),
};

static void pdp12_cpu_set_pc(CPUState *cs, vaddr value)
{
    PDP12_CPU(cs)->env.pc = value;
}

static vaddr pdp12_cpu_get_pc(CPUState *cs)
{
    return PDP12_CPU(cs)->env.pc;
}

static void pdp12_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    CPUPDP12State *env = cpu_env(cs);
    int i;

    qemu_fprintf(f, "PC=0x%016" PRIx64 " PSTATUS=0x%016" PRIx64
                 " SATP=0x%016" PRIx64 " TVEC=0x%016" PRIx64
                 " RETIRED=%" PRIu64 "\n",
                 env->pc, env->pstatus, env->satp, env->tvec, env->retired);
    qemu_fprintf(f, "EPC=0x%016" PRIx64 " CAUSE=0x%016" PRIx64
                 " TVAL=0x%016" PRIx64 "\n",
                 env->epc, env->cause, env->tval);
    qemu_fprintf(f, "IE=0x%016" PRIx64 " IP=0x%016" PRIx64
                 " TIME=0x%016" PRIx64 " TIMECMP=0x%016" PRIx64
                 " HARTID=0x%016" PRIx64 " KSCRATCH=0x%016" PRIx64 "\n",
                 env->ie, pdp12_pending_interrupts(env),
                 pdp12_cpu_read_time(env), env->timecmp, env->hartid,
                 env->kscratch);
    for (i = 0; i < 32; i += 4) {
        qemu_fprintf(f,
                     "x%-2d=0x%016" PRIx64 " x%-2d=0x%016" PRIx64
                     " x%-2d=0x%016" PRIx64 " x%-2d=0x%016" PRIx64 "\n",
                     i, i == 0 ? 0 : env->gprs[i],
                     i + 1, env->gprs[i + 1],
                     i + 2, env->gprs[i + 2],
                     i + 3, env->gprs[i + 3]);
    }
}

static bool pdp12_cpu_has_work(CPUState *cs)
{
    CPUPDP12State *env = cpu_env(cs);

    return (pdp12_pending_interrupts(env) & env->ie & PDP12_IRQ_MASK) != 0;
}

/*
 * P0 Section 7 takes interrupts at instruction retirement boundaries, which
 * the retire helper implements exactly. This hook only exists so that an
 * asynchronous platform source leaves the translation-block loop promptly;
 * the architectural entry itself happens at the next retirement.
 */
static bool pdp12_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    return false;
}

/*
 * Platform interrupt plumbing. cpu_interrupt() only forces the execution loop
 * to re-check state; pdp12_interrupt_selected() decides delivery. Sources are
 * raised from device callbacks, from the timer deadline and from CSR helpers
 * running on the vCPU thread, so the lock is taken here when it is not
 * already held.
 */
void pdp12_cpu_update_irq(CPUPDP12State *env)
{
    CPUState *cs = env_cpu(env);

    BQL_LOCK_GUARD();

    if (pdp12_pending_interrupts(env) & env->ie & PDP12_IRQ_MASK) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

void pdp12_cpu_set_software_interrupt(CPUPDP12State *env, bool level)
{
    if (level) {
        env->irq_pending |= 1ULL << PDP12_IRQ_SOFTWARE;
    } else {
        env->irq_pending &= ~(1ULL << PDP12_IRQ_SOFTWARE);
    }
    pdp12_cpu_update_irq(env);
}

/*
 * pdpv-virt v0.1 Section 5: time is a 10 MHz counter advanced by QEMU
 * virtual time, not by retired instructions, and it reads zero at reset.
 * The CSR and the timer MMIO page are the same counter, so both call here.
 */
uint64_t pdp12_cpu_read_time(CPUPDP12State *env)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    if (now <= env->time_base_ns) {
        return 0;
    }
    return (uint64_t)(now - env->time_base_ns) / PDP12_TIMER_NS_PER_TICK;
}

/*
 * Virtual-time deadline at which time reaches @ticks. A comparator the
 * clock cannot reach in a 63-bit nanosecond range never expires, which is
 * how the reset value of 2^64-1 keeps the timer quiet.
 */
static int64_t pdp12_cpu_timer_deadline(CPUPDP12State *env, uint64_t ticks)
{
    uint64_t delay;

    if (ticks > (uint64_t)INT64_MAX / PDP12_TIMER_NS_PER_TICK) {
        return INT64_MAX;
    }
    delay = ticks * PDP12_TIMER_NS_PER_TICK;
    if (delay > (uint64_t)(INT64_MAX - env->time_base_ns)) {
        return INT64_MAX;
    }
    return env->time_base_ns + (int64_t)delay;
}

/*
 * P0 Section 7: the timer source is pending while time is at or past
 * timecmp. The bit is latched here and by the deadline callback so that the
 * hot retirement path never has to read the clock; every write to timecmp
 * re-evaluates it against the current counter.
 */
static void pdp12_cpu_timer_update(CPUPDP12State *env)
{
    PDP12CPU *cpu = env_archcpu(env);

    if (pdp12_cpu_read_time(env) >= env->timecmp) {
        env->irq_pending |= 1ULL << PDP12_IRQ_TIMER;
        if (cpu->timer) {
            timer_del(cpu->timer);
        }
    } else {
        env->irq_pending &= ~(1ULL << PDP12_IRQ_TIMER);
        if (cpu->timer) {
            timer_mod(cpu->timer,
                      pdp12_cpu_timer_deadline(env, env->timecmp));
        }
    }
    pdp12_cpu_update_irq(env);
}

static void pdp12_cpu_timer_expire(void *opaque)
{
    CPUPDP12State *env = &PDP12_CPU(opaque)->env;

    pdp12_cpu_timer_update(env);
}

void pdp12_cpu_set_timecmp(CPUPDP12State *env, uint64_t value)
{
    env->timecmp = value;
    pdp12_cpu_timer_update(env);
}

static vaddr pdp12_pointer_wrap(CPUState *cs, int mmu_idx,
                                vaddr result, vaddr base)
{
    return result;
}

static const struct SysemuCPUOps pdp12_sysemu_ops = {
    .has_work = pdp12_cpu_has_work,
    .get_phys_page_debug = pdp12_cpu_get_phys_page_debug,
};

static void pdp12_cpu_set_irq(void *opaque, int irq, int level)
{
    CPUPDP12State *env = &PDP12_CPU(opaque)->env;

    if (level) {
        env->irq_pending |= 1ULL << PDP12_IRQ_EXTERNAL;
    } else {
        env->irq_pending &= ~(1ULL << PDP12_IRQ_EXTERNAL);
    }
    pdp12_cpu_update_irq(env);
}

static void pdp12_cpu_init(Object *obj)
{
    qdev_init_gpio_in(DEVICE(obj), pdp12_cpu_set_irq, 1);
}

static void pdp12_cpu_realize(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    PDP12CPUClass *pcc = PDP12_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }
    PDP12_CPU(dev)->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                         pdp12_cpu_timer_expire, dev);
    qemu_init_vcpu(cs);
    cpu_reset(cs);
    pcc->parent_realize(dev, errp);
}

/* P0 Section 12: reset enters Kernel mode with previous mode set to User. */
void pdp12_cpu_reset(CPUState *cs)
{
    PDP12CPU *cpu = PDP12_CPU(cs);
    CPUPDP12State *env = &cpu->env;

    memset(env->gprs, 0, sizeof(env->gprs));
    env->pc = PDP12_RESET_VECTOR;   /* pdpv-virt v0.1 Section 4: Boot ROM */
    /* P0 §12: PRV=Kernel(00), PPV=User(10), IE=PIE=NZVC=0 */
    env->pstatus = (uint64_t)PDP12_PRV_USER << PSTATUS_PPV_SHIFT;
    env->satp = 0;           /* MMU paging disabled on reset */
    env->tvec = 0;
    env->epc = 0;
    env->cause = 0;
    env->tval = 0;
    env->kscratch = 0;
    env->ie = 0;
    env->hartid = 0;
    /*
     * pdpv-virt v0.1 Section 4: the counter runs from reset and the
     * comparator starts at its maximum, so no timer interrupt is pending.
     * Rebasing the origin makes time read zero at every cold reset.
     */
    env->time_base_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    env->timecmp = UINT64_MAX;
    env->irq_pending = 0;
    env->retired = 0;
    pdp12_clear_reservation(env);
    env->vcfg = 0;
    env->vl = 0;
    env->svt_base = 0;
    if (cpu->timer) {
        timer_del(cpu->timer);
    }
    pdp12_cpu_update_irq(env);
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
    uint32_t flags = 0;

    flags = FIELD_DP32(flags, TB_FLAGS, MMU_IDX,
                       pdp12_cpu_mmu_index(cs, false));
    return (TCGTBCPUState){ .pc = cpu->env.pc, .flags = flags };
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

/* A0 makes every debugger entry a reservation-losing event. */
static void pdp12_cpu_debug_excp_handler(CPUState *cs)
{
    pdp12_clear_reservation(cpu_env(cs));
}

static const TCGCPUOps pdp12_tcg_ops = {
    .guest_default_memory_order = TCG_MO_ALL,
    .mttcg_supported = false,
    .initialize = pdp12_translate_init,
    .translate_code = pdp12_translate_code,
    .get_tb_cpu_state = pdp12_get_tb_cpu_state,
    .synchronize_from_tb = pdp12_cpu_synchronize_from_tb,
    .restore_state_to_opc = pdp12_restore_state_to_opc,
    .debug_excp_handler = pdp12_cpu_debug_excp_handler,
    .mmu_index = pdp12_cpu_mmu_index,
    .tlb_fill = pdp12_cpu_tlb_fill,
    .cpu_exec_halt = pdp12_cpu_has_work,
    .cpu_exec_interrupt = pdp12_cpu_exec_interrupt,
    .cpu_exec_reset = cpu_reset,
    .pointer_wrap = pdp12_pointer_wrap,
};

/*
 * The profile defines one CPU model, so -cpu accepts the type name and any
 * subclass of it. Without this hook the common CPU code cannot resolve a
 * -cpu argument at all.
 */
static ObjectClass *pdp12_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc = object_class_by_name(cpu_model);

    if (oc == NULL ||
        object_class_dynamic_cast(oc, TYPE_PDP12_CPU) == NULL ||
        object_class_is_abstract(oc)) {
        return NULL;
    }
    return oc;
}

static void pdp12_cpu_class_init(ObjectClass *c, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(c);
    PDP12CPUClass *pcc = PDP12_CPU_CLASS(c);
    ResettableClass *rc = RESETTABLE_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);

    device_class_set_parent_realize(dc, pdp12_cpu_realize,
                                    &pcc->parent_realize);
    device_class_set_props(dc, pdp12_cpu_properties);
    resettable_class_set_parent_phases(rc, NULL, pdp12_cpu_reset_hold, NULL,
                                       &pdp12_cpu_parent_phases);

    cc->class_by_name = pdp12_cpu_class_by_name;
    cc->sysemu_ops = &pdp12_sysemu_ops;
    cc->tcg_ops = &pdp12_tcg_ops;
    cc->set_pc = pdp12_cpu_set_pc;
    cc->get_pc = pdp12_cpu_get_pc;
    cc->dump_state = pdp12_cpu_dump_state;
}

static const TypeInfo pdp12_cpu_type_info = {
    .name = TYPE_PDP12_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(PDP12CPU),
    .instance_align = __alignof(PDP12CPU),
    .class_size = sizeof(PDP12CPUClass),
    .instance_init = pdp12_cpu_init,
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

    /* pstatus.PRV is bits 7:6. PDP-V defines kernel=0 and user=2. */
    return (cpu->env.pstatus >> PSTATUS_PRV_SHIFT) & 0x3;
}
