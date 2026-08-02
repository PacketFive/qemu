// SPDX-License-Identifier: GPL-2.0-or-later

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"
#include "exec/cputlb.h"
#include "system/runstate.h"

void helper_tlb_flush(CPUPDP12State *env)
{
    pdp12_clear_reservation(env);
    tlb_flush(env_cpu(env));
}

static void stop_at_bound(PDP12CPU *cpu)
{
    CPUState *cs = CPU(cpu);

    cs->halted = 1;
    qemu_system_vmstop_request_prepare();
    qemu_system_vmstop_request(RUN_STATE_PAUSED);
    cpu_loop_exit(cs);
}

void helper_check_stop(CPUPDP12State *env)
{
    PDP12CPU *cpu = env_archcpu(env);

    if (cpu->stop_after_insns &&
        env->retired >= cpu->stop_after_insns) {
        stop_at_bound(cpu);
    }
}

/*
 * P0 Section 7: ip reports the platform-driven software and external sources
 * plus the timer comparison. All three are latched in irq_pending: the timer
 * bit is set whenever time reaches timecmp, either by the timecmp write
 * itself or by the virtual-time deadline the platform arms for it. Reserved
 * bits read as zero.
 */
uint64_t pdp12_pending_interrupts(CPUPDP12State *env)
{
    return env->irq_pending & PDP12_IRQ_MASK;
}

/*
 * P0 Section 7: an interrupt may be taken between retired instructions when
 * pstatus.IE is set and (ip & ie) is nonzero. Source priority is
 * external > timer > software.
 */
bool pdp12_interrupt_selected(CPUPDP12State *env, unsigned int *number)
{
    static const unsigned int priority[] = {
        PDP12_IRQ_EXTERNAL, PDP12_IRQ_TIMER, PDP12_IRQ_SOFTWARE,
    };
    uint64_t enabled;
    unsigned int i;

    if (!(env->pstatus & PSTATUS_IE)) {
        return false;
    }
    enabled = pdp12_pending_interrupts(env) & env->ie & PDP12_IRQ_MASK;
    for (i = 0; i < ARRAY_SIZE(priority); i++) {
        if (enabled & (1ULL << priority[i])) {
            *number = priority[i];
            return true;
        }
    }
    return false;
}

/*
 * P0 Section 9: Trap entry.
 * 1. epc receives the resume address
 * 2. cause and tval receive the trap information
 * 3. pstatus.PPV receives pstatus.PRV
 * 4. pstatus.PIE receives pstatus.IE
 * 5. pstatus.IE becomes zero
 * 6. pstatus.PRV becomes Kernel
 * 7. PC becomes tvec
 *
 * Before changing state, hardware validates that tvec is aligned and
 * executable in Kernel mode on the current physical platform. Failure
 * enters the platform's fatal trap state.
 */
static void pdp12_enter_trap(CPUPDP12State *env, uint64_t cause,
                             uint64_t tval, uint64_t resume_pc)
{
    CPUState *cs = env_cpu(env);
    uint64_t pstatus = env->pstatus;
    PDP12InstructionTargetFault vector_fault;
    uint64_t prv, ie;

    /* A0 Section 12: synchronous and asynchronous trap entry both clear LR. */
    pdp12_clear_reservation(env);
    vector_fault = pdp12_validate_instruction_target(
        env, env->tvec, PDP12_PRV_KERNEL);
    if (vector_fault != PDP12_TARGET_OK) {
        cpu_abort(cs, "PDP-V fatal: tvec 0x%" PRIx64
                  " is not a Kernel executable target (fault=%u) at trap "
                  "cause=%" PRIu64 " pc=0x%" PRIx64,
                  env->tvec, vector_fault, cause, env->pc);
    }

    env->epc = resume_pc;
    env->cause = cause;
    env->tval = tval;

    prv = (pstatus >> PSTATUS_PRV_SHIFT) & 3;
    ie = (pstatus >> 4) & 1;

    pstatus &= ~(PSTATUS_PPV_MASK | PSTATUS_PIE | PSTATUS_IE |
                 PSTATUS_PRV_MASK);
    pstatus |= (prv << PSTATUS_PPV_SHIFT);   /* PPV = old PRV */
    pstatus |= (ie << 5);                    /* PIE = old IE */
    /* IE = 0 and PRV = Kernel = 0 are already cleared */
    env->pstatus = pstatus;

    env->pc = env->tvec;
}

G_NORETURN void pdp12_raise_exception(CPUPDP12State *env,
                                      uint64_t cause, uint64_t tval,
                                      uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);

    /* Synchronize PC from TCG if needed */
    if (retaddr) {
        cpu_restore_state(cs, retaddr);
    }

    pdp12_enter_trap(env, cause, tval, env->pc);
    cpu_loop_exit(cs);
}

void helper_retire(CPUPDP12State *env)
{
    PDP12CPU *cpu = env_archcpu(env);
    unsigned int number;

    env->retired++;

    /*
     * P0 Section 9: an interrupt is taken at this retirement boundary, and
     * epc receives the next instruction's PC, which the translator has
     * already committed to env->pc.
     */
    if (pdp12_interrupt_selected(env, &number)) {
        pdp12_enter_trap(env, PDP12_CAUSE_INTERRUPT | number, 0, env->pc);
        cpu_loop_exit(env_cpu(env));
    }

    if (cpu->stop_after_insns &&
        env->retired >= cpu->stop_after_insns) {
        stop_at_bound(cpu);
    }
}

/*
 * P0 Section 11: WFI is a hint that retires normally and may resume
 * spuriously. The translator emits it after the retirement helper, so any
 * interrupt that was already pending has been taken; parking the hart until
 * a source becomes pending changes no architectural state and stops a
 * firmware idle loop from spinning on the host.
 */
G_NORETURN void helper_wfi(CPUPDP12State *env)
{
    CPUState *cs = env_cpu(env);

    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

G_NORETURN void helper_raise_exception(CPUPDP12State *env,
                                       uint64_t cause, uint64_t tval)
{
    pdp12_raise_exception(env, cause, tval, GETPC());
}

G_NORETURN void helper_illegal(CPUPDP12State *env, uint32_t insn)
{
    pdp12_raise_exception(env, PDP12_CAUSE_ILLEGAL_INSN,
                          (uint64_t)insn, GETPC());
}

/*
 * P0 Section 10 and P1 Section 12: validate all RTE state before committing
 * any of it.  In P39 mode, every aligned translation or access failure is
 * reported as an instruction page fault at the rejected epc.
 */
void helper_rte(CPUPDP12State *env, uint32_t insn)
{
    uint64_t old_pstatus = env->pstatus;
    uint64_t ppv = (old_pstatus & PSTATUS_PPV_MASK) >> PSTATUS_PPV_SHIFT;
    uint64_t epc = env->epc;
    uint64_t new_pstatus;
    uint64_t cause;
    PDP12InstructionTargetFault fault;
    bool p39_active = (env->satp >> 60) == 1;

    if (ppv != PDP12_PRV_KERNEL && ppv != PDP12_PRV_USER) {
        pdp12_raise_exception(env, PDP12_CAUSE_ILLEGAL_INSN,
                              insn, GETPC());
    }

    fault = pdp12_validate_instruction_target(env, epc, ppv);
    if (fault != PDP12_TARGET_OK) {
        if (fault == PDP12_TARGET_MISALIGNED) {
            cause = PDP12_CAUSE_INSN_ADDR_MISALIGNED;
        } else if (p39_active) {
            cause = PDP12_CAUSE_INSN_PAGE_FAULT;
        } else {
            cause = PDP12_CAUSE_INSN_ACCESS_FAULT;
        }
        pdp12_raise_exception(env, cause, epc, GETPC());
    }

    new_pstatus = old_pstatus &
        ~(PSTATUS_PRV_MASK | PSTATUS_PPV_MASK | PSTATUS_IE | PSTATUS_PIE);
    new_pstatus |= ppv << PSTATUS_PRV_SHIFT;
    if (old_pstatus & PSTATUS_PIE) {
        new_pstatus |= PSTATUS_IE;
    }
    new_pstatus |= PSTATUS_PIE;
    new_pstatus |= (uint64_t)PDP12_PRV_USER << PSTATUS_PPV_SHIFT;

    env->pstatus = new_pstatus;
    env->pc = epc;
}

/*
 * satp write validation (P1 Section 3, P0 Section 6).
 * - Bare mode: reserved bits and PPN must be zero.
 * - P39 mode (mode=1): reserved bits [59:44] must be zero.
 * - Any other mode: illegal.
 */
static void pdp12_satp_write(CPUPDP12State *env, uint64_t value, uint32_t insn,
                             uintptr_t retaddr)
{
    uint64_t mode = (value >> 60) & 0xf;
    uint64_t reserved = (value >> 44) & 0xffff;
    uint64_t ppn = value & ((1ULL << 44) - 1);

    if (mode > 1 || reserved != 0 || (mode == 0 && ppn != 0)) {
        pdp12_raise_exception(env, PDP12_CAUSE_ILLEGAL_INSN, insn, retaddr);
    }

    env->satp = value;
    /* A context change cannot preserve physical reservation identity. */
    pdp12_clear_reservation(env);
    tlb_flush(env_cpu(env));
}

/* P0 Section 6 and P1 Section 5: CSR reads. */
uint64_t helper_csr_read(CPUPDP12State *env, uint32_t csr, uint32_t insn)
{
    switch (csr) {
    case PDP12_CSR_PSTATUS:
        return env->pstatus;
    case PDP12_CSR_TVEC:
        return env->tvec;
    case PDP12_CSR_EPC:
        return env->epc;
    case PDP12_CSR_CAUSE:
        return env->cause;
    case PDP12_CSR_TVAL:
        return env->tval;
    case PDP12_CSR_KSCRATCH:
        return env->kscratch;
    case PDP12_CSR_SATP:
        return env->satp;
    case PDP12_CSR_IP:
        return pdp12_pending_interrupts(env);
    case PDP12_CSR_IE:
        return env->ie;
    case PDP12_CSR_HARTID:
        return env->hartid;
    case PDP12_CSR_TIME:
        return pdp12_cpu_read_time(env);
    case PDP12_CSR_TIMECMP:
        return env->timecmp;
    default:
        pdp12_raise_exception(env, PDP12_CAUSE_ILLEGAL_INSN, insn, GETPC());
    }
}

/*
 * P0 Section 6: CSR writes. A write to a fully read-only CSR or to an
 * unimplemented CSR raises illegal-instruction and changes no state; tvec and
 * epc reject unaligned values the same way.
 */
void helper_csr_write(CPUPDP12State *env, uint32_t csr, uint64_t value,
                      uint32_t insn)
{
    uint64_t updated;

    switch (csr) {
    case PDP12_CSR_PSTATUS:
        updated = (env->pstatus & ~(uint64_t)PSTATUS_WRITABLE) |
                  (value & PSTATUS_WRITABLE);
        if ((env->pstatus ^ updated) & (PSTATUS_KUA | PSTATUS_MXR)) {
            /* Effective fetch permissions changed. */
            tlb_flush(env_cpu(env));
        }
        env->pstatus = updated;
        return;
    case PDP12_CSR_TVEC:
    case PDP12_CSR_EPC:
        if (value & 3) {
            pdp12_raise_exception(env, PDP12_CAUSE_ILLEGAL_INSN, insn,
                                  GETPC());
        }
        if (csr == PDP12_CSR_TVEC) {
            env->tvec = value;
        } else {
            env->epc = value;
        }
        return;
    case PDP12_CSR_KSCRATCH:
        env->kscratch = value;
        return;
    case PDP12_CSR_SATP:
        pdp12_satp_write(env, value, insn, GETPC());
        return;
    case PDP12_CSR_IE:
        env->ie = value & PDP12_IRQ_MASK;
        return;
    case PDP12_CSR_TIMECMP:
        pdp12_cpu_set_timecmp(env, value);
        return;
    case PDP12_CSR_CAUSE:
    case PDP12_CSR_TVAL:
    case PDP12_CSR_IP:
    case PDP12_CSR_HARTID:
    case PDP12_CSR_TIME:
    default:
        pdp12_raise_exception(env, PDP12_CAUSE_ILLEGAL_INSN, insn, GETPC());
    }
}

void helper_validate_control_target(CPUPDP12State *env, uint64_t target)
{
    PDP12InstructionTargetFault fault;
    uint64_t cause;
    int mmu_idx;

    mmu_idx = (env->pstatus >> PSTATUS_PRV_SHIFT) & 3;
    fault = pdp12_validate_instruction_target(env, target, mmu_idx);
    switch (fault) {
    case PDP12_TARGET_OK:
        return;
    case PDP12_TARGET_MISALIGNED:
        cause = PDP12_CAUSE_INSN_ADDR_MISALIGNED;
        break;
    case PDP12_TARGET_ACCESS_FAULT:
        cause = PDP12_CAUSE_INSN_ACCESS_FAULT;
        break;
    case PDP12_TARGET_PAGE_FAULT:
        cause = PDP12_CAUSE_INSN_PAGE_FAULT;
        break;
    default:
        g_assert_not_reached();
    }

    pdp12_raise_exception(env, cause, target, GETPC());
}

/*
 * S0 Section 5 and S1 Section 5.2: signed division raises
 * integer-divide-by-zero for a zero divisor and integer-overflow for the
 * minimum value divided by minus one. Both carry tval zero and retire no
 * register, flag or memory state.
 */
uint64_t helper_div_d(CPUPDP12State *env, uint64_t dividend, uint64_t divisor)
{
    if (divisor == 0) {
        pdp12_raise_exception(env, PDP12_CAUSE_DIV_BY_ZERO, 0, GETPC());
    }
    if (dividend == INT64_MIN && divisor == UINT64_MAX) {
        pdp12_raise_exception(env, PDP12_CAUSE_INTEGER_OVERFLOW, 0, GETPC());
    }
    return (uint64_t)((int64_t)dividend / (int64_t)divisor);
}

uint64_t helper_div_w(CPUPDP12State *env, uint64_t dividend, uint64_t divisor)
{
    int32_t a = (int32_t)dividend;
    int32_t b = (int32_t)divisor;

    if (b == 0) {
        pdp12_raise_exception(env, PDP12_CAUSE_DIV_BY_ZERO, 0, GETPC());
    }
    if (a == INT32_MIN && b == -1) {
        pdp12_raise_exception(env, PDP12_CAUSE_INTEGER_OVERFLOW, 0, GETPC());
    }
    return (uint64_t)(int64_t)(a / b);
}
