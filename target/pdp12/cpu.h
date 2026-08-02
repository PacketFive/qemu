/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU PDP-12 CPU Definitions.
 * Copyright (C) 2026 QEMU authors.
 * Contributed by Weqaar Janjua.
 */

#ifndef TARGET_PDP12_CPU_H
#define TARGET_PDP12_CPU_H

#define TARGET_LONG_BITS 64

#include "exec/cpu-defs.h"
#include "cpu-qom.h"
#include "hw/registerfields.h"
#include "qemu/timer.h"

#define TYPE_PDP12_CPU "pdp12-cpu"
#define PDP12_CPU(obj) OBJECT_CHECK(PDP12CPU, (obj), TYPE_PDP12_CPU)
#define CPU_RESOLVING_TYPE TYPE_PDP12_CPU

/* P0 trap cause numbers */
#define PDP12_CAUSE_INSN_ADDR_MISALIGNED   0
#define PDP12_CAUSE_INSN_ACCESS_FAULT      1
#define PDP12_CAUSE_ILLEGAL_INSN           2
#define PDP12_CAUSE_BREAKPOINT             3
#define PDP12_CAUSE_LOAD_ADDR_MISALIGNED   4
#define PDP12_CAUSE_LOAD_ACCESS_FAULT      5
#define PDP12_CAUSE_STORE_ADDR_MISALIGNED  6
#define PDP12_CAUSE_STORE_ACCESS_FAULT     7
#define PDP12_CAUSE_ECALL_FROM_USER        8
#define PDP12_CAUSE_ECALL_FROM_KERNEL      9
#define PDP12_CAUSE_PRIVILEGE_VIOLATION    10
#define PDP12_CAUSE_INSN_PAGE_FAULT       12
#define PDP12_CAUSE_LOAD_PAGE_FAULT       13
#define PDP12_CAUSE_STORE_PAGE_FAULT      14
#define PDP12_CAUSE_DIV_BY_ZERO           16
#define PDP12_CAUSE_INTEGER_OVERFLOW      17

/* P0 Section 8: bit 63 of cause marks an interrupt. */
#define PDP12_CAUSE_INTERRUPT             (1ULL << 63)

/* P0 Section 12: the first fetch after reset is taken from this address. */
#define PDP12_RESET_VECTOR       0x00001000ULL

/*
 * pdpv-virt v0.1 Section 5: the platform timebase is a fixed 10 MHz counter
 * advanced by QEMU virtual time, so one tick is exactly 100 ns. The same
 * constants drive the time CSR, the timer MMIO page and the FDT
 * timebase-frequency the board publishes.
 */
#define PDP12_TIMEBASE_HZ        10000000LL
#define PDP12_TIMER_NS_PER_TICK  (NANOSECONDS_PER_SECOND / PDP12_TIMEBASE_HZ)

/* P0 Section 7: interrupt source numbers and the implemented ip/ie mask. */
#define PDP12_IRQ_SOFTWARE  1
#define PDP12_IRQ_TIMER     5
#define PDP12_IRQ_EXTERNAL  9
#define PDP12_IRQ_MASK      ((1ULL << PDP12_IRQ_SOFTWARE) | \
                             (1ULL << PDP12_IRQ_TIMER) | \
                             (1ULL << PDP12_IRQ_EXTERNAL))

/* P0 Section 6: implemented CSR numbers. */
#define PDP12_CSR_PSTATUS   0x000
#define PDP12_CSR_TVEC      0x001
#define PDP12_CSR_EPC       0x002
#define PDP12_CSR_CAUSE     0x003
#define PDP12_CSR_TVAL      0x004
#define PDP12_CSR_KSCRATCH  0x005
#define PDP12_CSR_SATP      0x006
#define PDP12_CSR_IP        0x007
#define PDP12_CSR_IE        0x008
#define PDP12_CSR_HARTID    0x009
#define PDP12_CSR_TIME      0x00a
#define PDP12_CSR_TIMECMP   0x00b

/* pstatus bit definitions */
#define PSTATUS_C     BIT(0)
#define PSTATUS_V     BIT(1)
#define PSTATUS_Z     BIT(2)
#define PSTATUS_N     BIT(3)
#define PSTATUS_IE    BIT(4)
#define PSTATUS_PIE   BIT(5)
#define PSTATUS_PRV_SHIFT  6
#define PSTATUS_PRV_MASK   (3ULL << 6)
#define PSTATUS_PPV_SHIFT  8
#define PSTATUS_PPV_MASK   (3ULL << 8)
#define PSTATUS_KUA   BIT(10)
#define PSTATUS_MXR   BIT(11)
#define PSTATUS_NZVC  (PSTATUS_N | PSTATUS_Z | PSTATUS_V | PSTATUS_C)

/* Writable bits via CSR write: NZVC, IE, PIE, KUA, MXR */
#define PSTATUS_WRITABLE 0xc3f

/* Privilege modes */
#define PDP12_PRV_KERNEL 0
#define PDP12_PRV_USER   2

FIELD(TB_FLAGS, MMU_IDX, 0, 2)

/*
 * Descriptor passed from the translator to the data-access helpers.
 *
 * SIZE is the final data width in bytes (1, 2, 4 or 8).  MMIO records
 * whether S0 Section 9 and S1 Section 10 permit this particular transfer to
 * complete on side-effecting device memory: only the single final transfer
 * of a register-to-memory or memory-to-register move, addressed without
 * autoupdate and without a deferred pointer read, may do so.
 */
FIELD(MEMDESC, SIZE, 0, 4)
FIELD(MEMDESC, MMIO, 4, 1)

typedef enum PDP12InstructionTargetFault {
    PDP12_TARGET_OK,
    PDP12_TARGET_MISALIGNED,
    PDP12_TARGET_ACCESS_FAULT,
    PDP12_TARGET_PAGE_FAULT,
} PDP12InstructionTargetFault;

typedef struct CPUArchState {
    uint64_t gprs[32];     /* General-purpose registers x0 - x31 */
    uint64_t pc;           /* Program Counter */
    uint64_t pstatus;      /* Privilege / ALU status register */
    uint64_t satp;         /* P39 MMU root pointer */
    uint64_t tvec;         /* Trap vector */
    uint64_t ie;           /* Interrupt-enable mask */
    uint64_t epc;          /* Exception saved PC */
    uint64_t cause;        /* Trap cause */
    uint64_t tval;         /* Trap fault-specific value */
    uint64_t kscratch;     /* Kernel scratch */
    uint64_t hartid;       /* Hardware-thread identifier */
    int64_t time_base_ns;  /* Virtual-time origin of the P0 time CSR */
    uint64_t timecmp;      /* Timer comparator (P0 timecmp CSR) */
    uint64_t irq_pending;  /* Latched ip bits (software, timer, external) */
    uint64_t vcfg;         /* Vector Configuration CSR */
    uint64_t vl;           /* Active Vector Length CSR */
    uint64_t svt_base;     /* System Vector Table base register */
    uint64_t retired;      /* Debug-visible retired instruction count */

    /* Internal emulation helpers */
    uint64_t sp_bank[3];   /* Banked Stack Pointers for Ring 0, 1, 2 */
    /*
     * A0 uses physical reservation identity.  This implementation chooses
     * the smallest permitted reservation set (the naturally aligned access
     * itself), so address/size also describe the set.
     */
    uint64_t reservation_addr;
    uint8_t reservation_size;
    bool reservation_valid;
} CPUPDP12State;

struct ArchCPU {
    CPUState parent_obj;
    CPUPDP12State env;
    uint64_t stop_after_insns;
    QEMUTimer *timer;      /* timecmp deadline in QEMU virtual time */
};

void pdp12_cpu_reset(CPUState *cs);
hwaddr pdp12_cpu_get_phys_page_debug(CPUState *cs, vaddr address);
int pdp12_cpu_mmu_index(CPUState *cs, bool ifetch);
bool pdp12_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr);
PDP12InstructionTargetFault
pdp12_validate_instruction_target(CPUPDP12State *env, vaddr address,
                                  int mmu_idx);
G_NORETURN void pdp12_raise_exception(CPUPDP12State *env, uint64_t cause,
                                      uint64_t tval, uintptr_t retaddr);
uint64_t pdp12_pending_interrupts(CPUPDP12State *env);
uint64_t pdp12_cpu_read_time(CPUPDP12State *env);
bool pdp12_interrupt_selected(CPUPDP12State *env, unsigned int *number);
void pdp12_cpu_update_irq(CPUPDP12State *env);
void pdp12_cpu_set_software_interrupt(CPUPDP12State *env, bool level);
void pdp12_cpu_set_timecmp(CPUPDP12State *env, uint64_t value);
void pdp12_clear_reservation(CPUPDP12State *env);
void pdp12_invalidate_reservation(CPUPDP12State *env, hwaddr address,
                                  hwaddr size);
void pdp12_translate_init(void);
void pdp12_translate_code(CPUState *cs, TranslationBlock *tb,
                          int *max_insns, vaddr pc, void *host_pc);

#endif /* TARGET_PDP12_CPU_H */
