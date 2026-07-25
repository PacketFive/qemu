/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QEMU PDP-12 CPU Definitions.
   Copyright (C) 2026 QEMU authors.
   Contributed by Weqaar Janjua. */

#ifndef TARGET_PDP12_CPU_H
#define TARGET_PDP12_CPU_H

#define TARGET_LONG_BITS 64

#include "exec/cpu-defs.h"
#include "cpu-qom.h"

#define TYPE_PDP12_CPU "pdp12-cpu"
#define PDP12_CPU(obj) OBJECT_CHECK(PDP12CPU, (obj), TYPE_PDP12_CPU)
#define CPU_RESOLVING_TYPE TYPE_PDP12_CPU

typedef struct CPUArchState {
    uint64_t gprs[32];     /* General-purpose registers x0 - x31 */
    uint64_t pc;           /* Program Counter */
    uint64_t pstatus;      /* Privilege / ALU status register */
    uint64_t satp;         /* Sv39 MMU root pointer */
    uint64_t vcfg;         /* Vector Configuration CSR */
    uint64_t vl;           /* Active Vector Length CSR */
    uint64_t svt_base;     /* System Vector Table base register */
    uint64_t sepc;         /* Exception saved PC */

    /* Internal emulation helpers */
    uint64_t sp_bank[3];   /* Banked Stack Pointers for Ring 0, 1, 2 */
} CPUPDP12State;

struct ArchCPU {
    CPUState parent_obj;
    CPUPDP12State env;
};

void pdp12_cpu_reset(CPUState *cs);
int pdp12_cpu_mmu_index(CPUState *cs, bool ifetch);
bool pdp12_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr);
void pdp12_translate_init(void);
void pdp12_translate_code(CPUState *cs, TranslationBlock *tb,
                          int *max_insns, vaddr pc, void *host_pc);

#endif /* TARGET_PDP12_CPU_H */
