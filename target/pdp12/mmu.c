// SPDX-License-Identifier: GPL-2.0-or-later
/* QEMU PDP-12 MMU address translation walks.
   Copyright (C) 2026 QEMU authors.
   Contributed by Weqaar Janjua. */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "exec/target_page.h"
#include "system/memory.h"

bool pdp12_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr)
{
    PDP12CPU *cpu = PDP12_CPU(cs);
    CPUPDP12State *env = &cpu->env;

    /* Paging disabled (satp mode bit is 0) -> direct address mapping */
    if ((env->satp >> 60) == 0) {
        tlb_set_page(cs, address & TARGET_PAGE_MASK, address & TARGET_PAGE_MASK,
                     PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }

    /* Sv39 3-level walk */
    uint64_t vpn[3] = {
        (address >> 12) & 0x1ff,
        (address >> 21) & 0x1ff,
        (address >> 30) & 0x1ff
    };

    uint64_t base_addr = (env->satp & 0x000fffffffffffffULL) * 4096;
    int i = 2;
    uint64_t pte;
    MemTxResult res;

    for (;;) {
        hwaddr pte_addr = base_addr + vpn[i] * 8;
        pte = address_space_ldq_le(cs->as, pte_addr, MEMTXATTRS_UNSPECIFIED, &res);
        if (res != MEMTX_OK) {
            return false; /* Memory fault */
        }
        if (!(pte & 1)) { /* V (Valid) bit == 0 */
            return false; /* Page Fault */
        }
        if (pte & 0xe) { /* Leaf node found */
            break;
        }
        base_addr = ((pte >> 10) & 0x3ffffffffffULL) * 4096;
        i--;
        if (i < 0) return false;
    }

    /* Perform privilege and permission checks */
    int page_priv = (pte & 8) ? 2 : 0; /* User bit */
    if (mmu_idx == 2 && page_priv == 0) return false; /* Access violation */

    /* Translate to target PA */
    hwaddr pa = (((pte >> 10) & 0x3ffffffffffULL) * 4096) + (address & 0xfff);
    int prot = PAGE_READ | (pte & 4 ? PAGE_WRITE : 0) | (pte & 8 ? PAGE_EXEC : 0);

    tlb_set_page(cs, address & TARGET_PAGE_MASK, pa & TARGET_PAGE_MASK,
                 prot, mmu_idx, TARGET_PAGE_SIZE);
    return true;
}
