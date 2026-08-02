// SPDX-License-Identifier: GPL-2.0-or-later
/* PDP-V P39 page-table walker and architectural data-access path. */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu-common.h"
#include "exec/cputlb.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "qemu/atomic.h"
#include "system/memory.h"
#include "system/ram_addr.h"

#define SATP_MODE_SHIFT 60
#define SATP_MODE_MASK  0xf
#define SATP_PPN_MASK   ((1ULL << 44) - 1)

#define PTE_V           BIT_ULL(0)
#define PTE_R           BIT_ULL(1)
#define PTE_W           BIT_ULL(2)
#define PTE_X           BIT_ULL(3)
#define PTE_U           BIT_ULL(4)
#define PTE_RESERVED    BIT_ULL(5)
#define PTE_A           BIT_ULL(6)
#define PTE_D           BIT_ULL(7)
#define PTE_PPN_MASK    ((1ULL << 44) - 1)
#define PTE_HIGH_MASK   (0x3ffULL << 54)

#define PDP12_A_LR      0
#define PDP12_A_SC      1
#define PDP12_A_SWAP    2
#define PDP12_A_ADD     3
#define PDP12_A_AND     4
#define PDP12_A_OR      5
#define PDP12_A_XOR     6
#define PDP12_A_MIN     7
#define PDP12_A_MAX     8
#define PDP12_A_MINU    9
#define PDP12_A_MAXU    10

/*
 * Reference to the leaf PTE of a completed data translation.
 *
 * P1 Section 8 requires D to be exact and ordered before the triggering
 * store.  The walker reports the leaf it used and whether a store still owes
 * a D update; the data path validates the final transaction, publishes D,
 * and only then issues the physical write.
 */
typedef struct PDP12PteRef {
    hwaddr addr;
    uint64_t value;
    bool valid;
    bool needs_dirty;
} PDP12PteRef;

typedef struct PDP12AtomicMapping {
    MemoryRegion *mr;
    hwaddr offset;
    void *host;
} PDP12AtomicMapping;

void pdp12_clear_reservation(CPUPDP12State *env)
{
    env->reservation_valid = false;
    env->reservation_addr = 0;
    env->reservation_size = 0;
}

void pdp12_invalidate_reservation(CPUPDP12State *env, hwaddr address,
                                  hwaddr size)
{
    uint64_t reservation_end;
    uint64_t write_end;

    if (!env->reservation_valid || size == 0) {
        return;
    }
    reservation_end = env->reservation_addr + env->reservation_size;
    write_end = address + size;
    if (address < reservation_end && env->reservation_addr < write_end) {
        pdp12_clear_reservation(env);
    }
}

static bool p39_canonical(vaddr address)
{
    uint64_t upper = address >> 39;

    return (address & BIT_ULL(38)) ? upper == 0x1ffffff : upper == 0;
}

/*
 * P1 Section 7: Permission checks.
 * - User instruction fetch, load, and store require U=1
 * - Kernel instruction fetch always requires U=0
 * - Kernel data access to U=1 requires pstatus.KUA=1
 * - Kernel data access to U=0 is permitted by privilege
 * - Instruction fetch requires X=1
 * - A load requires R=1, or MXR=1 and X=1
 * - A store requires W=1
 * - KUA never permits Kernel instruction fetch from a User leaf
 */
static bool p39_permissions(uint64_t pte, MMUAccessType access_type,
                            int mmu_idx, uint64_t pstatus)
{
    bool user = (mmu_idx == 2);
    bool pte_user = (pte & PTE_U) != 0;
    bool kua = (pstatus & PSTATUS_KUA) != 0;
    bool mxr = (pstatus & PSTATUS_MXR) != 0;

    if (access_type == MMU_INST_FETCH) {
        /* User fetch requires U=1 and X=1 */
        /* Kernel fetch requires U=0 and X=1 */
        if (!(pte & PTE_X)) {
            return false;
        }
        if (user) {
            return pte_user;
        }
        /* Kernel: KUA never permits fetch from User leaf */
        return !pte_user;
    }

    /* Data access: load or store */
    if (user) {
        /* User data requires U=1 */
        if (!pte_user) {
            return false;
        }
    } else {
        /* Kernel data access */
        if (pte_user) {
            /* Kernel accessing User leaf requires KUA=1 */
            if (!kua) {
                return false;
            }
        }
        /* Kernel accessing Kernel leaf (U=0) is always permitted */
    }

    if (access_type == MMU_DATA_STORE) {
        return (pte & PTE_W) != 0;
    }

    /* Load: requires R=1, or (MXR=1 and X=1) */
    if (pte & PTE_R) {
        return true;
    }
    if (mxr && (pte & PTE_X)) {
        return true;
    }
    return false;
}

/*
 * Effective TLB protection bits considering MXR and KUA.
 * We need to give QEMU softmmu the correct set of protections so
 * that it can handle permission faults correctly.
 */
static int effective_prot(uint64_t pte, int mmu_idx, uint64_t pstatus)
{
    bool user = (mmu_idx == 2);
    bool pte_user = (pte & PTE_U) != 0;
    bool kua = (pstatus & PSTATUS_KUA) != 0;
    bool mxr = (pstatus & PSTATUS_MXR) != 0;
    int prot = 0;

    /* Check if this leaf is accessible at all for this privilege */
    if (user && !pte_user) {
        return 0;
    }
    if (!user && pte_user && !kua) {
        return 0;
    }

    /* Execute: only if X=1 and correct privilege */
    if (pte & PTE_X) {
        if (user && pte_user) {
            prot |= PAGE_EXEC;
        } else if (!user && !pte_user) {
            prot |= PAGE_EXEC;
        }
        /* KUA never allows kernel fetch from user page */
    }

    /* Read: R=1, or MXR=1 and X=1 */
    if (pte & PTE_R) {
        prot |= PAGE_READ;
    } else if (mxr && (pte & PTE_X)) {
        prot |= PAGE_READ;
    }

    /* Write: W=1 */
    if (pte & PTE_W) {
        prot |= PAGE_WRITE;
    }

    return prot;
}

typedef enum PDP12TranslateResult {
    PDP12_TRANSLATE_OK,
    PDP12_TRANSLATE_ACCESS_FAULT,
    PDP12_TRANSLATE_PAGE_FAULT,
} PDP12TranslateResult;

/*
 * P1 Section 5 requires every PTE, not only one needing an A/D update, to
 * reside in normal coherent atomic-capable memory.  ROM, RAM devices and
 * MMIO therefore cannot host page tables.
 *
 * The caller must hold the RCU read lock across both this lookup and the
 * compare-and-swap that uses the returned host pointer.
 */
static void *pdp12_pte_host_ptr(CPUState *cs, hwaddr pte_addr,
                                PDP12AtomicMapping *mapping)
{
    MemoryRegion *mr;
    hwaddr xlat;
    hwaddr len = 8;
    void *host;

    mr = address_space_translate(cs->as, pte_addr, &xlat, &len, true,
                                 MEMTXATTRS_UNSPECIFIED);
    if (len < 8 ||
        !memory_access_is_direct(mr, true, MEMTXATTRS_UNSPECIFIED)) {
        return NULL;
    }
    host = qemu_map_ram_ptr(mr->ram_block, xlat);
    if (mapping) {
        mapping->mr = mr;
        mapping->offset = xlat;
        mapping->host = host;
    }
    return host;
}

/*
 * Direct host writes bypass address_space_write(), so reproduce its RAM
 * dirty accounting and invalidate every translated-code alias intersecting
 * the inclusive RAM-address range.
 */
static void pdp12_ram_write_complete(const PDP12AtomicMapping *mapping,
                                     unsigned int size)
{
    ram_addr_t ram_addr = memory_region_get_ram_addr(mapping->mr) +
                          mapping->offset;
    uint8_t dirty_mask = memory_region_get_dirty_log_mask(mapping->mr);

    if (dirty_mask) {
        dirty_mask = cpu_physical_memory_range_includes_clean(
            ram_addr, size, dirty_mask);
    }
    if (dirty_mask & (1 << DIRTY_MEMORY_CODE)) {
        tb_invalidate_phys_range(NULL, ram_addr, ram_addr + size - 1);
        dirty_mask &= ~(1 << DIRTY_MEMORY_CODE);
    }
    cpu_physical_memory_set_dirty_range(ram_addr, size, dirty_mask);
}

/*
 * Walk the table for @address.  When @debug is set the walk is side-effect
 * free: it publishes no A update and reports no pending D update, so a
 * monitor or debugger inspection never perturbs architectural state.
 */
static PDP12TranslateResult
pdp12_translate_address(CPUPDP12State *env, vaddr address,
                        MMUAccessType access_type, int mmu_idx,
                        hwaddr *physical, int *prot, PDP12PteRef *pte_ref,
                        bool debug)
{
    CPUState *cs = env_cpu(env);
    uint64_t mode = (env->satp >> SATP_MODE_SHIFT) & SATP_MODE_MASK;
    uint64_t vpn[3] = {
        (address >> 12) & 0x1ff,
        (address >> 21) & 0x1ff,
        (address >> 30) & 0x1ff,
    };
    uint64_t table;
    uint64_t pte = 0;
    hwaddr pte_addr = 0;
    hwaddr pa;
    int level;

    /*
     * Held across the whole walk: the flat view, the memory regions it
     * resolves and the RAM blocks behind the host pointers used for the
     * atomic A update are all RCU-protected.
     */
    RCU_READ_LOCK_GUARD();

    if (pte_ref) {
        pte_ref->addr = 0;
        pte_ref->value = 0;
        pte_ref->valid = false;
        pte_ref->needs_dirty = false;
    }

    if (mode == 0) {
        if (address >> 56) {
            return PDP12_TRANSLATE_ACCESS_FAULT;
        }
        pa = address;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        goto translated;
    }

    if (mode != 1) {
        return PDP12_TRANSLATE_ACCESS_FAULT;
    }

    if (!p39_canonical(address)) {
        return PDP12_TRANSLATE_PAGE_FAULT;
    }

restart:
    table = (env->satp & SATP_PPN_MASK) << TARGET_PAGE_BITS;
    for (level = 2; level >= 0; level--) {
        void *host_pte;

        pte_addr = table + vpn[level] * 8;
        if (pte_addr >> TARGET_PHYS_ADDR_SPACE_BITS) {
            return PDP12_TRANSLATE_ACCESS_FAULT;
        }
        host_pte = pdp12_pte_host_ptr(cs, pte_addr, NULL);
        if (host_pte == NULL) {
            return PDP12_TRANSLATE_ACCESS_FAULT;
        }
        pte = le64_to_cpu(qatomic_read((uint64_t *)host_pte));
        if (!(pte & PTE_V) ||
            (pte & (PTE_RESERVED | PTE_HIGH_MASK)) ||
            ((pte & PTE_W) && !(pte & PTE_R))) {
            return PDP12_TRANSLATE_PAGE_FAULT;
        }
        if (pte & (PTE_R | PTE_X)) {
            break;
        }
        if (level == 0 || (pte & (PTE_U | PTE_A | PTE_D))) {
            return PDP12_TRANSLATE_PAGE_FAULT;
        }
        table = ((pte >> 10) & PTE_PPN_MASK) << TARGET_PAGE_BITS;
    }
    if (level < 0) {
        return PDP12_TRANSLATE_PAGE_FAULT;
    }

    if (level > 0) {
        uint64_t low_ppn_mask = (1ULL << (level * 9)) - 1;

        if (((pte >> 10) & PTE_PPN_MASK) & low_ppn_mask) {
            return PDP12_TRANSLATE_PAGE_FAULT;
        }
    }

    if (!p39_permissions(pte, access_type, mmu_idx, env->pstatus)) {
        return PDP12_TRANSLATE_PAGE_FAULT;
    }

    pa = (((pte >> 10) & PTE_PPN_MASK) << TARGET_PAGE_BITS);
    if (level >= 1) {
        pa |= vpn[0] << 12;
    }
    if (level >= 2) {
        pa |= vpn[1] << 21;
    }
    pa |= address & (TARGET_PAGE_SIZE - 1);
    if (pa >> TARGET_PHYS_ADDR_SPACE_BITS) {
        return PDP12_TRANSLATE_ACCESS_FAULT;
    }

    /*
     * A updates (P1 Section 8).  A is hardware-managed through an atomic
     * read-modify-write of the leaf PTE and, unlike D, may be published
     * before a later stage of the same access faults.  The compare-and-swap
     * only commits if memory still holds the value the walk observed; if it
     * changed underneath us another agent rewrote the mapping, so the update
     * is discarded and the walk restarts from the root.  A stale mapping can
     * never be overwritten.
     */
    if (!(pte & PTE_A) && !debug) {
        uint64_t updated = pte | PTE_A;
        PDP12AtomicMapping mapping;
        void *host_pte = pdp12_pte_host_ptr(cs, pte_addr, &mapping);
        uint64_t old_pte;

        if (host_pte == NULL) {
            return PDP12_TRANSLATE_ACCESS_FAULT;
        }
        old_pte = qatomic_cmpxchg((uint64_t *)host_pte,
                                  cpu_to_le64(pte), cpu_to_le64(updated));
        old_pte = le64_to_cpu(old_pte);
        if (old_pte != pte) {
            /* The mapping changed under us; re-walk from the root. */
            goto restart;
        }
        pdp12_ram_write_complete(&mapping, 8);
        /*
         * Hardware A/D updates are physical coherence writes and therefore
         * participate in A0 reservation invalidation.
         */
        pdp12_invalidate_reservation(env, pte_addr, 8);
        pte = updated;
    }

    if (pte_ref && !debug) {
        pte_ref->addr = pte_addr;
        pte_ref->value = pte;
        pte_ref->valid = true;
        pte_ref->needs_dirty = (access_type == MMU_DATA_STORE) &&
                               !(pte & PTE_D);
        if (pte_ref->needs_dirty &&
            pdp12_pte_host_ptr(cs, pte_addr, NULL) == NULL) {
            return PDP12_TRANSLATE_ACCESS_FAULT;
        }
    }

    *prot = effective_prot(pte, mmu_idx, env->pstatus);

translated:
    if (access_type == MMU_INST_FETCH && cpu_physical_memory_is_io(pa)) {
        return PDP12_TRANSLATE_ACCESS_FAULT;
    }
    *physical = pa;
    return PDP12_TRANSLATE_OK;
}

/*
 * Publish D before the architectural store.  A compare-and-swap conflict
 * makes the caller restart the walk before any guest write is issued.
 */
static bool pdp12_publish_dirty(CPUPDP12State *env,
                                const PDP12PteRef *pte_ref,
                                bool invalidate_reservation)
{
    CPUState *cs = env_cpu(env);
    PDP12AtomicMapping mapping;
    void *host_pte;
    uint64_t old_pte;

    if (!pte_ref->needs_dirty) {
        return true;
    }
    RCU_READ_LOCK_GUARD();
    host_pte = pdp12_pte_host_ptr(cs, pte_ref->addr, &mapping);
    if (host_pte == NULL) {
        return false;
    }
    old_pte = qatomic_cmpxchg((uint64_t *)host_pte,
                              cpu_to_le64(pte_ref->value),
                              cpu_to_le64(pte_ref->value | PTE_D));
    if (le64_to_cpu(old_pte) == pte_ref->value) {
        pdp12_ram_write_complete(&mapping, 8);
        if (invalidate_reservation) {
            pdp12_invalidate_reservation(env, pte_ref->addr, 8);
        }
        return true;
    }
    return false;
}

/*
 * A physical transaction which unexpectedly fails after D publication did
 * not perform a write, so it must not leave a newly-created D bit behind.
 * The compare-and-swap avoids clearing a D bit in a PTE concurrently changed
 * by another agent.
 */
static void pdp12_rollback_dirty(CPUPDP12State *env,
                                 const PDP12PteRef *pte_ref)
{
    CPUState *cs = env_cpu(env);
    PDP12AtomicMapping mapping;
    void *host_pte;

    if (!pte_ref->needs_dirty) {
        return;
    }
    RCU_READ_LOCK_GUARD();
    host_pte = pdp12_pte_host_ptr(cs, pte_ref->addr, &mapping);
    if (host_pte != NULL) {
        uint64_t old_pte = qatomic_cmpxchg(
            (uint64_t *)host_pte,
            cpu_to_le64(pte_ref->value | PTE_D),
            cpu_to_le64(pte_ref->value));

        if (le64_to_cpu(old_pte) == (pte_ref->value | PTE_D)) {
            pdp12_ram_write_complete(&mapping, 8);
            pdp12_invalidate_reservation(env, pte_ref->addr, 8);
        }
    }
}

PDP12InstructionTargetFault
pdp12_validate_instruction_target(CPUPDP12State *env, vaddr address,
                                  int mmu_idx)
{
    PDP12TranslateResult result;
    hwaddr physical;
    int prot;

    if (address & 3) {
        return PDP12_TARGET_MISALIGNED;
    }

    result = pdp12_translate_address(env, address, MMU_INST_FETCH, mmu_idx,
                                     &physical, &prot, NULL, false);
    switch (result) {
    case PDP12_TRANSLATE_OK:
        return PDP12_TARGET_OK;
    case PDP12_TRANSLATE_ACCESS_FAULT:
        return PDP12_TARGET_ACCESS_FAULT;
    case PDP12_TRANSLATE_PAGE_FAULT:
        return PDP12_TARGET_PAGE_FAULT;
    default:
        g_assert_not_reached();
    }
}

static uint64_t pdp12_fault_cause(MMUAccessType access_type, bool page_fault)
{
    switch (access_type) {
    case MMU_INST_FETCH:
        return page_fault ? PDP12_CAUSE_INSN_PAGE_FAULT
                          : PDP12_CAUSE_INSN_ACCESS_FAULT;
    case MMU_DATA_LOAD:
        return page_fault ? PDP12_CAUSE_LOAD_PAGE_FAULT
                          : PDP12_CAUSE_LOAD_ACCESS_FAULT;
    case MMU_DATA_STORE:
    default:
        return page_fault ? PDP12_CAUSE_STORE_PAGE_FAULT
                          : PDP12_CAUSE_STORE_ACCESS_FAULT;
    }
}

/*
 * The softmmu TLB carries instruction fetches only.  Guest data accesses use
 * pdp12_data_access() below, which re-walks the page table for every access
 * so that alignment, MMIO legality, physical validation and the exact D
 * update all happen in architectural order.  A translation cache holding
 * successful entries is permitted by P1 Section "translationCache" but is not
 * required, and this model keeps none for data.
 */
bool pdp12_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr)
{
    CPUPDP12State *env = cpu_env(cs);
    PDP12TranslateResult result;
    hwaddr physical;
    uint64_t cause;
    int prot;

    result = pdp12_translate_address(env, address, access_type, mmu_idx,
                                     &physical, &prot, NULL, false);
    if (result != PDP12_TRANSLATE_OK) {
        if (probe) {
            return false;
        }
        cause = pdp12_fault_cause(
            access_type, result == PDP12_TRANSLATE_PAGE_FAULT);
        pdp12_raise_exception(env, cause, address, retaddr);
    }

    tlb_set_page_with_attrs(
        cs, address & TARGET_PAGE_MASK, physical & TARGET_PAGE_MASK,
        (MemTxAttrs) { .user = mmu_idx == PDP12_PRV_USER },
        prot, mmu_idx, TARGET_PAGE_SIZE);
    return true;
}

/*
 * S0 Section 9 and S1 Section 10: a platform with side-effecting MMIO must
 * reject, before the first side effect, any operand form that cannot be
 * restarted safely.  Only the single final transfer of a register-to-memory
 * or memory-to-register move - optionally with one direct displacement - may
 * complete on device memory.  The translator marks those transfers; every
 * other transfer (memory-to-memory moves, read-modify-write operands,
 * autoupdate forms and deferred pointer reads) arrives with MMIO clear and is
 * rejected here with an access fault, before the transaction is issued.
 *
 * The classification reuses QEMU's own address-space decode: a transfer is
 * "normal memory" exactly when the flat view resolves it to a directly
 * accessible RAM region for this direction.
 */
static bool pdp12_physical_access_valid(CPUState *cs, hwaddr pa, int size,
                                        bool is_store, bool mmio_ok,
                                        MemTxAttrs attrs)
{
    MemoryRegion *mr;
    hwaddr xlat;
    hwaddr len = size;

    RCU_READ_LOCK_GUARD();
    mr = address_space_translate(cs->as, pa, &xlat, &len, is_store, attrs);
    if (len < size) {
        return false;
    }
    if (memory_access_is_direct(mr, is_store, attrs)) {
        return true;
    }
    return mmio_ok &&
           memory_region_access_valid(mr, xlat, size, is_store,
                                      attrs);
}

/*
 * The architectural data path.  P1 Section "faultPriority" fixes the order:
 * decode legality (translator), effective-address calculation (translator),
 * alignment, canonicality and translation, physical access validation, and
 * only then the memory transaction.  Alignment is checked here rather than
 * through MemOp flags so that it always precedes translation and always
 * reports the exact byte address in tval.
 */
static uint64_t pdp12_data_access(CPUPDP12State *env, uint64_t address,
                                  uint64_t value, uint32_t desc,
                                  bool is_store, uintptr_t retaddr)
{
    CPUState *cs = env_cpu(env);
    unsigned int size = FIELD_EX32(desc, MEMDESC, SIZE);
    bool mmio_ok = FIELD_EX32(desc, MEMDESC, MMIO) != 0;
    MMUAccessType access_type = is_store ? MMU_DATA_STORE : MMU_DATA_LOAD;
    int mmu_idx = (env->pstatus >> PSTATUS_PRV_SHIFT) & 3;
    MemTxAttrs attrs = { .user = mmu_idx == PDP12_PRV_USER };
    PDP12TranslateResult result;
    PDP12PteRef pte_ref;
    MemTxResult transaction = MEMTX_OK;
    hwaddr physical;
    uint64_t data = 0;
    int prot;

restart:
    /* Alignment. */
    if (address & (size - 1)) {
        pdp12_raise_exception(env,
                              is_store ? PDP12_CAUSE_STORE_ADDR_MISALIGNED
                                       : PDP12_CAUSE_LOAD_ADDR_MISALIGNED,
                              address, retaddr);
    }

    /* Canonicality, translation, permissions and the atomic A update. */
    result = pdp12_translate_address(env, address, access_type, mmu_idx,
                                     &physical, &prot, &pte_ref, false);
    if (result != PDP12_TRANSLATE_OK) {
        pdp12_raise_exception(
            env,
            pdp12_fault_cause(access_type,
                              result == PDP12_TRANSLATE_PAGE_FAULT),
            address, retaddr);
    }

    /* Physical access validation, including S0/S1 MMIO legality. */
    if (!pdp12_physical_access_valid(cs, physical, size, is_store, mmio_ok,
                                     attrs)) {
        pdp12_raise_exception(env,
                              is_store ? PDP12_CAUSE_STORE_ACCESS_FAULT
                                       : PDP12_CAUSE_LOAD_ACCESS_FAULT,
                              address, retaddr);
    }

    /*
     * Publish D before a successful store can become visible.  A conflicting
     * PTE write invalidates the candidate translation, so restart before
     * issuing any guest transaction.
     */
    if (is_store && !pdp12_publish_dirty(env, &pte_ref, true)) {
        goto restart;
    }

    /*
     * If the destination aliases the leaf PTE itself, the guest store follows
     * the hardware RMW in coherence order.  Carry D into the outgoing bytes
     * so that this successful store cannot overwrite its own dirty update.
     */
    if (is_store && pte_ref.valid && pte_ref.addr >= physical &&
        pte_ref.addr - physical < size) {
        value |= PTE_D << ((pte_ref.addr - physical) * 8);
    }

    /* The memory transaction. */
    if (is_store) {
        switch (size) {
        case 1:
            address_space_stb(cs->as, physical, value, attrs, &transaction);
            break;
        case 2:
            address_space_stw_le(cs->as, physical, value,
                                 attrs, &transaction);
            break;
        case 4:
            address_space_stl_le(cs->as, physical, value,
                                 attrs, &transaction);
            break;
        default:
            address_space_stq_le(cs->as, physical, value,
                                 attrs, &transaction);
            break;
        }
    } else {
        switch (size) {
        case 1:
            data = address_space_ldub(cs->as, physical, attrs, &transaction);
            break;
        case 2:
            data = address_space_lduw_le(cs->as, physical,
                                         attrs, &transaction);
            break;
        case 4:
            data = address_space_ldl_le(cs->as, physical,
                                        attrs, &transaction);
            break;
        default:
            data = address_space_ldq_le(cs->as, physical,
                                        attrs, &transaction);
            break;
        }
    }
    if (transaction != MEMTX_OK) {
        if (is_store) {
            pdp12_rollback_dirty(env, &pte_ref);
        }
        pdp12_raise_exception(env,
                              is_store ? PDP12_CAUSE_STORE_ACCESS_FAULT
                                       : PDP12_CAUSE_LOAD_ACCESS_FAULT,
                              address, retaddr);
    }
    if (is_store) {
        pdp12_invalidate_reservation(env, physical, size);
    }
    return data;
}

/*
 * Return a host pointer only for naturally contiguous, writable RAM.  This is
 * A0's normal-coherent-atomic memory class in pdpv-virt: ROM, MMIO, RAM-device
 * regions, and split mappings are rejected before a transaction is issued.
 */
static bool pdp12_atomic_mapping(CPUState *cs, hwaddr address,
                                 unsigned int size,
                                 PDP12AtomicMapping *mapping)
{
    MemoryRegion *mr;
    hwaddr xlat;
    hwaddr len = size;

    RCU_READ_LOCK_GUARD();
    mr = address_space_translate(cs->as, address, &xlat, &len, true,
                                 MEMTXATTRS_UNSPECIFIED);
    if (len < size ||
        !memory_access_is_direct(mr, false, MEMTXATTRS_UNSPECIFIED) ||
        !memory_access_is_direct(mr, true, MEMTXATTRS_UNSPECIFIED)) {
        return false;
    }
    mapping->mr = mr;
    mapping->offset = xlat;
    mapping->host = qemu_map_ram_ptr(mr->ram_block, xlat);
    return true;
}

static uint64_t pdp12_preserve_pte_dirty(uint64_t value, hwaddr physical,
                                         unsigned int size,
                                         const PDP12PteRef *pte_ref)
{
    if (pte_ref->valid && pte_ref->addr >= physical &&
        pte_ref->addr - physical < size) {
        value |= PTE_D << ((pte_ref->addr - physical) * 8);
    }
    return value;
}

static uint64_t pdp12_atomic_new_value(unsigned int operation,
                                       uint64_t old, uint64_t source,
                                       unsigned int bits)
{
    if (bits == 32) {
        old = (uint32_t)old;
        source = (uint32_t)source;
    }

    switch (operation) {
    case PDP12_A_SWAP:
        return source;
    case PDP12_A_ADD:
        return bits == 32 ? (uint32_t)(old + source) : old + source;
    case PDP12_A_AND:
        return old & source;
    case PDP12_A_OR:
        return old | source;
    case PDP12_A_XOR:
        return old ^ source;
    case PDP12_A_MIN:
        if (bits == 32) {
            return (int32_t)old <= (int32_t)source ? old : source;
        }
        return (int64_t)old <= (int64_t)source ? old : source;
    case PDP12_A_MAX:
        if (bits == 32) {
            return (int32_t)old >= (int32_t)source ? old : source;
        }
        return (int64_t)old >= (int64_t)source ? old : source;
    case PDP12_A_MINU:
        return old <= source ? old : source;
    case PDP12_A_MAXU:
        return old >= source ? old : source;
    default:
        g_assert_not_reached();
    }
}

/*
 * PDP-V-A0 architectural atomic path.
 *
 * The CPU is deterministic and single-hart (mttcg_supported=false), while
 * host cmpxchg still makes each RAM RMW one indivisible coherence event with
 * respect to QEMU I/O threads.  We choose exact-width reservation sets and
 * never inject permitted spurious SC failure.  Consequently a conflict-free
 * constrained LR/SC loop makes bounded progress.  The model does not simulate
 * cache lines, store buffers, spontaneous reservation loss, or a second hart.
 * Future coherent devices must call pdp12_invalidate_reservation() for their
 * RAM writes; the current pdpv-virt devices perform no DMA writes.
 */
uint64_t helper_atomic(CPUPDP12State *env, uint64_t address, uint64_t source,
                       uint32_t desc)
{
    CPUState *cs = env_cpu(env);
    unsigned int size = (desc & 1) ? 8 : 4;
    unsigned int bits = size * 8;
    unsigned int operation = (desc >> 1) & 0xf;
    bool is_lr = operation == PDP12_A_LR;
    bool is_sc = operation == PDP12_A_SC;
    MMUAccessType access_type = is_lr ? MMU_DATA_LOAD : MMU_DATA_STORE;
    int mmu_idx = (env->pstatus >> PSTATUS_PRV_SHIFT) & 3;
    PDP12TranslateResult result;
    PDP12PteRef pte_ref;
    PDP12AtomicMapping mapping = { 0 };
    hwaddr physical;
    void *host;
    uint64_t old;
    uint64_t new_value;
    int prot;

restart:
    /* A0 fault priority: alignment precedes translation and region checks. */
    if (address & (size - 1)) {
        pdp12_raise_exception(
            env,
            is_lr ? PDP12_CAUSE_LOAD_ADDR_MISALIGNED
                  : PDP12_CAUSE_STORE_ADDR_MISALIGNED,
            address, GETPC());
    }

    /*
     * LR has load permissions.  SC and AMO have store permissions; P39
     * rejects W-without-R leaves, so a legal store leaf also supplies the
     * read permission required by an RMW.  A may be set here, while D remains
     * deferred until a write is certain to happen.
     */
    result = pdp12_translate_address(env, address, access_type, mmu_idx,
                                     &physical, &prot, &pte_ref, false);
    if (result != PDP12_TRANSLATE_OK) {
        pdp12_raise_exception(
            env,
            pdp12_fault_cause(access_type,
                              result == PDP12_TRANSLATE_PAGE_FAULT),
            address, GETPC());
    }

    if (!pdp12_atomic_mapping(cs, physical, size, &mapping)) {
        pdp12_raise_exception(
            env,
            is_lr ? PDP12_CAUSE_LOAD_ACCESS_FAULT
                  : PDP12_CAUSE_STORE_ACCESS_FAULT,
            address, GETPC());
    }
    host = mapping.host;

    if (is_lr) {
        if (size == 4) {
            old = le32_to_cpu(qatomic_read((uint32_t *)host));
        } else {
            old = le64_to_cpu(qatomic_read((uint64_t *)host));
        }
        env->reservation_addr = physical;
        env->reservation_size = size;
        env->reservation_valid = true;
        return bits == 32 ? (uint64_t)(int64_t)(int32_t)old : old;
    }

    if (is_sc) {
        bool matches = env->reservation_valid &&
                       env->reservation_addr == physical &&
                       env->reservation_size == size;

        if (!matches) {
            pdp12_clear_reservation(env);
            return 1;
        }
        /*
         * A D CAS conflict means the mapping changed before the store.
         * Re-walk while retaining the architectural reservation, then test
         * its physical identity against the new translation.
         */
        /*
         * The D update belongs to this SC attempt.  In particular, when a
         * clean leaf PTE is also the reserved target, its own bookkeeping
         * write must not deterministically defeat every constrained retry.
         * SC clears the reservation explicitly immediately afterwards.
         */
        if (!pdp12_publish_dirty(env, &pte_ref, false)) {
            goto restart;
        }
        /*
         * A D update is itself a coherence write.  The unusual case where
         * the target reservation covers its own leaf PTE must therefore fail
         * without leaving D set.
         */
        matches = env->reservation_valid &&
                  env->reservation_addr == physical &&
                  env->reservation_size == size;
        pdp12_clear_reservation(env);
        if (!matches) {
            pdp12_rollback_dirty(env, &pte_ref);
            return 1;
        }
        if (size == 4) {
            source = pdp12_preserve_pte_dirty(source, physical, size,
                                              &pte_ref);
            qatomic_set((uint32_t *)host, cpu_to_le32((uint32_t)source));
        } else {
            source = pdp12_preserve_pte_dirty(source, physical, size,
                                              &pte_ref);
            qatomic_set((uint64_t *)host, cpu_to_le64(source));
        }
        pdp12_ram_write_complete(&mapping, size);
        return 0;
    }

    if (!pdp12_publish_dirty(env, &pte_ref, true)) {
        goto restart;
    }

    if (size == 4) {
        uint32_t observed = qatomic_read((uint32_t *)host);

        do {
            uint32_t expected = observed;

            old = le32_to_cpu(expected);
            new_value = pdp12_atomic_new_value(operation, old, source, bits);
            new_value = pdp12_preserve_pte_dirty(
                new_value, physical, size, &pte_ref);
            observed = qatomic_cmpxchg((uint32_t *)host, expected,
                                       cpu_to_le32((uint32_t)new_value));
            if (observed == expected) {
                break;
            }
        } while (true);
    } else {
        uint64_t observed = qatomic_read((uint64_t *)host);

        do {
            uint64_t expected = observed;

            old = le64_to_cpu(expected);
            new_value = pdp12_atomic_new_value(operation, old, source, bits);
            new_value = pdp12_preserve_pte_dirty(
                new_value, physical, size, &pte_ref);
            observed = qatomic_cmpxchg((uint64_t *)host, expected,
                                       cpu_to_le64(new_value));
            if (observed == expected) {
                break;
            }
        } while (true);
    }
    pdp12_ram_write_complete(&mapping, size);
    pdp12_invalidate_reservation(env, physical, size);
    return bits == 32 ? (uint64_t)(int64_t)(int32_t)old : old;
}

/*
 * Monitor and debugger address translation. The walk is side-effect free and
 * reports the current mapping for the executing privilege mode.
 */
hwaddr pdp12_cpu_get_phys_page_debug(CPUState *cs, vaddr address)
{
    CPUPDP12State *env = cpu_env(cs);
    hwaddr physical;
    int prot;

    if (pdp12_translate_address(env, address, MMU_DATA_LOAD,
                                pdp12_cpu_mmu_index(cs, false), &physical,
                                &prot, NULL, true) != PDP12_TRANSLATE_OK) {
        return -1;
    }
    return physical;
}

uint64_t helper_load(CPUPDP12State *env, uint64_t address, uint32_t desc)
{
    return pdp12_data_access(env, address, 0, desc, false, GETPC());
}

void helper_store(CPUPDP12State *env, uint64_t address, uint64_t value,
                  uint32_t desc)
{
    pdp12_data_access(env, address, value, desc, true, GETPC());
}
