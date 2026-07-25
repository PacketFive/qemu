// SPDX-License-Identifier: GPL-2.0-or-later
/* QEMU PDP-12 TCG Instruction Translation frontend.
   Copyright (C) 2026 QEMU authors.
   Contributed by Weqaar Janjua. */

#include "qemu/osdep.h"
#include "tcg/tcg-op.h"
#include "exec/translator.h"
#include "cpu.h"

typedef struct DisasContext {
    DisasContextBase base;
    uint32_t opcode;
    int mem_idx;
    int element_size; /* 1, 2, 4, 8 bytes depending on operand type */
} DisasContext;

static TCGv cpu_gpr[32];
static TCGv cpu_pc;

/* Resolve orthogonal addressing modes in TCG. */
static TCGv decode_operand(DisasContext *ctx, uint32_t mode, uint32_t reg, TCGv displacement)
{
    TCGv addr = tcg_temp_new();
    TCGv size = tcg_constant_tl(ctx->element_size);

    switch (mode) {
    case 0: /* Register mode: GPR xn directly holds value */
        return cpu_gpr[reg];
    case 1: /* Register Deferred: Addr = xn */
        tcg_gen_mov_tl(addr, cpu_gpr[reg]);
        break;
    case 2: /* Autoincrement: Addr = xn; xn = xn + size */
        tcg_gen_mov_tl(addr, cpu_gpr[reg]);
        tcg_gen_add_tl(cpu_gpr[reg], cpu_gpr[reg], size);
        break;
    case 3: /* Autoincrement Deferred: Addr = Mem[xn]; xn = xn + 8 */
        tcg_gen_qemu_ld_tl(addr, cpu_gpr[reg], ctx->mem_idx, MO_TEUQ);
        tcg_gen_addi_tl(cpu_gpr[reg], cpu_gpr[reg], 8);
        break;
    case 4: /* Autodecrement: xn = xn - size; Addr = xn */
        tcg_gen_sub_tl(cpu_gpr[reg], cpu_gpr[reg], size);
        tcg_gen_mov_tl(addr, cpu_gpr[reg]);
        break;
    case 5: /* Autodecrement Deferred: xn = xn - 8; Addr = Mem[xn] */
        tcg_gen_subi_tl(cpu_gpr[reg], cpu_gpr[reg], 8);
        tcg_gen_qemu_ld_tl(addr, cpu_gpr[reg], ctx->mem_idx, MO_TEUQ);
        break;
    case 6: /* Indexed / Absolute: Addr = xn + Displacement */
        if (reg != 0) {
            tcg_gen_add_tl(addr, cpu_gpr[reg], displacement);
        } else {
            tcg_gen_mov_tl(addr, displacement); /* Absolute @X */
        }
        break;
    case 7: /* PC-Relative / Indexed Deferred */
        if (reg == 0) {
            TCGv pc = tcg_constant_tl(ctx->base.pc_next);
            tcg_gen_add_tl(addr, pc, displacement); /* PC-Relative X(PC) */
        } else {
            TCGv tmp = tcg_temp_new();
            tcg_gen_add_tl(tmp, cpu_gpr[reg], displacement);
            tcg_gen_qemu_ld_tl(addr, tmp, ctx->mem_idx, MO_TEUQ); /* Indexed Deferred @X(Rn) */
        }
        break;
    }
    return addr;
}

static void decode_opc(CPUPDP12State *env, DisasContext *ctx)
{
    uint32_t insn = ctx->opcode;
    uint32_t op = insn >> 26; /* Opcode field (6 bits) */

    switch (op) {
    case 0b000001: { /* MOV */
        uint32_t src_mode = (insn >> 23) & 0x7;
        uint32_t src_reg = (insn >> 18) & 0x1f;
        uint32_t dst_mode = (insn >> 15) & 0x7;
        uint32_t dst_reg = (insn >> 10) & 0x1f;
        int32_t disp = sextract32(insn, 0, 10);
        TCGv displacement = tcg_constant_tl(disp);

        TCGv src = decode_operand(ctx, src_mode, src_reg, displacement);
        TCGv dst_addr = decode_operand(ctx, dst_mode, dst_reg, displacement);

        if (dst_mode == 0) {
            tcg_gen_mov_tl(cpu_gpr[dst_reg], src);
        } else {
            tcg_gen_qemu_st_tl(src, dst_addr, ctx->mem_idx, MO_TEUQ);
        }
        break;
    }
    default:
        break;
    }
}

static void pdp12_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    ctx->mem_idx = pdp12_cpu_mmu_index(cs, false);
    ctx->element_size = 8; /* 64-bit */
}

static void pdp12_tr_tb_start(DisasContextBase *db, CPUState *cs)
{
}

static void pdp12_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    tcg_gen_insn_start(dcbase->pc_next);
}

static void pdp12_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    CPUPDP12State *env = cpu_env(cs);

    ctx->opcode = translator_ldl(env, &ctx->base, ctx->base.pc_next);
    ctx->base.pc_next += 4;

    decode_opc(env, ctx);
}

static void pdp12_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_NEXT:
    case DISAS_TOO_MANY:
        tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next);
        tcg_gen_lookup_and_goto_ptr();
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps pdp12_tr_ops = {
    .init_disas_context = pdp12_tr_init_disas_context,
    .tb_start           = pdp12_tr_tb_start,
    .insn_start         = pdp12_tr_insn_start,
    .translate_insn     = pdp12_tr_translate_insn,
    .tb_stop            = pdp12_tr_tb_stop,
};

void pdp12_translate_code(CPUState *cs, TranslationBlock *tb,
                          int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext ctx;
    translator_loop(cs, tb, max_insns, pc, host_pc, &pdp12_tr_ops, &ctx.base);
}

void pdp12_translate_init(void)
{
    static const char * const greg_names[32] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
        "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31"
    };
    int i;

    for (i = 0; i < 32; i++) {
        cpu_gpr[i] = tcg_global_mem_new_i64(tcg_env,
                                            offsetof(CPUPDP12State, gprs[i]),
                                            greg_names[i]);
    }
    cpu_pc = tcg_global_mem_new_i64(tcg_env,
                                    offsetof(CPUPDP12State, pc),
                                    "pc");
}
