// SPDX-License-Identifier: GPL-2.0-or-later
/* PDP-V scalar TCG translator (PDP-V-S0, PDP-V-S1 and PDP-V-P0). */

#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg-op.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/translation-block.h"
#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H
#include "exec/translator.h"

typedef struct DisasContext {
    DisasContextBase base;
    uint32_t opcode;
    int mem_idx;
} DisasContext;

typedef struct Operand {
    bool memory;
    unsigned int reg;
    unsigned int mode;
    TCGv reg_value;
    TCGv address;
    /* Staged register updates for autoincrement/decrement */
    unsigned int staged_reg;
    TCGv staged_value;
    bool has_staged;
} Operand;

typedef struct StagedGPROverlay {
    unsigned int reg;
    TCGv value;
    bool valid;
} StagedGPROverlay;

/* S0 Section 6 / S1 Section 9 S-Type opcodes. */
#define S_OP_CLR      0x801
#define S_OP_INC      0x802
#define S_OP_DEC      0x803
#define S_OP_NEG      0x804
#define S_OP_COM      0x805
#define S_OP_JMP      0x806
#define S_OP_JSR      0x807
#define S_OP_RTS      0x808
#define S_OP_SYS      0x809
#define S_OP_FENCE_I  0x80a
#define S_OP_BRK      0x80b
#define S_OP_NOP      0x80c

/* C-Type sub-ops (P0 Section 3, P1 Section 9). */
#define C_OP_CSRRW    0
#define C_OP_CSRRS    1
#define C_OP_CSRRC    2
#define C_OP_RTE      8
#define C_OP_SFENCE   9
#define C_OP_WFI      10

/* A0 A-Type operation field. */
#define A_OP_LR       0
#define A_OP_SC       1
#define A_OP_SWAP     2
#define A_OP_ADD      3
#define A_OP_AND      4
#define A_OP_OR       5
#define A_OP_XOR      6
#define A_OP_MIN      7
#define A_OP_MAX      8
#define A_OP_MINU     9
#define A_OP_MAXU     10

static TCGv cpu_gpr[32];
static TCGv cpu_pc;
static TCGv cpu_pstatus;

static TCGv gpr_read(unsigned int reg)
{
    return reg == 0 ? tcg_constant_tl(0) : cpu_gpr[reg];
}

static void gpr_write(unsigned int reg, TCGv value)
{
    if (reg != 0) {
        tcg_gen_mov_tl(cpu_gpr[reg], value);
    }
}

static TCGv gpr_read_overlay(unsigned int reg,
                             const StagedGPROverlay *overlay)
{
    if (overlay != NULL && overlay->valid && reg == overlay->reg) {
        return overlay->value;
    }
    return gpr_read(reg);
}

static uint32_t memory_descriptor(unsigned int size, bool mmio_ok)
{
    uint32_t desc = FIELD_DP32(0, MEMDESC, SIZE, size);

    return FIELD_DP32(desc, MEMDESC, MMIO, mmio_ok ? 1 : 0);
}

/*
 * Every guest data access is issued through the architectural data path in
 * mmu.c, which enforces natural alignment first, then canonicality,
 * translation and permissions, then physical and MMIO legality, and only then
 * the transaction. The translator never emits a raw TCG memory operation, so
 * no access can silently inherit MO_UNALN behaviour or bypass the S0/S1 MMIO
 * restrictions.
 */
static TCGv gen_load(DisasContext *ctx, TCGv address, unsigned int size,
                     bool mmio_ok)
{
    TCGv value = tcg_temp_new();

    /*
     * Only a transfer the profiles allow on device memory can reach a device
     * model, and a device such as the timer page observes QEMU virtual time.
     * Marking exactly those accesses I/O-capable keeps the counter exact
     * under icount and costs nothing when icount is off.
     */
    if (mmio_ok) {
        translator_io_start(&ctx->base);
    }
    gen_helper_load(value, tcg_env, address,
                    tcg_constant_i32(memory_descriptor(size, mmio_ok)));
    return value;
}

static void gen_store(DisasContext *ctx, TCGv address, TCGv value,
                      unsigned int size, bool mmio_ok)
{
    if (mmio_ok) {
        translator_io_start(&ctx->base);
    }
    gen_helper_store(tcg_env, address, value,
                     tcg_constant_i32(memory_descriptor(size, mmio_ok)));
}

/*
 * Operand resolution: stages register updates in temps rather than
 * immediately writing GPRs. The caller commits staged updates only
 * after all faultable operations complete. Destination resolution receives
 * the source operand's staged overlay so same-register addressing observes
 * the private working state required by S0 Section 9.
 *
 * S1 Section 6: an autoincrement or autodecrement register update equals the
 * final data width, while every deferred pointer read and pointer update
 * remains 64 bits wide.
 */
static Operand resolve_operand(DisasContext *ctx, unsigned int mode,
                               unsigned int reg, int64_t displacement,
                               unsigned int width, vaddr pc,
                               const StagedGPROverlay *overlay)
{
    Operand operand = {
        .memory = mode != 0,
        .reg = reg,
        .mode = mode,
        .reg_value = gpr_read_overlay(reg, overlay),
        .has_staged = false,
        .staged_reg = 0,
        .staged_value = NULL,
    };
    TCGv base;
    TCGv address;
    TCGv pointer;

    if (mode == 0) {
        return operand;
    }
    base = operand.reg_value;
    address = tcg_temp_new();
    operand.address = address;

    switch (mode) {
    case 1:                         /* register deferred */
        tcg_gen_mov_tl(address, base);
        break;
    case 2:                         /* autoincrement */
        tcg_gen_mov_tl(address, base);
        if (reg != 0) {
            operand.has_staged = true;
            operand.staged_reg = reg;
            operand.staged_value = tcg_temp_new();
            tcg_gen_addi_tl(operand.staged_value, base, width);
        }
        break;
    case 3:                         /* autoincrement deferred */
        tcg_gen_mov_tl(address, gen_load(ctx, base, 8, false));
        if (reg != 0) {
            operand.has_staged = true;
            operand.staged_reg = reg;
            operand.staged_value = tcg_temp_new();
            tcg_gen_addi_tl(operand.staged_value, base, 8);
        }
        break;
    case 4:                         /* autodecrement */
        tcg_gen_subi_tl(address, base, width);
        if (reg != 0) {
            operand.has_staged = true;
            operand.staged_reg = reg;
            operand.staged_value = tcg_temp_new();
            tcg_gen_mov_tl(operand.staged_value, address);
        }
        break;
    case 5:                         /* autodecrement deferred */
        pointer = tcg_temp_new();
        tcg_gen_subi_tl(pointer, base, 8);
        if (reg != 0) {
            operand.has_staged = true;
            operand.staged_reg = reg;
            operand.staged_value = tcg_temp_new();
            tcg_gen_mov_tl(operand.staged_value, pointer);
        }
        tcg_gen_mov_tl(address, gen_load(ctx, pointer, 8, false));
        break;
    case 6:                         /* indexed or absolute */
        if (reg == 0) {
            tcg_gen_movi_tl(address, displacement);
        } else {
            tcg_gen_addi_tl(address, base, displacement);
        }
        break;
    case 7:                         /* PC-relative or indexed deferred */
        if (reg == 0) {
            tcg_gen_movi_tl(address, pc + 4 + displacement);
        } else {
            pointer = tcg_temp_new();
            tcg_gen_addi_tl(pointer, base, displacement);
            tcg_gen_mov_tl(address, gen_load(ctx, pointer, 8, false));
        }
        break;
    default:
        g_assert_not_reached();
    }
    return operand;
}

/*
 * S0 Section 9 and S1 Section 10: side-effecting MMIO accepts only the single
 * final transfer of a move whose other operand is a register, addressed
 * without autoupdate and without a deferred pointer read. Register-deferred,
 * indexed, absolute and PC-relative forms qualify; every other mode does not.
 */
static bool mmio_capable_mode(unsigned int mode, unsigned int reg)
{
    return mode == 1 || mode == 6 || (mode == 7 && reg == 0);
}

/*
 * Commit staged register updates.
 * Called only after all faultable operations for the instruction complete.
 */
static void commit_operand_staged(Operand *op)
{
    if (op->has_staged && op->staged_reg != 0) {
        tcg_gen_mov_tl(cpu_gpr[op->staged_reg], op->staged_value);
    }
}

static void gen_extract_unsigned(TCGv destination, TCGv source,
                                 unsigned int bits)
{
    switch (bits) {
    case 8:
        tcg_gen_ext8u_tl(destination, source);
        break;
    case 16:
        tcg_gen_ext16u_tl(destination, source);
        break;
    case 32:
        tcg_gen_ext32u_tl(destination, source);
        break;
    default:
        tcg_gen_mov_tl(destination, source);
        break;
    }
}

static void gen_extract_signed(TCGv destination, TCGv source,
                               unsigned int bits)
{
    switch (bits) {
    case 8:
        tcg_gen_ext8s_tl(destination, source);
        break;
    case 16:
        tcg_gen_ext16s_tl(destination, source);
        break;
    case 32:
        tcg_gen_ext32s_tl(destination, source);
        break;
    default:
        tcg_gen_mov_tl(destination, source);
        break;
    }
}

/* Read an operand as the zero-extended value of the final data width. */
static TCGv operand_read(DisasContext *ctx, Operand *operand,
                         unsigned int bits, bool mmio_ok)
{
    TCGv value;

    if (!operand->memory) {
        value = tcg_temp_new();
        gen_extract_unsigned(value, operand->reg_value, bits);
        return value;
    }
    return gen_load(ctx, operand->address, bits / 8, mmio_ok);
}

static void operand_write(DisasContext *ctx, Operand *operand, TCGv value,
                          unsigned int bits, bool mmio_ok)
{
    if (!operand->memory) {
        gpr_write(operand->reg, value);
    } else {
        gen_store(ctx, operand->address, value, bits / 8, mmio_ok);
    }
}

static void operand_write_and_commit(DisasContext *ctx, Operand *source,
                                     Operand *destination, TCGv value,
                                     unsigned int bits, bool mmio_ok)
{
    /*
     * A memory write must validate and complete before any staged GPR update.
     * A direct-register result is committed last so it observes the staged
     * source value and wins over an aliased source autoupdate.
     */
    if (destination->memory) {
        operand_write(ctx, destination, value, bits, mmio_ok);
    }
    commit_operand_staged(source);
    commit_operand_staged(destination);
    if (!destination->memory) {
        operand_write(ctx, destination, value, bits, mmio_ok);
    }
}

/*
 * Flag production. Every flag input is a snapshot taken before the
 * destination write, and pstatus is updated only after all faultable work of
 * the instruction has completed, so a fault retires no flag change.
 */
static void gen_flags(TCGv n, TCGv z, TCGv v, TCGv c)
{
    TCGv accumulator = tcg_temp_new();
    TCGv bit = tcg_temp_new();

    tcg_gen_andi_tl(accumulator, c, 1);
    tcg_gen_andi_tl(bit, v, 1);
    tcg_gen_shli_tl(bit, bit, 1);
    tcg_gen_or_tl(accumulator, accumulator, bit);
    tcg_gen_andi_tl(bit, z, 1);
    tcg_gen_shli_tl(bit, bit, 2);
    tcg_gen_or_tl(accumulator, accumulator, bit);
    tcg_gen_andi_tl(bit, n, 1);
    tcg_gen_shli_tl(bit, bit, 3);
    tcg_gen_or_tl(accumulator, accumulator, bit);
    tcg_gen_andi_tl(cpu_pstatus, cpu_pstatus, ~(uint64_t)PSTATUS_NZVC);
    tcg_gen_or_tl(cpu_pstatus, cpu_pstatus, accumulator);
}

static TCGv gen_old_carry(void)
{
    TCGv carry = tcg_temp_new();

    tcg_gen_andi_tl(carry, cpu_pstatus, PSTATUS_C);
    return carry;
}

static TCGv gen_negative(TCGv result, unsigned int bits)
{
    TCGv n = tcg_temp_new();

    tcg_gen_shri_tl(n, result, bits - 1);
    tcg_gen_andi_tl(n, n, 1);
    return n;
}

static TCGv gen_zero(TCGv result, unsigned int bits)
{
    TCGv z = tcg_temp_new();
    TCGv masked = tcg_temp_new();

    gen_extract_unsigned(masked, result, bits);
    tcg_gen_setcondi_tl(TCG_COND_EQ, z, masked, 0);
    return z;
}

/* Flags for the result-only operations: V clear, C preserved. */
static void gen_logic_flags(TCGv result, unsigned int bits)
{
    gen_flags(gen_negative(result, bits), gen_zero(result, bits),
              tcg_constant_tl(0), gen_old_carry());
}

/* Flags for MUL and successful DIV: V and C clear. */
static void gen_product_flags(TCGv result, unsigned int bits)
{
    gen_flags(gen_negative(result, bits), gen_zero(result, bits),
              tcg_constant_tl(0), tcg_constant_tl(0));
}

static void gen_add_flags(TCGv left, TCGv right, TCGv result,
                          unsigned int bits)
{
    TCGv carry = tcg_temp_new();
    TCGv overflow = tcg_temp_new();
    TCGv tmp = tcg_temp_new();

    if (bits == 64) {
        tcg_gen_setcond_tl(TCG_COND_LTU, carry, result, left);
    } else {
        /* Operands are zero-extended, so the sum cannot wrap 64 bits. */
        tcg_gen_add_tl(tmp, left, right);
        tcg_gen_shri_tl(carry, tmp, bits);
        tcg_gen_andi_tl(carry, carry, 1);
    }
    tcg_gen_xor_tl(overflow, left, right);
    tcg_gen_not_tl(overflow, overflow);
    tcg_gen_xor_tl(tmp, left, result);
    tcg_gen_and_tl(overflow, overflow, tmp);
    tcg_gen_shri_tl(overflow, overflow, bits - 1);
    gen_flags(gen_negative(result, bits), gen_zero(result, bits),
              overflow, carry);
}

static void gen_sub_flags(TCGv left, TCGv right, TCGv result,
                          unsigned int bits)
{
    TCGv carry = tcg_temp_new();
    TCGv overflow = tcg_temp_new();
    TCGv tmp = tcg_temp_new();

    /* C=1 when no unsigned borrow: left >= right at the operand width. */
    tcg_gen_setcond_tl(TCG_COND_GEU, carry, left, right);
    tcg_gen_xor_tl(overflow, left, right);
    tcg_gen_xor_tl(tmp, left, result);
    tcg_gen_and_tl(overflow, overflow, tmp);
    tcg_gen_shri_tl(overflow, overflow, bits - 1);
    gen_flags(gen_negative(result, bits), gen_zero(result, bits),
              overflow, carry);
}

/*
 * Shift carry: the last bit shifted out.
 * For a left shift by k: bit (W-k) of the original value.
 * For a right shift by k: bit (k-1) of the original value.
 * A zero count preserves C.
 */
static TCGv gen_shift_carry(TCGv original, TCGv count, unsigned int bits,
                            bool left)
{
    TCGv carry = tcg_temp_new();
    TCGv position = tcg_temp_new();
    TCGv zero_count = tcg_temp_new();

    if (left) {
        tcg_gen_subfi_tl(position, bits, count);
    } else {
        tcg_gen_subi_tl(position, count, 1);
    }
    tcg_gen_andi_tl(position, position, 63);
    tcg_gen_shr_tl(carry, original, position);
    tcg_gen_andi_tl(carry, carry, 1);
    tcg_gen_setcondi_tl(TCG_COND_EQ, zero_count, count, 0);
    tcg_gen_movcond_tl(TCG_COND_NE, carry, zero_count, tcg_constant_tl(0),
                       gen_old_carry(), carry);
    return carry;
}

static void gen_exit_to(vaddr pc)
{
    tcg_gen_movi_tl(cpu_pc, pc);
    tcg_gen_lookup_and_goto_ptr();
}

static void gen_retire(void)
{
    gen_helper_retire(tcg_env);
}

static void gen_end_control_transfer(DisasContext *ctx)
{
    gen_retire();
    tcg_gen_lookup_and_goto_ptr();
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void gen_illegal(DisasContext *ctx)
{
    tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next);
    gen_helper_illegal(tcg_env, tcg_constant_i32(ctx->opcode));
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void gen_raise_exception(DisasContext *ctx, uint64_t cause,
                                TCGv tval)
{
    tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next);
    gen_helper_raise_exception(tcg_env, tcg_constant_i64(cause), tval);
    ctx->base.is_jmp = DISAS_NORETURN;
}

static bool valid_displacement(unsigned int src_mode, unsigned int dst_mode,
                               unsigned int encoded)
{
    unsigned int count = (src_mode >= 6) + (dst_mode >= 6);

    return count <= 1 && (count != 0 || encoded == 0);
}

typedef enum PDP12Operation {
    OP_RESERVED = 0,
    OP_MOVE,
    OP_MOVE_ZERO_EXTEND,
    OP_MOVE_SIGN_EXTEND,
    OP_ADD,
    OP_SUB,
    OP_COMPARE,
    OP_MUL,
    OP_DIV,
    OP_AND,
    OP_OR,
    OP_XOR,
    OP_SLL,
    OP_SRL,
    OP_SRA,
} PDP12Operation;

typedef struct PDP12OTypeInfo {
    PDP12Operation operation;
    unsigned int bits;
} PDP12OTypeInfo;

/* S0 Section 5 and S1 Section 5: the complete O-Type opcode map. */
static const PDP12OTypeInfo o_type_table[32] = {
    [1]  = { OP_MOVE,             64 },
    [2]  = { OP_ADD,              64 },
    [3]  = { OP_SUB,              64 },
    [4]  = { OP_MUL,              64 },
    [5]  = { OP_DIV,              64 },
    [6]  = { OP_COMPARE,          64 },
    [7]  = { OP_AND,              64 },
    [8]  = { OP_OR,               64 },
    [9]  = { OP_XOR,              64 },
    [10] = { OP_SLL,              64 },
    [11] = { OP_SRL,              64 },
    [12] = { OP_SRA,              64 },
    [13] = { OP_MOVE_ZERO_EXTEND,  8 },
    [14] = { OP_MOVE_SIGN_EXTEND,  8 },
    [15] = { OP_MOVE_ZERO_EXTEND, 16 },
    [16] = { OP_MOVE_SIGN_EXTEND, 16 },
    [17] = { OP_MOVE_ZERO_EXTEND, 32 },
    [18] = { OP_MOVE_SIGN_EXTEND, 32 },
    [19] = { OP_ADD,              32 },
    [20] = { OP_SUB,              32 },
    [21] = { OP_MUL,              32 },
    [22] = { OP_DIV,              32 },
    [23] = { OP_COMPARE,          32 },
    [24] = { OP_SLL,              32 },
    [25] = { OP_SRL,              32 },
    [26] = { OP_SRA,              32 },
};

static bool operation_is_move(PDP12Operation operation)
{
    return operation == OP_MOVE || operation == OP_MOVE_ZERO_EXTEND ||
           operation == OP_MOVE_SIGN_EXTEND;
}

/*
 * Canonicalise a width-limited result: a .W operation writes the sign
 * extension of its 32-bit result to a register and stores only the low bits
 * to memory (S1 Section 3).
 */
static TCGv gen_canonical_result(TCGv raw, unsigned int bits)
{
    TCGv value = tcg_temp_new();

    gen_extract_signed(value, raw, bits);
    return value;
}

static void translate_o_type(DisasContext *ctx, vaddr pc)
{
    uint32_t insn = ctx->opcode;
    unsigned int opcode = insn >> 26;
    unsigned int src_mode = extract32(insn, 23, 3);
    unsigned int src_reg = extract32(insn, 18, 5);
    unsigned int dst_mode = extract32(insn, 15, 3);
    unsigned int dst_reg = extract32(insn, 10, 5);
    unsigned int encoded = extract32(insn, 0, 10);
    int64_t displacement = sextract32(insn, 0, 10);
    const PDP12OTypeInfo *info = &o_type_table[opcode];
    unsigned int bits = info->bits;
    unsigned int flag_bits;
    unsigned int width;
    bool is_move;
    bool source_mmio;
    bool destination_mmio;
    Operand src;
    Operand dst;
    TCGv source;
    TCGv destination = NULL;
    TCGv result;
    TCGv value;
    TCGv count;
    TCGv carry;
    StagedGPROverlay source_overlay;

    if (info->operation == OP_RESERVED ||
        !valid_displacement(src_mode, dst_mode, encoded)) {
        gen_illegal(ctx);
        return;
    }
    width = bits / 8;
    is_move = operation_is_move(info->operation);
    flag_bits = is_move ? 64 : bits;
    source_mmio = is_move && dst_mode == 0 &&
                  mmio_capable_mode(src_mode, src_reg);
    destination_mmio = is_move && src_mode == 0 &&
                       mmio_capable_mode(dst_mode, dst_reg);

    src = resolve_operand(ctx, src_mode, src_reg, displacement, width, pc,
                          NULL);
    source = operand_read(ctx, &src, bits, source_mmio);
    source_overlay = (StagedGPROverlay) {
        .reg = src.staged_reg,
        .value = src.staged_value,
        .valid = src.has_staged,
    };
    dst = resolve_operand(ctx, dst_mode, dst_reg, displacement, width, pc,
                          &source_overlay);
    if (!is_move) {
        destination = operand_read(ctx, &dst, bits, destination_mmio);
    }

    result = tcg_temp_new();
    switch (info->operation) {
    case OP_MOVE:
    case OP_MOVE_ZERO_EXTEND:
        tcg_gen_mov_tl(result, source);
        operand_write_and_commit(ctx, &src, &dst, result, bits,
                                 destination_mmio);
        gen_logic_flags(result, flag_bits);
        return;
    case OP_MOVE_SIGN_EXTEND:
        gen_extract_signed(result, source, bits);
        operand_write_and_commit(ctx, &src, &dst, result, bits,
                                 destination_mmio);
        gen_logic_flags(result, flag_bits);
        return;
    case OP_ADD:
        tcg_gen_add_tl(result, destination, source);
        value = gen_canonical_result(result, bits);
        operand_write_and_commit(ctx, &src, &dst, value, bits, false);
        gen_add_flags(destination, source, result, bits);
        return;
    case OP_SUB:
    case OP_COMPARE:
        tcg_gen_sub_tl(result, destination, source);
        value = gen_canonical_result(result, bits);
        if (info->operation == OP_COMPARE) {
            commit_operand_staged(&src);
            commit_operand_staged(&dst);
        } else {
            operand_write_and_commit(ctx, &src, &dst, value, bits, false);
        }
        gen_sub_flags(destination, source, result, bits);
        return;
    case OP_MUL:
        tcg_gen_mul_tl(result, destination, source);
        value = gen_canonical_result(result, bits);
        operand_write_and_commit(ctx, &src, &dst, value, bits, false);
        gen_product_flags(result, bits);
        return;
    case OP_DIV:
        if (bits == 64) {
            gen_helper_div_d(result, tcg_env, destination, source);
        } else {
            gen_helper_div_w(result, tcg_env, destination, source);
        }
        value = gen_canonical_result(result, bits);
        operand_write_and_commit(ctx, &src, &dst, value, bits, false);
        gen_product_flags(result, bits);
        return;
    case OP_AND:
        tcg_gen_and_tl(result, destination, source);
        operand_write_and_commit(ctx, &src, &dst, result, bits, false);
        gen_logic_flags(result, flag_bits);
        return;
    case OP_OR:
        tcg_gen_or_tl(result, destination, source);
        operand_write_and_commit(ctx, &src, &dst, result, bits, false);
        gen_logic_flags(result, flag_bits);
        return;
    case OP_XOR:
        tcg_gen_xor_tl(result, destination, source);
        operand_write_and_commit(ctx, &src, &dst, result, bits, false);
        gen_logic_flags(result, flag_bits);
        return;
    case OP_SLL:
    case OP_SRL:
    case OP_SRA:
        count = tcg_temp_new();
        tcg_gen_andi_tl(count, source, bits - 1);
        if (info->operation == OP_SLL) {
            tcg_gen_shl_tl(result, destination, count);
            carry = gen_shift_carry(destination, count, bits, true);
        } else if (info->operation == OP_SRL) {
            tcg_gen_shr_tl(result, destination, count);
            carry = gen_shift_carry(destination, count, bits, false);
        } else {
            TCGv signed_source = gen_canonical_result(destination, bits);

            tcg_gen_sar_tl(result, signed_source, count);
            carry = gen_shift_carry(destination, count, bits, false);
        }
        value = gen_canonical_result(result, bits);
        operand_write_and_commit(ctx, &src, &dst, value, bits, false);
        gen_flags(gen_negative(result, bits), gen_zero(result, bits),
                  tcg_constant_tl(0), carry);
        return;
    default:
        g_assert_not_reached();
    }
}

/* P0 Section 6: reject a CSR number the profile does not implement. */
static bool csr_implemented(unsigned int csr)
{
    return csr <= PDP12_CSR_TIMECMP;
}

static bool csr_changes_translation(unsigned int csr)
{
    return csr == PDP12_CSR_PSTATUS || csr == PDP12_CSR_SATP;
}

static void translate_c_type(DisasContext *ctx)
{
    uint32_t insn = ctx->opcode;
    unsigned int subop = extract32(insn, 24, 4);
    unsigned int rd = extract32(insn, 19, 5);
    unsigned int rs = extract32(insn, 14, 5);
    unsigned int csr = extract32(insn, 2, 12);
    TCGv old;
    TCGv source;
    bool write;

    if (insn & 3) {
        gen_illegal(ctx);
        return;
    }

    /* Validate the complete encoding before applying privilege checks. */
    switch (subop) {
    case C_OP_SFENCE:
    case C_OP_RTE:
    case C_OP_WFI:
        if (rd || rs || csr) {
            gen_illegal(ctx);
            return;
        }
        break;
    case C_OP_CSRRW:
    case C_OP_CSRRS:
    case C_OP_CSRRC:
        if (!csr_implemented(csr)) {
            gen_illegal(ctx);
            return;
        }
        break;
    default:
        gen_illegal(ctx);
        return;
    }

    /*
     * P0 Section 3: every well-formed C-Type instruction requires Kernel
     * mode.  Privilege is part of the translation-block key.
     */
    if (ctx->mem_idx != PDP12_PRV_KERNEL) {
        gen_raise_exception(ctx, PDP12_CAUSE_PRIVILEGE_VIOLATION,
                            tcg_constant_tl((uint64_t)insn));
        return;
    }

    switch (subop) {
    case C_OP_SFENCE:
        /*
         * P1 changes translation context and A0 explicitly makes SFENCE.VM
         * a reservation-losing event.
         */
        gen_helper_tlb_flush(tcg_env);
        tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next + 4);
        gen_end_control_transfer(ctx);
        return;
    case C_OP_RTE:
        gen_helper_rte(tcg_env, tcg_constant_i32(insn));
        gen_end_control_transfer(ctx);
        return;
    case C_OP_WFI:
        /*
         * P0 Section 11: WFI is a hint and may resume spuriously. It must
         * not change architectural state, so it retires like any other
         * instruction and only then parks the hart until a source becomes
         * pending.
         */
        tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next + 4);
        gen_retire();
        gen_helper_wfi(tcg_env);
        ctx->base.is_jmp = DISAS_NORETURN;
        return;
    case C_OP_CSRRW:
    case C_OP_CSRRS:
    case C_OP_CSRRC:
        break;
    default:
        g_assert_not_reached();
    }

    /* CSRRS and CSRRC with rs=0 perform no CSR write. */
    write = (subop == C_OP_CSRRW) || rs != 0;
    /*
     * time reads and timecmp writes observe and arm QEMU virtual time, so
     * the access has to be the last one in the block under icount for the
     * counter to be exact.
     */
    if (csr == PDP12_CSR_TIME || csr == PDP12_CSR_TIMECMP) {
        translator_io_start(&ctx->base);
    }
    old = tcg_temp_new();
    gen_helper_csr_read(old, tcg_env, tcg_constant_i32(csr),
                        tcg_constant_i32(insn));
    if (write) {
        source = tcg_temp_new();
        tcg_gen_mov_tl(source, gpr_read(rs));
        if (subop == C_OP_CSRRS) {
            tcg_gen_or_tl(source, old, source);
        } else if (subop == C_OP_CSRRC) {
            tcg_gen_not_tl(source, source);
            tcg_gen_and_tl(source, old, source);
        }
        gen_helper_csr_write(tcg_env, tcg_constant_i32(csr), source,
                             tcg_constant_i32(insn));
    }
    gpr_write(rd, old);
    if (write && csr_changes_translation(csr)) {
        tcg_gen_movi_tl(cpu_pc, ctx->base.pc_next + 4);
        gen_end_control_transfer(ctx);
    }
}

/*
 * A0 atomic descriptor passed to helper_atomic:
 * bit 0 selects .D (otherwise .W), bits 1..4 hold the operation.
 */
static void translate_a_type(DisasContext *ctx)
{
    uint32_t insn = ctx->opcode;
    unsigned int aq = extract32(insn, 24, 1);
    unsigned int rl = extract32(insn, 23, 1);
    unsigned int rs2 = extract32(insn, 18, 5);
    unsigned int rs1 = extract32(insn, 13, 5);
    unsigned int rd = extract32(insn, 8, 5);
    unsigned int width = extract32(insn, 7, 1);
    unsigned int operation = extract32(insn, 3, 4);
    uint32_t desc = width | (operation << 1);
    TCGv address;
    TCGv source;
    TCGv result;

    if ((insn & 7) || operation > A_OP_MAXU ||
        (operation == A_OP_LR && rs2 != 0)) {
        gen_illegal(ctx);
        return;
    }

    /*
     * Snapshot both sources before touching rd.  This is required even
     * though helper arguments happen to be evaluated before gpr_write:
     * rd=rs1 and rd=rs2 are architectural aliases, not translator details.
     */
    address = tcg_temp_new();
    source = tcg_temp_new();
    tcg_gen_mov_tl(address, gpr_read(rs1));
    tcg_gen_mov_tl(source, gpr_read(rs2));

    if (rl) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }
    result = tcg_temp_new();
    gen_helper_atomic(result, tcg_env, address, source,
                      tcg_constant_i32(desc));
    if (aq) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }
    gpr_write(rd, result);
}

/*
 * Convert A0's normal/device predecessor and successor classes into the
 * load/store pairs understood by TCG.  I/R are reads and O/W are writes.
 * TCG cannot distinguish memory types, so this may order an unselected class
 * too; that is a permitted stronger implementation.
 */
static TCGBar a0_fence_barrier(unsigned int predecessor,
                               unsigned int successor)
{
    bool pred_read = predecessor & (BIT(3) | BIT(1));
    bool pred_write = predecessor & (BIT(2) | BIT(0));
    bool succ_read = successor & (BIT(3) | BIT(1));
    bool succ_write = successor & (BIT(2) | BIT(0));
    TCGBar barrier = 0;

    if (pred_read && succ_read) {
        barrier |= TCG_MO_LD_LD;
    }
    if (pred_read && succ_write) {
        barrier |= TCG_MO_LD_ST;
    }
    if (pred_write && succ_read) {
        barrier |= TCG_MO_ST_LD;
    }
    if (pred_write && succ_write) {
        barrier |= TCG_MO_ST_ST;
    }
    return barrier | TCG_BAR_SC;
}

typedef struct PDP12ITypeInfo {
    PDP12Operation operation;
    unsigned int bits;
    unsigned int shift_bits;    /* nonzero for shift sub-ops */
} PDP12ITypeInfo;

/* S1 Section 7: the complete I-Type sub-op map. */
static const PDP12ITypeInfo i_type_table[16] = {
    [0]  = { OP_ADD, 64, 0 },
    [1]  = { OP_SUB, 64, 0 },
    [2]  = { OP_AND, 64, 0 },
    [3]  = { OP_OR,  64, 0 },
    [4]  = { OP_XOR, 64, 0 },
    [5]  = { OP_SLL, 64, 6 },
    [6]  = { OP_SRL, 64, 6 },
    [7]  = { OP_SRA, 64, 6 },
    [8]  = { OP_ADD, 32, 0 },
    [9]  = { OP_SUB, 32, 0 },
    [10] = { OP_SLL, 32, 5 },
    [11] = { OP_SRL, 32, 5 },
    [12] = { OP_SRA, 32, 5 },
};

static void translate_i_type(DisasContext *ctx)
{
    uint32_t insn = ctx->opcode;
    unsigned int subop = extract32(insn, 24, 4);
    unsigned int src_reg = extract32(insn, 19, 5);
    unsigned int dst_reg = extract32(insn, 14, 5);
    unsigned int encoded = extract32(insn, 0, 14);
    int64_t immediate = sextract32(insn, 0, 14);
    const PDP12ITypeInfo *info = &i_type_table[subop];
    unsigned int bits = info->bits;
    unsigned int shift_count = 0;
    TCGv source = tcg_temp_new();
    TCGv right;
    TCGv result = tcg_temp_new();
    TCGv value;
    TCGv carry;

    if (info->operation == OP_RESERVED) {
        gen_illegal(ctx);
        return;
    }
    if (info->shift_bits != 0) {
        unsigned int reserved = ~((1u << info->shift_bits) - 1u) & 0x3fff;

        if (encoded & reserved) {
            gen_illegal(ctx);
            return;
        }
        shift_count = encoded & ((1u << info->shift_bits) - 1u);
    }

    gen_extract_unsigned(source, gpr_read(src_reg), bits);
    right = tcg_temp_new();
    gen_extract_unsigned(right, tcg_constant_tl(immediate), bits);

    switch (info->operation) {
    case OP_ADD:
        tcg_gen_add_tl(result, source, right);
        gen_add_flags(source, right, result, bits);
        break;
    case OP_SUB:
        tcg_gen_sub_tl(result, source, right);
        gen_sub_flags(source, right, result, bits);
        break;
    case OP_AND:
        tcg_gen_and_tl(result, source, right);
        gen_logic_flags(result, bits);
        break;
    case OP_OR:
        tcg_gen_or_tl(result, source, right);
        gen_logic_flags(result, bits);
        break;
    case OP_XOR:
        tcg_gen_xor_tl(result, source, right);
        gen_logic_flags(result, bits);
        break;
    case OP_SLL:
    case OP_SRL:
    case OP_SRA: {
        TCGv count = tcg_constant_tl(shift_count);

        if (info->operation == OP_SLL) {
            tcg_gen_shli_tl(result, source, shift_count);
            carry = gen_shift_carry(source, count, bits, true);
        } else if (info->operation == OP_SRL) {
            tcg_gen_shri_tl(result, source, shift_count);
            carry = gen_shift_carry(source, count, bits, false);
        } else {
            TCGv signed_source = gen_canonical_result(source, bits);

            tcg_gen_sari_tl(result, signed_source, shift_count);
            carry = gen_shift_carry(source, count, bits, false);
        }
        gen_flags(gen_negative(result, bits), gen_zero(result, bits),
                  tcg_constant_tl(0), carry);
        break;
    }
    default:
        g_assert_not_reached();
    }

    value = gen_canonical_result(result, bits);
    gpr_write(dst_reg, value);
}

/* S1 Section 8: U-Type upper-immediate construction. Flags are unchanged. */
static void translate_u_type(DisasContext *ctx, vaddr pc)
{
    uint32_t insn = ctx->opcode;
    unsigned int operation = extract32(insn, 27, 1);
    unsigned int dst_reg = extract32(insn, 22, 5);
    int64_t immediate = sextract32(insn, 0, 22);
    uint64_t upper = (uint64_t)immediate << 14;

    if (operation == 0) {                       /* LUI */
        gpr_write(dst_reg, tcg_constant_tl(upper));
    } else {                                    /* AUIPC */
        gpr_write(dst_reg, tcg_constant_tl(pc + 4 + upper));
    }
}

static void translate_branch(DisasContext *ctx, vaddr pc)
{
    unsigned int condition = extract32(ctx->opcode, 20, 5);
    int64_t offset = sextract32(ctx->opcode, 0, 20);
    vaddr next = pc + 4;
    vaddr target = next + offset * 4;
    TCGv flags = tcg_temp_new();
    TCGv predicate = tcg_temp_new();
    TCGv tmp = tcg_temp_new();
    TCGLabel *taken;
    TCGLabel *done;

    /* S0 Section 7: conditions 15 through 31 are reserved. */
    if (condition >= 15) {
        gen_illegal(ctx);
        return;
    }

    tcg_gen_mov_tl(flags, cpu_pstatus);
    switch (condition) {
    case 0:                         /* BR - always */
        gen_helper_validate_control_target(tcg_env,
                                           tcg_constant_tl(target));
        tcg_gen_movi_tl(cpu_pc, target);
        gen_end_control_transfer(ctx);
        return;
    case 1:                         /* BEQ: Z=1 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_Z);
        break;
    case 2:                         /* BNE: Z=0 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_Z);
        tcg_gen_xori_tl(predicate, predicate, PSTATUS_Z);
        break;
    case 3:                         /* BLT: N != V */
        tcg_gen_shri_tl(predicate, flags, 3);
        tcg_gen_shri_tl(tmp, flags, 1);
        tcg_gen_xor_tl(predicate, predicate, tmp);
        tcg_gen_andi_tl(predicate, predicate, 1);
        break;
    case 4:                         /* BGE: N == V */
        tcg_gen_shri_tl(predicate, flags, 3);
        tcg_gen_shri_tl(tmp, flags, 1);
        tcg_gen_xor_tl(predicate, predicate, tmp);
        tcg_gen_andi_tl(predicate, predicate, 1);
        tcg_gen_xori_tl(predicate, predicate, 1);
        break;
    case 5:                         /* BLTU: C=0 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_C);
        tcg_gen_xori_tl(predicate, predicate, PSTATUS_C);
        break;
    case 6:                         /* BGEU: C=1 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_C);
        break;
    case 7:                         /* BGT: Z=0 and N==V */
        tcg_gen_shri_tl(predicate, flags, 3);  /* N */
        tcg_gen_shri_tl(tmp, flags, 1);        /* V */
        tcg_gen_xor_tl(predicate, predicate, tmp);
        tcg_gen_andi_tl(predicate, predicate, 1);
        tcg_gen_xori_tl(predicate, predicate, 1); /* N==V */
        tcg_gen_andi_tl(tmp, flags, PSTATUS_Z);
        tcg_gen_setcondi_tl(TCG_COND_EQ, tmp, tmp, 0); /* Z==0 */
        tcg_gen_and_tl(predicate, predicate, tmp);
        break;
    case 8:                         /* BLE: Z=1 or N!=V */
        tcg_gen_shri_tl(predicate, flags, 3);  /* N */
        tcg_gen_shri_tl(tmp, flags, 1);        /* V */
        tcg_gen_xor_tl(predicate, predicate, tmp);
        tcg_gen_andi_tl(predicate, predicate, 1); /* N!=V */
        tcg_gen_andi_tl(tmp, flags, PSTATUS_Z);
        tcg_gen_setcondi_tl(TCG_COND_NE, tmp, tmp, 0); /* Z==1 */
        tcg_gen_or_tl(predicate, predicate, tmp);
        break;
    case 9:                         /* BCS: C=1 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_C);
        break;
    case 10:                        /* BCC: C=0 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_C);
        tcg_gen_xori_tl(predicate, predicate, PSTATUS_C);
        break;
    case 11:                        /* BVS: V=1 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_V);
        break;
    case 12:                        /* BVC: V=0 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_V);
        tcg_gen_xori_tl(predicate, predicate, PSTATUS_V);
        break;
    case 13:                        /* BMI: N=1 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_N);
        break;
    case 14:                        /* BPL: N=0 */
        tcg_gen_andi_tl(predicate, flags, PSTATUS_N);
        tcg_gen_xori_tl(predicate, predicate, PSTATUS_N);
        break;
    default:
        g_assert_not_reached();
    }

    taken = gen_new_label();
    done = gen_new_label();
    tcg_gen_brcondi_tl(TCG_COND_NE, predicate, 0, taken);
    tcg_gen_movi_tl(cpu_pc, next);
    tcg_gen_br(done);
    gen_set_label(taken);
    gen_helper_validate_control_target(tcg_env, tcg_constant_tl(target));
    tcg_gen_movi_tl(cpu_pc, target);
    gen_set_label(done);
    gen_end_control_transfer(ctx);
}

static void translate_s_type(DisasContext *ctx, vaddr pc)
{
    uint32_t insn = ctx->opcode;
    unsigned int opcode = insn >> 20;
    unsigned int mode = extract32(insn, 17, 3);
    unsigned int reg = extract32(insn, 12, 5);
    unsigned int encoded = extract32(insn, 0, 12);
    int64_t displacement = sextract32(insn, 0, 12);
    Operand destination;
    TCGv target;
    TCGv value;
    TCGv result;
    TCGv overflow;

    switch (opcode) {
    case S_OP_RTS:
    case S_OP_SYS:
    case S_OP_FENCE_I:
    case S_OP_BRK:
    case S_OP_NOP:
        /* S0 Section 6: these forms reserve every operand field. */
        if (insn & 0xfffff) {
            gen_illegal(ctx);
            return;
        }
        break;
    case S_OP_CLR:
    case S_OP_INC:
    case S_OP_DEC:
    case S_OP_NEG:
    case S_OP_COM:
    case S_OP_JMP:
    case S_OP_JSR:
        /* Modes without a displacement must encode a zero displacement. */
        if (mode < 6 && encoded != 0) {
            gen_illegal(ctx);
            return;
        }
        break;
    default:
        gen_illegal(ctx);
        return;
    }

    switch (opcode) {
    case S_OP_RTS:
        target = tcg_temp_new();
        tcg_gen_mov_tl(target, gpr_read(1));
        gen_helper_validate_control_target(tcg_env, target);
        tcg_gen_mov_tl(cpu_pc, target);
        gen_end_control_transfer(ctx);
        return;
    case S_OP_SYS:
        /* P0 Section 4: SYS reports the calling privilege, with tval zero. */
        gen_raise_exception(ctx,
                            ctx->mem_idx == PDP12_PRV_USER
                                ? PDP12_CAUSE_ECALL_FROM_USER
                                : PDP12_CAUSE_ECALL_FROM_KERNEL,
                            tcg_constant_tl(0));
        return;
    case S_OP_BRK:
        /* S1 Section 9: breakpoint with tval equal to the faulting PC. */
        gen_raise_exception(ctx, PDP12_CAUSE_BREAKPOINT,
                            tcg_constant_tl(pc));
        return;
    case S_OP_FENCE_I:
        /*
         * S0 Section 12: later instruction fetches observe earlier stores.
         * Ending the translation block re-fetches the following instruction.
         */
        tcg_gen_movi_tl(cpu_pc, pc + 4);
        gen_end_control_transfer(ctx);
        return;
    case S_OP_NOP:
        return;
    default:
        break;
    }

    destination = resolve_operand(ctx, mode, reg, displacement, 8, pc, NULL);

    if (opcode == S_OP_JMP || opcode == S_OP_JSR) {
        /*
         * S0 Section 10: for memory modes the target is the resolved
         * effective address, not the data stored there. Deferred modes still
         * perform their pointer read while resolving that address.
         */
        target = tcg_temp_new();
        tcg_gen_mov_tl(target,
                       destination.memory ? destination.address
                                          : destination.reg_value);
        gen_helper_validate_control_target(tcg_env, target);
        commit_operand_staged(&destination);
        if (opcode == S_OP_JSR) {
            gpr_write(1, tcg_constant_tl(pc + 4));
        }
        tcg_gen_mov_tl(cpu_pc, target);
        gen_end_control_transfer(ctx);
        return;
    }

    result = tcg_temp_new();
    switch (opcode) {
    case S_OP_CLR:
        /* CLR does not read its destination. */
        tcg_gen_movi_tl(result, 0);
        operand_write_and_commit(ctx, &destination, &destination, result, 64,
                                 false);
        gen_flags(tcg_constant_tl(0), tcg_constant_tl(1),
                  tcg_constant_tl(0), gen_old_carry());
        return;
    case S_OP_INC:
    case S_OP_DEC:
    case S_OP_NEG:
        value = operand_read(ctx, &destination, 64, false);
        overflow = tcg_temp_new();
        if (opcode == S_OP_INC) {
            tcg_gen_addi_tl(result, value, 1);
            tcg_gen_setcondi_tl(TCG_COND_EQ, overflow, value, INT64_MAX);
        } else if (opcode == S_OP_DEC) {
            tcg_gen_subi_tl(result, value, 1);
            tcg_gen_setcondi_tl(TCG_COND_EQ, overflow, value, INT64_MIN);
        } else {
            tcg_gen_neg_tl(result, value);
            tcg_gen_setcondi_tl(TCG_COND_EQ, overflow, value, INT64_MIN);
        }
        operand_write_and_commit(ctx, &destination, &destination, result, 64,
                                 false);
        gen_flags(gen_negative(result, 64), gen_zero(result, 64), overflow,
                  gen_old_carry());
        return;
    case S_OP_COM:
        value = operand_read(ctx, &destination, 64, false);
        tcg_gen_not_tl(result, value);
        operand_write_and_commit(ctx, &destination, &destination, result, 64,
                                 false);
        gen_logic_flags(result, 64);
        return;
    default:
        g_assert_not_reached();
    }
}

static void decode_opc(DisasContext *ctx, vaddr pc)
{
    uint32_t insn = ctx->opcode;
    uint32_t prefix = insn >> 28;

    if (!(insn & 0x80000000)) {
        translate_o_type(ctx, pc);
    } else if (prefix == 8) {
        translate_s_type(ctx, pc);
    } else if (prefix == 9) {
        translate_c_type(ctx);
    } else if (prefix == 10) {
        translate_i_type(ctx);
    } else if (prefix == 11) {
        translate_u_type(ctx, pc);
    } else if ((insn >> 25) == 0x60) {
        translate_branch(ctx, pc);
    } else if ((insn >> 25) == 0x70) {
        translate_a_type(ctx);
    } else if ((insn >> 25) == 0x71) {
        if ((insn & 0x1ffff) ||
            !extract32(insn, 21, 4) || !extract32(insn, 17, 4)) {
            gen_illegal(ctx);
        } else {
            tcg_gen_mb(a0_fence_barrier(extract32(insn, 21, 4),
                                        extract32(insn, 17, 4)));
        }
    } else {
        gen_illegal(ctx);
    }
}

static void pdp12_tr_init_disas_context(DisasContextBase *dcbase,
                                        CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    ctx->mem_idx = FIELD_EX32(ctx->base.tb->flags, TB_FLAGS, MMU_IDX);
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
    vaddr pc = ctx->base.pc_next;

    ctx->opcode = translator_ldl(env, &ctx->base, pc);
    gen_helper_check_stop(tcg_env);
    decode_opc(ctx, pc);
    ctx->base.pc_next = pc + 4;
    if (ctx->base.is_jmp != DISAS_NORETURN) {
        tcg_gen_movi_tl(cpu_pc, pc + 4);
        gen_retire();
    }
}

static void pdp12_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_NEXT:
    case DISAS_TOO_MANY:
        gen_exit_to(ctx->base.pc_next);
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps pdp12_tr_ops = {
    .init_disas_context = pdp12_tr_init_disas_context,
    .tb_start = pdp12_tr_tb_start,
    .insn_start = pdp12_tr_insn_start,
    .translate_insn = pdp12_tr_translate_insn,
    .tb_stop = pdp12_tr_tb_stop,
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
        "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31",
    };
    int i;

    for (i = 0; i < 32; i++) {
        cpu_gpr[i] = tcg_global_mem_new_i64(
            tcg_env, offsetof(CPUPDP12State, gprs[i]), greg_names[i]);
    }
    cpu_pc = tcg_global_mem_new_i64(
        tcg_env, offsetof(CPUPDP12State, pc), "pc");
    cpu_pstatus = tcg_global_mem_new_i64(
        tcg_env, offsetof(CPUPDP12State, pstatus), "pstatus");
}
