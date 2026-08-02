#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""PDP-12 scalar instruction tests: shifts, branches, and exceptions."""

import argparse
import json
import pathlib
import re
import struct
import subprocess
import tempfile


RAM_ENTRY = 0x80001000
VIRTUAL_ENTRY = 0xFFFFFFC000001000
P39_ROOT_PA = 0x80004000
P39_L1_PA = 0x80005000
P39_SAME_REG_VA = 0x401FFFF8
P39_SAME_REG_NEXT_VA = 0x40200000
P39_SATP = (1 << 60) | (P39_ROOT_PA >> 12)


def make_kernel(path, code_bytes):
    """Build a minimal ELF with given code at RAM_ENTRY."""
    payload = code_bytes
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 2, 0xFF50, 1, VIRTUAL_ENTRY, 64, 0, 0,
        64, 56, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1, 5, 0x1000, VIRTUAL_ENTRY, RAM_ENTRY,
        len(payload), len(payload), 0x1000,
    )
    path.write_bytes(ehdr + phdr + bytes(0x1000 - len(ehdr) - len(phdr)) +
                     payload)


def encode_addi_d(imm14, src_reg, dst_reg):
    """Encode ADDI.D imm, src, dst."""
    insn = (
        (0xA << 28) | (src_reg << 19) | (dst_reg << 14) |
        (imm14 & 0x3FFF)
    )
    return insn


def encode_nop():
    return 0x80C00000


def encode_slli_d(count, src_reg, dst_reg):
    """Encode SLLI.D with immediate count."""
    insn = (
        (0xA << 28) | (5 << 24) | (src_reg << 19) |
        (dst_reg << 14) | (count & 0x3F)
    )
    return insn


def encode_ori_d(imm14, src_reg, dst_reg):
    """Encode ORI.D imm, src, dst."""
    return (
        (0xA << 28) | (3 << 24) | (src_reg << 19) |
        (dst_reg << 14) | (imm14 & 0x3FFF)
    )


def encode_srli_d(count, src_reg, dst_reg):
    """Encode SRLI.D with immediate count."""
    insn = (
        (0xA << 28) | (6 << 24) | (src_reg << 19) |
        (dst_reg << 14) | (count & 0x3F)
    )
    return insn


def encode_o_type(op, src_mode, src_reg, dst_mode, dst_reg, disp=0):
    """Encode an O-Type instruction: opcode<31:26>, src/dst mode+reg, disp."""
    return (
        (op << 26) | (src_mode << 23) | (src_reg << 18) |
        (dst_mode << 15) | (dst_reg << 10) | (disp & 0x3FF)
    )


def encode_sll(count_reg, value_reg):
    """O-Type SLL: value_reg <<= (count_reg & 63), both register operands."""
    return encode_o_type(10, 0, count_reg, 0, value_reg)


def encode_srl(count_reg, value_reg):
    """O-Type SRL: value_reg >>= (count_reg & 63) logical."""
    return encode_o_type(11, 0, count_reg, 0, value_reg)


def encode_sra(count_reg, value_reg):
    """O-Type SRA: value_reg >>= (count_reg & 63) arithmetic."""
    return encode_o_type(12, 0, count_reg, 0, value_reg)


def encode_subi_d(imm14, src_reg, dst_reg):
    """Encode SUBI.D imm, src, dst."""
    insn = (
        (0xA << 28) | (1 << 24) | (src_reg << 19) |
        (dst_reg << 14) | (imm14 & 0x3FFF)
    )
    return insn


def encode_branch(condition, offset20):
    """Encode B-Type: opcode=1100000, condition, offset."""
    insn = (0x60 << 25) | (condition << 20) | (offset20 & 0xFFFFF)
    return insn


def encode_c_type(subop, rd=0, rs=0, csr=0):
    return (
        (9 << 28) | (subop << 24) | (rd << 19) | (rs << 14) |
        (csr << 2)
    )


def encode_add_d(src_reg, dst_reg):
    return (2 << 26) | (src_reg << 18) | (dst_reg << 10)


def encode_jmp(mode, reg, displacement=0):
    return (
        (0x806 << 20) | (mode << 17) | (reg << 12) |
        (displacement & 0xFFF)
    )


def load_imm(reg, value):
    """Materialise an unsigned 64-bit value from positive 12-bit chunks."""
    value &= (1 << 64) - 1
    chunks = []
    while value:
        chunks.append(value & 0xFFF)
        value >>= 12

    insns = [encode_addi_d(0, 0, reg)]
    for chunk in reversed(chunks):
        insns.append(encode_slli_d(12, reg, reg))
        if chunk:
            insns.append(encode_ori_d(chunk, reg, reg))
    return insns


def p39_payload(insns):
    """Add an identity-mapping P39 root page to an instruction payload."""
    code = struct.pack(f"<{len(insns)}I", *insns)
    payload = bytearray(0x4000)
    payload[:len(code)] = code
    root_offset = P39_ROOT_PA - RAM_ENTRY
    identity_leaf = 0x2000004B  # PA 0x80000000, V|R|X|A
    struct.pack_into("<Q", payload, root_offset + 2 * 8, identity_leaf)
    return bytes(payload)


def same_reg_fault_payload(insns):
    """Map one 2 MiB data leaf ending immediately before the fault target."""
    code = struct.pack(f"<{len(insns)}I", *insns)
    payload = bytearray(0x5000)
    payload[:len(code)] = code
    root_offset = P39_ROOT_PA - RAM_ENTRY
    l1_offset = P39_L1_PA - RAM_ENTRY
    identity_leaf = 0x200000CB  # PA 0x80000000, V|R|W|X|A|D
    l1_pointer = ((P39_L1_PA >> 12) << 10) | 1
    data_leaf = 0x200000C7      # PA 0x80000000, V|R|W|A|D

    struct.pack_into("<Q", payload, root_offset + 2 * 8, identity_leaf)
    struct.pack_into("<Q", payload, root_offset + 1 * 8, l1_pointer)
    struct.pack_into("<Q", payload, l1_offset, data_leaf)
    return bytes(payload)


class QMP:
    def __init__(self, process):
        self.process = process
        self.events = []

    def read(self):
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("QMP connection closed")
        return json.loads(line)

    def command(self, execute, arguments=None):
        request = {"execute": execute}
        if arguments is not None:
            request["arguments"] = arguments
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        while True:
            response = self.read()
            if "event" in response:
                self.events.append(response)
            elif "error" in response:
                raise RuntimeError(f"QMP command failed: {response['error']!r}")
            elif "return" in response:
                return response["return"]

    def wait_event(self, name):
        while True:
            for index, event in enumerate(self.events):
                if event["event"] == name:
                    return self.events.pop(index)
            response = self.read()
            if "event" in response:
                self.events.append(response)


def run_program(qemu, tmpdir, insns, stop_count, test_name, payload=None):
    """Run a program and return register dump text."""
    code = payload
    if code is None:
        code = struct.pack(f"<{len(insns)}I", *insns)
    kernel = tmpdir / f"{test_name}.elf"
    make_kernel(kernel, code)

    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-global", f"pdp12-cpu.stop-after-insns={stop_count}",
        "-m", "32M",
        "-kernel", str(kernel),
        "-display", "none",
        "-audio", "none",
        "-S",
        "-qmp", "stdio",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        qmp = QMP(process)
        greeting = qmp.read()
        if "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting")
        qmp.command("qmp_capabilities")
        qmp.command("cont")
        qmp.wait_event("STOP")
        registers = qmp.command(
            "human-monitor-command",
            {"command-line": "info registers"},
        )
        return registers
    finally:
        process.terminate()
        process.communicate(timeout=10)


def parse_reg(text, reg_name):
    """Parse a register value from dump."""
    match = re.search(rf"{reg_name}\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"Cannot find {reg_name} in:\n{text}")
    return int(match.group(1), 16)


def parse_pstatus(text):
    match = re.search(r"PSTATUS=0x([0-9a-f]+)", text, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"Cannot find PSTATUS in:\n{text}")
    return int(match.group(1), 16)


def parse_pc(text):
    match = re.search(r"PC=0x([0-9a-f]+)", text, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"Cannot find PC in:\n{text}")
    return int(match.group(1), 16)


def parse_retired(text):
    match = re.search(r"RETIRED=(\d+)", text, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"Cannot find RETIRED in:\n{text}")
    return int(match.group(1))


def parse_csr(text, name):
    match = re.search(rf"{name}=0x([0-9a-f]+)", text, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"Cannot find {name} in:\n{text}")
    return int(match.group(1), 16)


def test_sll(qemu, tmpdir):
    """O-Type SLL: x10=1 shifted left by x11=3 -> 8; carry (bit 61) = 0."""
    insns = [
        encode_addi_d(1, 0, 10),      # x10 = 1 (value)
        encode_addi_d(3, 0, 11),      # x11 = 3 (count)
        encode_sll(11, 10),           # x10 = x10 << 3 = 8
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 4, "sll")
    assert parse_reg(regs, "x10") == 8, f"SLL result={parse_reg(regs, 'x10')}"
    assert parse_pstatus(regs) & 1 == 0, "SLL carry expected 0"
    print("  O-Type SLL: PASS")


def test_srl(qemu, tmpdir):
    """O-Type SRL: x10=0x80 shifted right by x11=4 -> 8; carry (bit 3) = 0."""
    insns = [
        encode_addi_d(0x80, 0, 10),   # x10 = 128 (value)
        encode_addi_d(4, 0, 11),      # x11 = 4 (count)
        encode_srl(11, 10),           # x10 = x10 >> 4 = 8
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 4, "srl")
    assert parse_reg(regs, "x10") == 8, f"SRL result={parse_reg(regs, 'x10')}"
    assert parse_pstatus(regs) & 1 == 0, "SRL carry expected 0"
    print("  O-Type SRL: PASS")


def test_sra(qemu, tmpdir):
    """O-Type SRA: x10=-16 shifted right by x11=2 -> -4; carry (bit 1) = 0."""
    insns = [
        encode_addi_d((-16) & 0x3FFF, 0, 10),  # x10 = -16 (value)
        encode_addi_d(2, 0, 11),               # x11 = 2 (count)
        encode_sra(11, 10),                     # x10 = x10 >> 2 = -4 (signed)
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 4, "sra")
    assert parse_reg(regs, "x10") == 0xFFFFFFFFFFFFFFFC, "SRA result != -4"
    assert parse_pstatus(regs) & 1 == 0, "SRA carry expected 0"
    print("  O-Type SRA: PASS")


def test_sll_carry(qemu, tmpdir):
    """O-Type SLL carry-out: (1<<63) << 1 = 0 with carry from bit 63 = 1."""
    insns = [
        encode_addi_d(1, 0, 10),      # x10 = 1
        encode_addi_d(63, 0, 12),     # x12 = 63 (count)
        encode_sll(12, 10),           # x10 = 1 << 63
        encode_addi_d(1, 0, 11),      # x11 = 1 (count)
        encode_sll(11, 10),           # x10 = (1<<63) << 1 = 0, carry = 1
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 6, "sll_carry")
    assert parse_reg(regs, "x10") == 0, "SLL carry-out result expected 0"
    assert parse_pstatus(regs) & 1 == 1, "SLL carry-out expected 1"
    print("  O-Type SLL carry-out: PASS")


def test_srl_carry(qemu, tmpdir):
    """O-Type SRL carry-out: 0x80 >> 8 = 0 with carry from bit 7 = 1."""
    insns = [
        encode_addi_d(0x80, 0, 10),   # x10 = 128
        encode_addi_d(8, 0, 11),      # x11 = 8 (count)
        encode_srl(11, 10),           # x10 = 0, carry = bit 7 = 1
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 4, "srl_carry")
    assert parse_reg(regs, "x10") == 0, "SRL carry-out result expected 0"
    assert parse_pstatus(regs) & 1 == 1, "SRL carry-out expected 1"
    print("  O-Type SRL carry-out: PASS")


def test_shift_zero_count_preserves_carry(qemu, tmpdir):
    """A zero-count O-Type shift leaves the operand and the carry intact."""
    # SLL by 0 preserves C=1 and the value.
    insns = [
        encode_addi_d(5, 0, 10),      # x10 = 5 (value)
        encode_subi_d(0, 10, 0),      # 5 - 0 sets C=1 (no borrow)
        encode_sll(0, 10),            # count = x0 = 0 -> preserve C, keep x10
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 4, "sll_zero_c1")
    assert parse_reg(regs, "x10") == 5, "SLL #0 must not change the operand"
    assert parse_pstatus(regs) & 1 == 1, "SLL #0 must preserve C=1"
    # SRL by 0 preserves C=0 and the value.
    insns = [
        encode_addi_d(9, 0, 10),      # x10 = 9 (value)
        encode_addi_d(0, 0, 12),      # x12 = 0
        encode_subi_d(5, 12, 0),      # 0 - 5: C=0 (borrow)
        encode_srl(0, 10),            # count = x0 = 0 -> preserve C, keep x10
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 5, "srl_zero_c0")
    assert parse_reg(regs, "x10") == 9, "SRL #0 must not change the operand"
    assert parse_pstatus(regs) & 1 == 0, "SRL #0 must preserve C=0"
    print("  O-Type shift zero-count carry preservation: PASS")


def test_same_register_operand_staging(qemu, tmpdir):
    """Source staging overlays destination resolution for aliased operands."""
    data_offset = 0x200
    data_addr = RAM_ENTRY + data_offset
    first = 0x1122334455667788
    second = 0x8877665544332211
    insns = (
        load_imm(10, data_addr) +
        [
            # The destination must use data_addr + 8 and leave x10 += 16.
            encode_o_type(1, 2, 10, 2, 10),
            encode_o_type(1, 0, 10, 0, 15),  # preserve double-update result
            encode_addi_d(-8, 10, 11),
            encode_o_type(1, 1, 11, 0, 12),
            # Direct x10 must read the staged data_addr + 24, then win.
            encode_o_type(2, 2, 10, 0, 10),
            encode_nop(),
        ]
    )
    payload = bytearray(data_offset + 24)
    struct.pack_into(f"<{len(insns)}I", payload, 0, *insns)
    struct.pack_into("<QQQ", payload, data_offset, first, second, 3)
    regs = run_program(
        qemu, tmpdir, insns, len(insns), "same_reg_staging",
        payload=bytes(payload),
    )

    assert parse_reg(regs, "x15") == data_addr + 16
    assert parse_reg(regs, "x12") == first
    assert parse_reg(regs, "x10") == data_addr + 27
    print("  Same-register source/destination staging and snapshots: PASS")


def test_same_register_fault_rollback(qemu, tmpdir):
    """A destination page fault discards both aliased autoincrements."""
    handler_addr = RAM_ENTRY
    for _ in range(8):
        preamble = (
            load_imm(14, handler_addr) +
            [encode_c_type(0, 0, 14, 1)] +
            load_imm(12, P39_SATP) +
            [encode_c_type(0, 0, 12, 6)] +
            load_imm(10, P39_SAME_REG_VA)
        )
        fault_index = len(preamble)
        handler_index = fault_index + 3
        new_handler_addr = RAM_ENTRY + handler_index * 4
        if new_handler_addr == handler_addr:
            break
        handler_addr = new_handler_addr
    else:
        raise RuntimeError("same-register fault handler layout did not settle")

    faulting_mov = encode_o_type(1, 2, 10, 2, 10)
    insns = preamble + [
        faulting_mov,
        encode_addi_d(99, 0, 21),
        encode_branch(0, -1),
        encode_addi_d(77, 0, 13),
        encode_nop(),
    ]
    regs = run_program(
        qemu, tmpdir, insns, len(preamble) + 2, "same_reg_fault",
        payload=same_reg_fault_payload(insns),
    )

    assert parse_csr(regs, "CAUSE") == 14
    assert parse_csr(regs, "TVAL") == P39_SAME_REG_NEXT_VA
    assert parse_csr(regs, "EPC") == RAM_ENTRY + fault_index * 4
    assert parse_reg(regs, "x10") == P39_SAME_REG_VA
    assert parse_reg(regs, "x13") == 77
    assert parse_reg(regs, "x21") != 99
    assert parse_retired(regs) == len(preamble) + 2
    print("  Same-register destination-fault staged rollback: PASS")


def _branch_marker(qemu, tmpdir, name, condition, setup, expect_taken):
    """Execute a B-Type branch and confirm taken/not-taken via marker x20.

    After `setup`, a taken branch skips the not-taken block (x20=5) and lands
    on the taken marker (x20=9); a not-taken branch falls through, and the
    trailing unconditional BR keeps it from also reaching the taken marker."""
    body = setup + [
        encode_branch(condition, 2),  # taken -> skip the not-taken block
        encode_addi_d(5, 0, 20),      # not-taken marker: x20 = 5
        encode_branch(0, 1),          # unconditional: skip the taken marker
        encode_addi_d(9, 0, 20),      # taken marker: x20 = 9
        encode_nop(),
    ]
    stop = len(setup) + (3 if expect_taken else 4)
    regs = run_program(qemu, tmpdir, body, stop, name)
    x20 = parse_reg(regs, "x20")
    expected = 9 if expect_taken else 5
    disposition = "taken" if expect_taken else "not-taken"
    assert x20 == expected, \
        f"{name}: x20={x20}, expected {expected} ({disposition})"


# Flag-producing setups. The final NZVC state of each drives the predicate
# under test; states are verified against gen_sub_flags/gen_add_flags.
def _flags_eq():   # Z=1, C=1, N=0, V=0
    return [encode_addi_d(5, 0, 10), encode_subi_d(5, 10, 0)]


def _flags_gt():   # Z=0, C=1, N=0, V=0 (positive result, N==V)
    return [encode_addi_d(5, 0, 10), encode_subi_d(3, 10, 0)]


def _flags_lt():   # Z=0, C=0, N=1, V=0 (N!=V)
    return [encode_addi_d(1, 0, 10), encode_subi_d(5, 10, 0)]


def _flags_c0():   # C=0
    return [encode_addi_d(0, 0, 10), encode_subi_d(5, 10, 0)]


def _flags_c1():   # C=1
    return [encode_addi_d(5, 0, 10), encode_subi_d(3, 10, 0)]


def _flags_v1():   # V=1, N=1, Z=0, C=0 (0x7fff... + 1 overflows)
    return [
        encode_addi_d((-1) & 0x3FFF, 0, 10),
        encode_srli_d(1, 10, 10),
        encode_addi_d(1, 10, 0),
    ]


def _flags_neg():  # N=1, Z=0, V=0, C=0
    return [encode_addi_d((-1) & 0x3FFF, 0, 10), encode_addi_d(0, 10, 0)]


# (mnemonic, condition, taken-setup, not-taken-setup). BR is unconditional so
# it has no not-taken case; condition 15 is illegal (tested separately).
BRANCH_CASES = (
    ("BR",   0,  lambda: [], None),
    ("BEQ",  1,  _flags_eq,  _flags_gt),
    ("BNE",  2,  _flags_gt,  _flags_eq),
    ("BLT",  3,  _flags_lt,  _flags_gt),
    ("BGE",  4,  _flags_gt,  _flags_lt),
    ("BLTU", 5,  _flags_c0,  _flags_c1),
    ("BGEU", 6,  _flags_c1,  _flags_c0),
    ("BGT",  7,  _flags_gt,  _flags_eq),
    ("BLE",  8,  _flags_eq,  _flags_gt),
    ("BCS",  9,  _flags_c1,  _flags_c0),
    ("BCC",  10, _flags_c0,  _flags_c1),
    ("BVS",  11, _flags_v1,  _flags_gt),
    ("BVC",  12, _flags_gt,  _flags_v1),
    ("BMI",  13, _flags_neg, _flags_gt),
    ("BPL",  14, _flags_gt,  _flags_neg),
)


def test_branches(qemu, tmpdir):
    """Every defined B-Type condition (0-14) branches correctly for both the
    taken and not-taken cases. Condition 15 is exercised as illegal below."""
    for name, condition, taken_setup, nottaken_setup in BRANCH_CASES:
        _branch_marker(qemu, tmpdir, f"{name}_taken", condition,
                       taken_setup(), True)
        if nottaken_setup is not None:
            _branch_marker(qemu, tmpdir, f"{name}_nottaken", condition,
                           nottaken_setup(), False)
        coverage = "taken" if nottaken_setup is None else "taken/not-taken"
        print(f"  {name} (cond {condition}) {coverage}: PASS")


def test_exception_illegal(qemu, tmpdir):
    """An illegal instruction traps to tvec with cause=2 without retiring.

    tvec is pointed at a handler block at 0x80001024 (built with LI/SLLI/ADDI
    because the address exceeds a 14-bit immediate); a reserved branch
    condition (15) then triggers the trap and the handler marker is checked."""

    def encode_csrrw(rd, rs, csr):
        return (9 << 28) | (0 << 24) | (rd << 19) | (rs << 14) | (csr << 2)

    handler_addr = RAM_ENTRY + 9 * 4  # handler lives at instruction index 9
    insns = [
        encode_addi_d(1, 0, 10),                       # x10 = 1
        encode_slli_d(31, 10, 10),                     # x10 = 0x80000000
        encode_addi_d(handler_addr & 0x3FFF, 10, 10),  # x10 = 0x80001024
        encode_csrrw(0, 10, 1),                        # tvec = x10
        encode_branch(15, 0),                          # reserved -> illegal
        encode_addi_d(99, 0, 11),                      # never runs (trapped)
        encode_addi_d(99, 0, 12),
        encode_addi_d(99, 0, 13),
        encode_addi_d(99, 0, 14),
        encode_addi_d(77, 0, 15),                      # handler marker
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 6, "illegal")
    # The illegal instruction does not retire; the four setup instructions and
    # the two handler instructions do.
    assert parse_reg(regs, "x15") == 77, "ILLEGAL: handler did not run"
    assert parse_reg(regs, "x11") != 99, "ILLEGAL: post-illegal code ran"
    print("  ILLEGAL exception delivery: PASS")


def test_reserved_branch_15(qemu, tmpdir):
    """Branch condition 15 is reserved and raises illegal-instruction."""
    # Same as above but simpler check: just verify it doesn't crash
    # With tvec pointed at handler
    handler_addr = RAM_ENTRY + 7 * 4

    def encode_csrrw(rd, rs, csr):
        return (
            (9 << 28) | (rd << 19) | (rs << 14) | (csr << 2)
        )

    insns = [
        encode_addi_d(1, 0, 10),
        encode_slli_d(31, 10, 10),
        encode_addi_d((handler_addr & 0x1FFF), 10, 10),  # build addr
        encode_csrrw(0, 10, 1),                     # set tvec
        encode_branch(15, 0),                       # reserved condition
        encode_addi_d(99, 0, 11),                   # should not run
        encode_addi_d(99, 0, 12),                   # should not run
        # handler at index 7:
        encode_addi_d(55, 0, 13),                   # x13 = 55
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 6, "reserved_branch_15")
    x13 = parse_reg(regs, "x13")
    x11 = parse_reg(regs, "x11")
    assert x13 == 55, f"reserved_branch_15: handler didn't run, x13={x13}"
    assert x11 != 99, f"reserved_branch_15: post-illegal code ran"
    print("  Reserved branch 15: PASS")


def test_csr_write_faults(qemu, tmpdir):
    """Invalid control CSR writes trap before either CSR or rd commits."""
    handler_index = 9
    handler_addr = RAM_ENTRY + handler_index * 4

    for name, csr in (("tvec", 1), ("epc", 2), ("satp", 6)):
        if csr == 6:
            source = encode_addi_d(-1, 0, 11)
        else:
            source = encode_addi_d(2, 10, 11)
        bad_write = encode_c_type(0, 12, 11, csr)
        insns = [
            encode_addi_d(1, 0, 10),
            encode_slli_d(31, 10, 10),
            encode_addi_d(handler_addr & 0x1FFF, 10, 10),
            encode_c_type(0, 0, 10, 1),
            source,
            encode_addi_d(55, 0, 12),
            bad_write,
            encode_addi_d(99, 0, 14),
            encode_nop(),
            encode_addi_d(77, 0, 13),
            encode_nop(),
        ]
        regs = run_program(qemu, tmpdir, insns, 8, f"bad_{name}")
        fault_pc = RAM_ENTRY + 6 * 4
        assert parse_csr(regs, "CAUSE") == 2
        assert parse_csr(regs, "TVAL") == bad_write
        assert parse_csr(regs, "EPC") == fault_pc
        assert parse_reg(regs, "x12") == 55
        assert parse_reg(regs, "x13") == 77
        assert parse_reg(regs, "x14") != 99
        if csr == 1:
            assert parse_csr(regs, "TVEC") == handler_addr
        if csr == 6:
            assert parse_csr(regs, "SATP") == 0
        print(f"  Invalid {name} write atomicity/tval: PASS")


def test_privilege_tb_key(qemu, tmpdir):
    """A Kernel TB at an address must not be reused after RTE to User."""
    handler_index = 13
    handler_addr = RAM_ENTRY + handler_index * 4
    privileged_insn = encode_c_type(1, 15, 0, 5)
    insns = [
        privileged_insn,
        encode_addi_d(1, 0, 10),
        encode_slli_d(31, 10, 10),
        encode_addi_d(handler_addr & 0x1FFF, 10, 10),
        encode_c_type(0, 0, 10, 1),
        encode_addi_d(1, 0, 11),
        encode_slli_d(31, 11, 11),
        encode_addi_d(RAM_ENTRY & 0x1FFF, 11, 11),
        encode_c_type(0, 0, 11, 2),
        encode_c_type(8),
        encode_addi_d(99, 0, 12),
        encode_nop(),
        encode_nop(),
        encode_addi_d(77, 0, 14),
        encode_nop(),
    ]
    regs = run_program(qemu, tmpdir, insns, 12, "privilege_tb_key")
    assert parse_csr(regs, "CAUSE") == 10
    assert parse_csr(regs, "TVAL") == privileged_insn
    assert parse_csr(regs, "EPC") == RAM_ENTRY
    assert parse_reg(regs, "x12") != 99
    assert parse_reg(regs, "x14") == 77
    assert parse_retired(regs) == 12
    print("  Privilege-sensitive TB key: PASS")


def test_rte_valid_atomic_restore(qemu, tmpdir):
    """A valid RTE atomically restores privilege/interrupt state and retires."""
    target = RAM_ENTRY + 0x100
    restored_fields = 0xC2B  # KUA|MXR|PIE|N|V|C
    insns = (
        load_imm(10, target) +
        [encode_c_type(0, 0, 10, 2)] +
        load_imm(11, restored_fields) +
        [encode_c_type(0, 0, 11, 0), encode_c_type(8)]
    )
    regs = run_program(qemu, tmpdir, insns, len(insns), "rte_valid")

    assert parse_pc(regs) == target
    assert parse_pstatus(regs) == 0xEBB
    assert parse_csr(regs, "EPC") == target
    assert parse_csr(regs, "CAUSE") == 0
    assert parse_csr(regs, "TVAL") == 0
    assert parse_retired(regs) == len(insns)
    print("  Valid RTE atomic state restore and retirement: PASS")


def test_rte_p39_target_fault(qemu, tmpdir):
    """An invalid P39 epc traps from the unchanged pre-RTE Kernel state."""
    target = 0x40000000
    handler_addr = RAM_ENTRY
    for _ in range(8):
        preamble = (
            load_imm(14, handler_addr) +
            [encode_c_type(0, 0, 14, 1)] +
            load_imm(10, target) +
            [encode_c_type(0, 0, 10, 2)] +
            load_imm(12, P39_SATP) +
            [encode_c_type(0, 0, 12, 6)] +
            load_imm(11, 0xC15) +
            [encode_c_type(0, 0, 11, 0)]
        )
        rte_index = len(preamble)
        handler_index = rte_index + 3
        new_handler_addr = RAM_ENTRY + handler_index * 4
        if new_handler_addr == handler_addr:
            break
        handler_addr = new_handler_addr
    else:
        raise RuntimeError("RTE fault handler layout did not settle")

    insns = preamble + [
        encode_c_type(8),
        encode_addi_d(99, 0, 21),
        encode_branch(0, -1),
        encode_c_type(1, 22, 0, 0),
        encode_nop(),
    ]
    regs = run_program(
        qemu, tmpdir, insns, len(preamble) + 2, "rte_p39_fault",
        payload=p39_payload(insns),
    )

    assert parse_csr(regs, "CAUSE") == 12
    assert parse_csr(regs, "TVAL") == target
    assert parse_csr(regs, "EPC") == RAM_ENTRY + rte_index * 4
    # Trap entry consumed PRV=Kernel and IE=1 from the unchanged old state.
    pstatus = parse_pstatus(regs)
    assert pstatus == 0xC25, f"post-RTE-fault pstatus={pstatus:#x}"
    assert parse_reg(regs, "x22") == 0xC25
    assert parse_reg(regs, "x21") != 99
    assert parse_retired(regs) == len(preamble) + 2
    print("  RTE invalid P39 target precision and old-state trap entry: PASS")


def test_jmp_precise_bare_faults(qemu, tmpdir):
    """JMP target faults must discard autoincrement and retirement."""
    handler_index = 10
    handler_addr = RAM_ENTRY + handler_index * 4

    cases = (
        (
            "misaligned",
            [encode_addi_d(2, 11, 10), encode_nop()],
            handler_addr + 2,
            0,
        ),
        (
            "access",
            [encode_addi_d(1, 0, 10), encode_slli_d(30, 10, 10)],
            0x40000000,
            1,
        ),
    )
    for name, target_setup, expected_target, expected_cause in cases:
        jmp = encode_jmp(2, 10)
        insns = [
            encode_addi_d(1, 0, 11),
            encode_slli_d(31, 11, 11),
            encode_addi_d(handler_addr & 0x1FFF, 11, 11),
            encode_c_type(0, 0, 11, 1),
            *target_setup,
            jmp,
            encode_addi_d(99, 0, 12),
            encode_nop(),
            encode_nop(),
            encode_addi_d(77, 0, 13),
            encode_nop(),
        ]
        regs = run_program(qemu, tmpdir, insns, 8, f"jmp_{name}")
        assert parse_csr(regs, "CAUSE") == expected_cause
        assert parse_csr(regs, "TVAL") == expected_target
        assert parse_csr(regs, "EPC") == RAM_ENTRY + 6 * 4
        assert parse_reg(regs, "x10") == expected_target
        assert parse_reg(regs, "x12") != 99
        assert parse_reg(regs, "x13") == 77
        assert parse_retired(regs) == 8
        print(f"  JMP {name} target precision: PASS")


def test_jmp_precise_p39_page_fault(qemu, tmpdir):
    """A P39 JMP page fault occurs before staged state commits."""
    handler_index = 16
    handler_addr = RAM_ENTRY + handler_index * 4
    satp = 0x1000000000080004
    jmp = encode_jmp(2, 10)
    insns = [
        encode_addi_d(1, 0, 12),
        encode_slli_d(60, 12, 12),
        encode_addi_d(1, 0, 13),
        encode_slli_d(19, 13, 13),
        encode_addi_d(4, 13, 13),
        encode_add_d(13, 12),
        encode_c_type(0, 0, 12, 6),
        encode_addi_d(1, 0, 11),
        encode_slli_d(31, 11, 11),
        encode_addi_d(handler_addr & 0x1FFF, 11, 11),
        encode_c_type(0, 0, 11, 1),
        encode_addi_d(1, 0, 10),
        encode_slli_d(30, 10, 10),
        jmp,
        encode_addi_d(99, 0, 15),
        encode_nop(),
        encode_addi_d(77, 0, 14),
        encode_nop(),
    ]
    regs = run_program(
        qemu, tmpdir, insns, 15, "jmp_page",
        payload=p39_payload(insns),
    )
    assert parse_csr(regs, "SATP") == satp
    assert parse_csr(regs, "CAUSE") == 12
    assert parse_csr(regs, "TVAL") == 0x40000000
    assert parse_csr(regs, "EPC") == RAM_ENTRY + 13 * 4
    assert parse_reg(regs, "x10") == 0x40000000
    assert parse_reg(regs, "x14") == 77
    assert parse_reg(regs, "x15") != 99
    assert parse_retired(regs) == 15
    print("  JMP P39 page-fault precision: PASS")


def test_p39_fatal_trap_vector(qemu, tmpdir):
    """An unmapped P39 tvec is fatal without overwriting trap state."""
    illegal = encode_branch(15, 0)
    insns = [
        encode_addi_d(1, 0, 12),
        encode_slli_d(60, 12, 12),
        encode_addi_d(1, 0, 13),
        encode_slli_d(19, 13, 13),
        encode_addi_d(4, 13, 13),
        encode_add_d(13, 12),
        encode_c_type(0, 0, 12, 6),
        encode_addi_d(1, 0, 10),
        encode_slli_d(30, 10, 10),
        encode_c_type(0, 0, 10, 1),
        encode_addi_d(0x1234, 0, 11),
        encode_c_type(0, 0, 11, 2),
        illegal,
    ]
    kernel = tmpdir / "fatal_tvec.elf"
    make_kernel(kernel, p39_payload(insns))
    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-m", "32M",
        "-kernel", str(kernel),
        "-display", "none",
        "-audio", "none",
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=10
    )
    assert result.returncode != 0, "invalid P39 tvec did not stop the VM"
    assert "is not a Kernel executable target" in result.stderr
    assert parse_csr(result.stderr, "EPC") == 0x1234
    assert parse_csr(result.stderr, "CAUSE") == 0
    assert parse_csr(result.stderr, "TVAL") == 0
    assert parse_retired(result.stderr) == 12
    print("  P39 fatal tvec validation/state preservation: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", type=pathlib.Path)
    args = parser.parse_args()
    qemu = args.qemu.resolve()

    with tempfile.TemporaryDirectory(prefix="pdp12-scalar-") as tmp:
        tmpdir = pathlib.Path(tmp)
        print("PDP-12 scalar/exception tests:")
        test_sll(qemu, tmpdir)
        test_srl(qemu, tmpdir)
        test_sra(qemu, tmpdir)
        test_sll_carry(qemu, tmpdir)
        test_srl_carry(qemu, tmpdir)
        test_shift_zero_count_preserves_carry(qemu, tmpdir)
        test_same_register_operand_staging(qemu, tmpdir)
        test_same_register_fault_rollback(qemu, tmpdir)
        test_branches(qemu, tmpdir)
        test_exception_illegal(qemu, tmpdir)
        test_reserved_branch_15(qemu, tmpdir)
        test_csr_write_faults(qemu, tmpdir)
        test_rte_valid_atomic_restore(qemu, tmpdir)
        test_rte_p39_target_fault(qemu, tmpdir)
        test_privilege_tb_key(qemu, tmpdir)
        test_jmp_precise_bare_faults(qemu, tmpdir)
        test_jmp_precise_p39_page_fault(qemu, tmpdir)
        test_p39_fatal_trap_vector(qemu, tmpdir)
    print("PDP-12 scalar/exception tests: ALL PASS")


if __name__ == "__main__":
    main()
