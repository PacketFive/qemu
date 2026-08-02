#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""PDP-12 P39 MMU tests: A/D setting, MXR, KUA, and TLB mutation/invalidation.

These tests build a real three-level P39 page table in guest RAM, enable
translation, execute loads/stores through fine-grained leaves, and then
inspect the *architectural* results: guest registers and the raw in-memory
PTE bytes (read back with pmemsave). They verify the hardware-managed A/D
compare-and-swap actually lands in RAM, that MXR/KUA gate permission checks,
and that SFENCE.VM makes PTE mutations/invalidations visible while a stale
TLB entry survives until it is flushed.
"""

import argparse
import json
import pathlib
import re
import struct
import subprocess
import tempfile


# Physical layout inside the loaded kernel image (identity mapped by L2[2]).
RAM_BASE = 0x80000000
RAM_ENTRY = 0x80001000
VIRTUAL_ENTRY = 0xFFFFFFC000001000
L2_ROOT_PA = 0x80004000
L1_PA = 0x80005000
L0_PA = 0x80006000
DATA0_PA = 0x80007000
DATA1_PA = 0x80008000
PAYLOAD_SIZE = 0x9000

SATP = (1 << 60) | (L2_ROOT_PA >> 12)      # P39 mode, root = L2_ROOT_PA
TEST_VA = 0x40000000                        # VPN2=1 -> L1[0] -> L0[0]

# PTE bit helpers.
PTE_V, PTE_R, PTE_W, PTE_X, PTE_U, PTE_A, PTE_D = (
    1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 6, 1 << 7)

# Identity leaf for the whole 0x80000000-0xBFFFFFFF gigapage: RWX, A+D preset
# so instruction fetch and kernel PTE writes never churn A/D on it.
IDENTITY_LEAF = ((RAM_BASE >> 12) << 10) | (
    PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)

MARKER = 0x99  # written to x20 by the trap handler when a fault is taken

# Additional physical pages and virtual addresses for the leaf-size,
# permission, canonicality and dirty-exactness tests.
GIGAPAGE_VA = 0x40007000        # VPN2=1, offset 0x7000 into the 1 GiB leaf
UNMAPPED_PA = 0x90000000        # beyond the 32 MiB of test RAM
NONCANONICAL_VA = 0x8000000000  # bit 39 set while bit 38 is clear
ROM_TABLE_PA = 0x2000
XIC_BASE = 0x0C000000
XIC_ENABLE = XIC_BASE + 8
SECOND_TABLE_VA = TEST_VA + 0x200000
MMIO_TABLE_VA = SECOND_TABLE_VA + 0x1000


def leaf(pa, flags):
    """Build a leaf PTE mapping physical page `pa` with `flags`."""
    return ((pa >> 12) << 10) | flags


# --- Instruction encoders (subset needed here; match target/pdp12) -----------

def encode_addi_d(imm14, src, dst):
    return (0xA << 28) | (src << 19) | (dst << 14) | (imm14 & 0x3FFF)


def encode_slli_d(count, src, dst):
    return (0xA << 28) | (5 << 24) | (src << 19) | (dst << 14) | (count & 0x3F)


def encode_ori_d(imm14, src, dst):
    return ((0xA << 28) | (3 << 24) | (src << 19) |
            (dst << 14) | (imm14 & 0x3FFF))


def encode_c_type(subop, rd=0, rs=0, csr=0):
    return (9 << 28) | (subop << 24) | (rd << 19) | (rs << 14) | (csr << 2)


def encode_o_type(op, src_mode, src_reg, dst_mode, dst_reg, disp=0):
    return (
        (op << 26) | (src_mode << 23) | (src_reg << 18) |
        (dst_mode << 15) | (dst_reg << 10) | (disp & 0x3FF)
    )


def encode_mov_load(addr_reg, dst_reg):
    """dst = mem[addr_reg] (register-deferred source, 64-bit)."""
    return encode_o_type(1, 1, addr_reg, 0, dst_reg)


def encode_mov_store(src_reg, addr_reg):
    """mem[addr_reg] = src_reg (register-deferred destination, 64-bit)."""
    return encode_o_type(1, 0, src_reg, 1, addr_reg)


def encode_branch(condition, offset20):
    return (0x60 << 25) | (condition << 20) | (offset20 & 0xFFFFF)


def encode_s_type(opcode, mode=0, reg=0, disp=0):
    return (opcode << 20) | (mode << 17) | (reg << 12) | (disp & 0xFFF)


def encode_jsr(mode, reg):
    return encode_s_type(0x807, mode, reg)


def encode_rts():
    return encode_s_type(0x808)


def encode_mov_reg(src, dst):
    return encode_o_type(1, 0, src, 0, dst)


def br_self():
    """One-instruction self-loop; parks the CPU until stop-after-insns."""
    return encode_branch(0, (-1) & 0xFFFFF)


def load_imm(reg, value):
    """Materialise an arbitrary unsigned value into `reg` using ADDI/SLLI/ORI.

    The value is built most-significant 12-bit chunk first so intermediate
    results never overflow 64 bits.
    """
    value &= (1 << 64) - 1
    parts = []
    tmp = value
    while tmp:
        parts.append(tmp & 0xFFF)
        tmp >>= 12
    insns = [encode_addi_d(0, 0, reg)]  # reg = 0
    for chunk in reversed(parts):
        insns.append(encode_slli_d(12, reg, reg))
        if chunk:
            insns.append(encode_ori_d(chunk, reg, reg))
    return insns


# --- Program / payload assembly ---------------------------------------------

# Register conventions inside test programs:
#   r10 = TEST_VA          r12 = satp scratch      r14 = tvec scratch
#   r15 = pstatus scratch  r16..r22 = load results / mutation scratch
#   x20 = fault marker (set by handler)

def preamble(handler_pa, set_bits=0, before_satp=()):
    """Set tvec, optionally OR bits into pstatus (KUA/MXR), then enable P39."""
    insns = []
    insns += load_imm(14, handler_pa)
    insns.append(encode_c_type(0, 0, 14, 1))      # tvec = r14
    if set_bits:
        insns += load_imm(15, set_bits)
        insns.append(encode_c_type(1, 0, 15, 0))  # pstatus |= r15 (CSRRS)
    insns += before_satp
    insns += load_imm(12, SATP)
    insns.append(encode_c_type(0, 0, 12, 6))      # satp = r12 -> P39 active
    return insns


def assemble(body, set_bits=0, before_satp=()):
    """Wrap a test body with a P39 preamble, a terminal self-loop and a
    trap handler (which records MARKER in x20 and parks). The trap vector
    address is solved to a fixed point across encoding-length changes."""
    handler_pa = RAM_ENTRY
    for _ in range(8):
        pre = preamble(handler_pa, set_bits, before_satp)
        terminal = [br_self()]
        handler = [encode_addi_d(MARKER, 0, 20), br_self()]
        program = pre + body + terminal + handler
        new_handler_pa = RAM_ENTRY + (len(pre) + len(body) + len(terminal)) * 4
        if new_handler_pa == handler_pa:
            return program
        handler_pa = new_handler_pa
    raise RuntimeError("trap-vector layout did not converge")


def make_payload(program, leaf_value, data0=0, data1=0, extra_ptes=None):
    payload = bytearray(PAYLOAD_SIZE)
    code = struct.pack(f"<{len(program)}I", *program)
    assert len(code) < (L2_ROOT_PA - RAM_ENTRY), "code overruns page tables"
    payload[:len(code)] = code

    def put(pa, value):
        struct.pack_into("<Q", payload, pa - RAM_ENTRY, value)

    put(L2_ROOT_PA + 2 * 8, IDENTITY_LEAF)             # 0x8xxxxxxx identity
    put(L2_ROOT_PA + 1 * 8, leaf(L1_PA, PTE_V))        # -> L1 table
    put(L1_PA + 0 * 8, leaf(L0_PA, PTE_V))             # -> L0 table
    put(L0_PA + 0 * 8, leaf_value)                     # fine-grained leaf
    put(DATA0_PA, data0)
    put(DATA1_PA, data1)
    for pa, value in (extra_ptes or {}).items():
        put(pa, value)
    return bytes(payload)


def make_kernel(path, payload):
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


# --- QMP driver --------------------------------------------------------------

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
                raise RuntimeError(
                    f"QMP command failed: {response['error']!r}")
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


def run(qemu, tmpdir, name, program, leaf_value, *, set_bits=0,
        data0=0, data1=0, extra_ptes=None, reads=(), stop=400,
        extra_args=()):
    """Run one P39 program and return (register-dump text, {pa: qword})."""
    payload = make_payload(program, leaf_value, data0, data1, extra_ptes)
    kernel = tmpdir / f"{name}.elf"
    make_kernel(kernel, payload)

    command = [
        str(qemu), "-M", "pdp12-virt",
        "-global", f"pdp12-cpu.stop-after-insns={stop}",
        "-m", "32M", "-kernel", str(kernel),
        "-display", "none", "-audio", "none", "-S", "-qmp", "stdio",
        *extra_args,
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    try:
        qmp = QMP(process)
        if "QMP" not in qmp.read():
            raise RuntimeError("invalid QMP greeting")
        qmp.command("qmp_capabilities")
        qmp.command("cont")
        qmp.wait_event("STOP")
        registers = qmp.command(
            "human-monitor-command", {"command-line": "info registers"})
        memory = {}
        for pa in reads:
            out = tmpdir / f"{name}-{pa:x}.bin"
            err = qmp.command(
                "human-monitor-command",
                {"command-line": f'pmemsave 0x{pa:x} 8 "{out}"'})
            if err:
                raise RuntimeError(f"pmemsave failed: {err.strip()}")
            memory[pa] = struct.unpack("<Q", out.read_bytes())[0]
        return registers, memory
    finally:
        process.terminate()
        process.communicate(timeout=10)


def reg(text, name):
    match = re.search(rf"{name}\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"cannot find {name} in:\n{text}")
    return int(match.group(1), 16)


# --- Tests -------------------------------------------------------------------

def test_a_bit_set(qemu, tmpdir):
    """A load through an A=0 leaf sets A (only) in the in-memory PTE."""
    data = 0xCAFEF00D12345678
    leaf_value = leaf(DATA0_PA, PTE_V | PTE_R | PTE_W)  # A=0, D=0
    body = load_imm(10, TEST_VA) + [encode_mov_load(10, 11)]
    regs, mem = run(qemu, tmpdir, "a_bit", assemble(body), leaf_value,
                    data0=data, reads=(L0_PA,))
    assert reg(regs, "x11") == data, f"load result {reg(regs,'x11'):#x}"
    assert reg(regs, "x20") == 0, "unexpected trap"
    assert reg(regs, "CAUSE") == 0, "unexpected cause"
    pte = mem[L0_PA]
    assert pte & PTE_A, f"A not set in PTE {pte:#x}"
    assert not (pte & PTE_D), f"D wrongly set in PTE {pte:#x}"
    expected_pte = leaf_value | PTE_A
    assert pte == expected_pte, f"PTE {pte:#x} != {expected_pte:#x}"
    print("  A-bit set on load (PTE writeback verified): PASS")


def test_d_bit_load_then_store(qemu, tmpdir):
    """A store after a load of the same clean page sets D on the store.

    The load publishes A only; the store re-walks, completes its physical
    write and only then publishes D through a compare-and-swap."""
    leaf_value = leaf(DATA0_PA, PTE_V | PTE_R | PTE_W)  # A=0, D=0
    body = (
        load_imm(10, TEST_VA) +
        [encode_mov_load(10, 11)] +          # load: sets A, masks write
        load_imm(13, 0x55) +
        [encode_mov_store(13, 10)]           # store: re-walk, sets D
    )
    regs, mem = run(qemu, tmpdir, "d_bit", assemble(body), leaf_value,
                    reads=(L0_PA, DATA0_PA))
    pte = mem[L0_PA]
    assert reg(regs, "x20") == 0, "unexpected trap"
    assert pte & PTE_A, f"A not set in PTE {pte:#x}"
    assert pte & PTE_D, f"D not set in PTE {pte:#x}"
    assert pte == leaf_value | PTE_A | PTE_D, f"PTE {pte:#x}"
    assert mem[DATA0_PA] == 0x55, f"store did not land: {mem[DATA0_PA]:#x}"
    print("  D-bit set on load-then-store (masking + CAS verified): PASS")


def test_mxr(qemu, tmpdir):
    """An execute-only leaf (R=0,X=1): load faults unless MXR=1."""
    data = 0x0BADF00DFEEDFACE
    leaf_value = leaf(DATA0_PA, PTE_V | PTE_X | PTE_A)  # R=0
    body = load_imm(10, TEST_VA) + [encode_mov_load(10, 11)]

    # MXR=0: load-page-fault (cause 13), handler marker set.
    regs, _ = run(qemu, tmpdir, "mxr_off", assemble(body), leaf_value,
                  data0=data)
    assert reg(regs, "x20") == MARKER, "MXR=0 load should fault"
    assert reg(regs, "CAUSE") == 13, f"cause {reg(regs,'CAUSE')}"
    assert reg(regs, "EPC") != 0

    # MXR=1: load succeeds and returns the data word.
    regs, _ = run(qemu, tmpdir, "mxr_on", assemble(body, set_bits=(1 << 11)),
                  leaf_value, data0=data)
    assert reg(regs, "x20") == 0, "MXR=1 load should succeed"
    assert reg(regs, "x11") == data, f"x11 {reg(regs,'x11'):#x}"
    print("  MXR gates load of execute-only page: PASS")


def test_kua(qemu, tmpdir):
    """A user leaf (U=1): kernel load faults unless KUA=1."""
    data = 0x1234567887654321
    leaf_value = leaf(DATA0_PA, PTE_V | PTE_R | PTE_U | PTE_A)
    body = load_imm(10, TEST_VA) + [encode_mov_load(10, 11)]

    # KUA=0: kernel data access to user page faults (cause 13).
    regs, _ = run(qemu, tmpdir, "kua_off", assemble(body), leaf_value,
                  data0=data)
    assert reg(regs, "x20") == MARKER, "KUA=0 kernel load should fault"
    assert reg(regs, "CAUSE") == 13, f"cause {reg(regs,'CAUSE')}"

    # KUA=1: kernel load of user page succeeds.
    regs, _ = run(qemu, tmpdir, "kua_on", assemble(body, set_bits=(1 << 10)),
                  leaf_value, data0=data)
    assert reg(regs, "x20") == 0, "KUA=1 kernel load should succeed"
    assert reg(regs, "x11") == data, f"x11 {reg(regs,'x11'):#x}"
    print("  KUA gates kernel access to user page: PASS")


def test_remap_data_and_fetch(qemu, tmpdir):
    """Data accesses re-walk immediately; instruction fetch needs SFENCE.VM.

    P1 permits, but does not require, caching successful translations. This
    model keeps no data translation cache - every data access re-walks the
    table, exactly like the reference emulator - so a leaf rewrite is visible
    to the next load without SFENCE.VM. Instruction fetch does use a cached
    translation, so a code remap only takes effect after SFENCE.VM.
    """
    data0 = 0x1111111122222222
    data1 = 0x3333333344444444
    leaf0 = leaf(DATA0_PA, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    leaf1 = leaf(DATA1_PA, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    body = (
        load_imm(10, TEST_VA) +
        [encode_mov_load(10, 16)] +          # first load -> data0
        load_imm(17, L0_PA) +
        load_imm(18, leaf1) +
        [encode_mov_store(18, 17)] +         # rewrite leaf to map data1
        [encode_mov_load(10, 21)] +          # no sfence: re-walk sees data1
        [encode_c_type(9)] +                 # SFENCE.VM
        [encode_mov_load(10, 22)]            # after sfence: data1
    )
    regs, mem = run(qemu, tmpdir, "remap", assemble(body), leaf0,
                    data0=data0, data1=data1, reads=(L0_PA,))
    assert reg(regs, "x20") == 0, "unexpected trap"
    assert reg(regs, "x16") == data0, f"first load {reg(regs,'x16'):#x}"
    assert reg(regs, "x21") == data1, f"re-walked load {reg(regs,'x21'):#x}"
    assert reg(regs, "x22") == data1, f"post-sfence load {reg(regs,'x22'):#x}"
    assert mem[L0_PA] == leaf1, f"leaf not rewritten: {mem[L0_PA]:#x}"
    print("  Data remap re-walks without SFENCE.VM (no data TLB): PASS")

    # Instruction fetch: the cached translation survives the leaf rewrite.
    code_a = (encode_addi_d(0xA1, 0, 16) | (encode_rts() << 32))
    code_b = (encode_addi_d(0xB2, 0, 16) | (encode_rts() << 32))
    exec0 = leaf(DATA0_PA, PTE_V | PTE_R | PTE_X | PTE_A)
    exec1 = leaf(DATA1_PA, PTE_V | PTE_R | PTE_X | PTE_A)
    body = (
        load_imm(10, TEST_VA) +
        [encode_jsr(1, 10), encode_mov_reg(16, 17)] +
        load_imm(11, L0_PA) +
        load_imm(12, exec1) +
        [encode_mov_store(12, 11)] +         # remap the code leaf
        [encode_jsr(1, 10), encode_mov_reg(16, 18)] +
        [encode_c_type(9)] +                 # SFENCE.VM
        [encode_jsr(1, 10), encode_mov_reg(16, 19)]
    )
    regs, _ = run(qemu, tmpdir, "remap_fetch", assemble(body), exec0,
                  extra_ptes={DATA0_PA: code_a, DATA1_PA: code_b})
    assert reg(regs, "x20") == 0, "unexpected trap"
    assert reg(regs, "x17") == 0xA1, f"first call {reg(regs,'x17'):#x}"
    assert reg(regs, "x18") == 0xA1, f"stale fetch {reg(regs,'x18'):#x}"
    assert reg(regs, "x19") == 0xB2, f"post-sfence fetch {reg(regs,'x19'):#x}"
    print("  Instruction remap requires SFENCE.VM (fetch TLB flush): PASS")


def test_invalidate_sfence(qemu, tmpdir):
    """Clearing V makes the next data access page-fault immediately."""
    data0 = 0x00DECAFC0FFEE000
    leaf0 = leaf(DATA0_PA, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    body = (
        load_imm(10, TEST_VA) +
        [encode_mov_load(10, 16)] +          # first load succeeds
        load_imm(17, L0_PA) +
        load_imm(18, 0) +
        [encode_mov_store(18, 17)] +         # invalidate leaf (V=0)
        [encode_c_type(9)] +                 # SFENCE.VM
        [encode_mov_load(10, 19)]            # re-load -> page fault
    )
    regs, mem = run(qemu, tmpdir, "invalidate", assemble(body), leaf0,
                    data0=data0, reads=(L0_PA,))
    assert reg(regs, "x16") == data0, f"first load {reg(regs,'x16'):#x}"
    assert reg(regs, "x20") == MARKER, "invalidated access should fault"
    assert reg(regs, "CAUSE") == 13, f"cause {reg(regs,'CAUSE')}"
    assert reg(regs, "TVAL") == TEST_VA, f"tval {reg(regs,'TVAL'):#x}"
    assert mem[L0_PA] == 0, f"leaf not invalidated: {mem[L0_PA]:#x}"
    print("  Invalidate + SFENCE.VM faults on stale mapping: PASS")


def test_leaf_sizes(qemu, tmpdir):
    """P39 resolves 4 KiB, 2 MiB and 1 GiB leaves, and rejects a misaligned
    superpage PPN."""
    data = 0x00C0FFEE0BADCAFE
    # 1 GiB leaf directly at level 2: VA 0x40000000 maps to PA 0x80000000.
    giga_leaf = leaf(RAM_BASE, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    body = load_imm(10, GIGAPAGE_VA) + [encode_mov_load(10, 11)]
    regs, _ = run(qemu, tmpdir, "gigapage", assemble(body), 0,
                  data0=data,
                  extra_ptes={L2_ROOT_PA + 1 * 8: giga_leaf})
    assert reg(regs, "x20") == 0, "unexpected trap"
    assert reg(regs, "x11") == data, f"1 GiB leaf load {reg(regs,'x11'):#x}"
    print("  1 GiB leaf translation: PASS")

    # 2 MiB leaf at level 1: VA 0x40000000 maps to PA 0x80000000.
    mega_leaf = leaf(RAM_BASE, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    regs, _ = run(qemu, tmpdir, "megapage", assemble(body), 0,
                  data0=data, extra_ptes={L1_PA + 0 * 8: mega_leaf})
    assert reg(regs, "x20") == 0, "unexpected trap"
    assert reg(regs, "x11") == data, f"2 MiB leaf load {reg(regs,'x11'):#x}"
    print("  2 MiB leaf translation: PASS")

    # 4 KiB leaf at level 0 for the same offset.
    fine_leaf = leaf(DATA0_PA, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    body4k = load_imm(10, TEST_VA + 0) + [encode_mov_load(10, 11)]
    regs, _ = run(qemu, tmpdir, "fourk", assemble(body4k), fine_leaf,
                  data0=data)
    assert reg(regs, "x11") == data, f"4 KiB leaf load {reg(regs,'x11'):#x}"
    print("  4 KiB leaf translation: PASS")

    # A 2 MiB leaf whose PPN is not 2 MiB aligned is invalid.
    bad_leaf = leaf(RAM_BASE + 0x1000, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    regs, _ = run(qemu, tmpdir, "misaligned_superpage", assemble(body), 0,
                  data0=data, extra_ptes={L1_PA + 0 * 8: bad_leaf})
    assert reg(regs, "x20") == MARKER, "misaligned superpage should fault"
    assert reg(regs, "CAUSE") == 13, f"cause {reg(regs,'CAUSE')}"
    assert reg(regs, "TVAL") == GIGAPAGE_VA, f"tval {reg(regs,'TVAL'):#x}"
    print("  Misaligned superpage PPN rejected: PASS")


def test_canonicality(qemu, tmpdir):
    """A noncanonical virtual address page-faults before any table walk."""
    leaf_value = leaf(DATA0_PA, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    body = load_imm(10, NONCANONICAL_VA) + [encode_mov_load(10, 11)]
    regs, _ = run(qemu, tmpdir, "noncanonical", assemble(body), leaf_value)
    assert reg(regs, "x20") == MARKER, "noncanonical access should fault"
    assert reg(regs, "CAUSE") == 13, f"cause {reg(regs,'CAUSE')}"
    assert reg(regs, "TVAL") == NONCANONICAL_VA, f"tval {reg(regs,'TVAL'):#x}"
    print("  Noncanonical virtual address rejected: PASS")


def test_invalid_pte_patterns(qemu, tmpdir):
    """W=1,R=0 leaves, reserved bits and non-leaf A/D/U are all invalid."""
    cases = (
        ("write_only", leaf(DATA0_PA, PTE_V | PTE_W | PTE_A), None),
        ("reserved_low", leaf(DATA0_PA, PTE_V | PTE_R | PTE_A | (1 << 5)),
         None),
        ("reserved_high",
         leaf(DATA0_PA, PTE_V | PTE_R | PTE_A) | (1 << 54), None),
        ("nonleaf_accessed", None,
         {L1_PA + 0 * 8: leaf(L0_PA, PTE_V | PTE_A)}),
        ("nonleaf_user", None,
         {L1_PA + 0 * 8: leaf(L0_PA, PTE_V | PTE_U)}),
    )
    body = load_imm(10, TEST_VA) + [encode_mov_load(10, 11)]
    for name, leaf_value, extras in cases:
        regs, _ = run(qemu, tmpdir, f"pte_{name}", assemble(body),
                      leaf_value if leaf_value is not None
                      else leaf(DATA0_PA, PTE_V | PTE_R | PTE_A),
                      extra_ptes=extras)
        assert reg(regs, "x20") == MARKER, f"{name}: expected a fault"
        assert reg(regs, "CAUSE") == 13, f"{name}: cause {reg(regs,'CAUSE')}"
        assert reg(regs, "TVAL") == TEST_VA, f"{name}: tval"
        print(f"  Invalid PTE pattern {name.replace('_', ' ')}: PASS")


def test_store_permission(qemu, tmpdir):
    """A store to a read-only leaf page-faults and never sets D."""
    leaf_value = leaf(DATA0_PA, PTE_V | PTE_R | PTE_A)     # no W
    body = (load_imm(10, TEST_VA) + load_imm(11, 0x55) +
            [encode_mov_store(11, 10)])
    regs, mem = run(qemu, tmpdir, "store_ro", assemble(body), leaf_value,
                    reads=(L0_PA, DATA0_PA))
    assert reg(regs, "x20") == MARKER, "store to read-only should fault"
    assert reg(regs, "CAUSE") == 14, f"cause {reg(regs,'CAUSE')}"
    assert reg(regs, "TVAL") == TEST_VA, f"tval {reg(regs,'TVAL'):#x}"
    assert mem[L0_PA] == leaf_value, f"PTE changed: {mem[L0_PA]:#x}"
    assert mem[DATA0_PA] == 0, "store landed despite the page fault"
    print("  Store to a read-only page faults with D untouched: PASS")


def test_dirty_exactness(qemu, tmpdir):
    """A store that faults on the final physical access must not set D.

    The leaf is writable and its A bit is clear, but it maps to physical
    space the platform does not implement. P1 Section 8 allows A to be
    published before a later stage faults, and requires D to be exact, so the
    in-memory PTE must come back with A set and D clear while the store
    reports a store access fault.
    """
    leaf_value = leaf(UNMAPPED_PA, PTE_V | PTE_R | PTE_W)   # A=0, D=0
    body = (load_imm(10, TEST_VA) + load_imm(11, 0xDEAD) +
            [encode_mov_store(11, 10)])
    regs, mem = run(qemu, tmpdir, "dirty_exact", assemble(body), leaf_value,
                    reads=(L0_PA,))
    assert reg(regs, "x20") == MARKER, "unmapped store should fault"
    assert reg(regs, "CAUSE") == 7, f"cause {reg(regs,'CAUSE')}"
    assert reg(regs, "TVAL") == TEST_VA, f"tval {reg(regs,'TVAL'):#x}"
    pte = mem[L0_PA]
    assert pte & PTE_A, f"A not published: {pte:#x}"
    assert not (pte & PTE_D), f"D set by a faulting store: {pte:#x}"
    assert pte == leaf_value | PTE_A, f"PTE {pte:#x}"
    print("  Faulting final store leaves D clear (A published): PASS")


def test_self_pte_store(qemu, tmpdir):
    """A store through a leaf onto that leaf's own PTE leaves D set."""
    new_leaf = leaf(DATA1_PA, PTE_V | PTE_R | PTE_W | PTE_A)
    body = (
        load_imm(10, TEST_VA) +
        load_imm(11, new_leaf) +
        [encode_mov_store(11, 10)]
    )
    for name, initial_dirty in (("clean", False), ("dirty", True)):
        old_leaf = leaf(L0_PA, PTE_V | PTE_R | PTE_W | PTE_A |
                       (PTE_D if initial_dirty else 0))
        regs, mem = run(
            qemu, tmpdir, f"self_pte_store_{name}", assemble(body),
            old_leaf, reads=(L0_PA,))
        assert reg(regs, "x20") == 0, \
            f"{name} self-PTE store unexpectedly trapped"
        assert reg(regs, "CAUSE") == 0, f"cause {reg(regs, 'CAUSE')}"
        assert mem[L0_PA] == new_leaf | PTE_D, \
            f"{name} self-PTE store retired with value {mem[L0_PA]:#x}"
    print("  Store targeting its own leaf PTE retires with D set: PASS")


def test_pte_memory_type(qemu, tmpdir):
    """ROM and MMIO are never legal PTE sources, even for preset A/D."""
    valid_rom_leaf = leaf(DATA0_PA,
                          PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    body = load_imm(10, SECOND_TABLE_VA) + [encode_mov_load(10, 11)]
    regs, _ = run(
        qemu, tmpdir, "rom_page_table", assemble(body),
        leaf(DATA0_PA, PTE_V | PTE_R | PTE_A),
        extra_ptes={
            L1_PA + 1 * 8: leaf(ROM_TABLE_PA, PTE_V),
        },
        extra_args=(
            "-device",
            f"loader,addr={ROM_TABLE_PA:#x},data={valid_rom_leaf:#x},"
            "data-len=8",
        ),
    )
    assert reg(regs, "x20") == MARKER, "ROM PTE read should fault"
    assert reg(regs, "CAUSE") == 5, f"ROM PTE cause {reg(regs, 'CAUSE')}"
    assert reg(regs, "TVAL") == SECOND_TABLE_VA

    # Put a structurally valid A/D-preset leaf in XIC ENABLE before enabling
    # translation, then point an otherwise normal walk at that MMIO qword.
    mmio_pte = leaf(0, PTE_V | PTE_R | PTE_W | PTE_A | PTE_D)
    before_satp = (
        load_imm(16, XIC_ENABLE) +
        load_imm(17, mmio_pte) +
        [encode_mov_store(17, 16)]
    )
    body = load_imm(10, MMIO_TABLE_VA) + [encode_mov_load(10, 11)]
    regs, _ = run(
        qemu, tmpdir, "mmio_page_table",
        assemble(body, before_satp=before_satp),
        leaf(DATA0_PA, PTE_V | PTE_R | PTE_A),
        extra_ptes={
            L1_PA + 1 * 8: leaf(XIC_BASE, PTE_V),
        },
    )
    assert reg(regs, "x20") == MARKER, "MMIO PTE read should fault"
    assert reg(regs, "CAUSE") == 5, f"MMIO PTE cause {reg(regs, 'CAUSE')}"
    assert reg(regs, "TVAL") == MMIO_TABLE_VA
    print("  ROM/MMIO page-table reads raise access faults: PASS")


def test_kernel_fetch_from_user_page(qemu, tmpdir):
    """KUA never permits a Kernel instruction fetch from a User leaf."""
    code = (encode_addi_d(0xA1, 0, 16) | (encode_rts() << 32))
    leaf_value = leaf(DATA0_PA, PTE_V | PTE_R | PTE_X | PTE_U | PTE_A)
    body = load_imm(10, TEST_VA) + [encode_jsr(1, 10)]
    regs, _ = run(qemu, tmpdir, "kernel_fetch_user",
                  assemble(body, set_bits=(1 << 10)), leaf_value,
                  extra_ptes={DATA0_PA: code})
    assert reg(regs, "x20") == MARKER, "kernel fetch from user page must fault"
    assert reg(regs, "CAUSE") == 12, f"cause {reg(regs,'CAUSE')}"
    assert reg(regs, "TVAL") == TEST_VA, f"tval {reg(regs,'TVAL'):#x}"
    assert reg(regs, "x16") == 0, "user page executed in Kernel mode"
    print("  Kernel fetch from a User leaf rejected even with KUA: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", type=pathlib.Path)
    args = parser.parse_args()
    qemu = args.qemu.resolve()

    with tempfile.TemporaryDirectory(prefix="pdp12-p39-") as tmp:
        tmpdir = pathlib.Path(tmp)
        print("PDP-12 P39 MMU tests:")
        test_a_bit_set(qemu, tmpdir)
        test_d_bit_load_then_store(qemu, tmpdir)
        test_mxr(qemu, tmpdir)
        test_kua(qemu, tmpdir)
        test_remap_data_and_fetch(qemu, tmpdir)
        test_invalidate_sfence(qemu, tmpdir)
        test_leaf_sizes(qemu, tmpdir)
        test_canonicality(qemu, tmpdir)
        test_invalid_pte_patterns(qemu, tmpdir)
        test_store_permission(qemu, tmpdir)
        test_dirty_exactness(qemu, tmpdir)
        test_self_pte_store(qemu, tmpdir)
        test_pte_memory_type(qemu, tmpdir)
        test_kernel_fetch_from_user_page(qemu, tmpdir)
    print("PDP-12 P39 MMU tests: ALL PASS")


if __name__ == "__main__":
    main()
