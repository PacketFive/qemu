#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Stateful PDP-V-A0 LR/SC, reservation, fault, and P39 tests."""

import argparse
import json
import pathlib
import re
import struct
import subprocess
import tempfile


RAM_ENTRY = 0x80001000
VIRTUAL_ENTRY = 0xFFFFFFC000001000
HANDLER = 0x80002000
DATA_BASE = 0x80003000
L2_ROOT_PA = 0x80008000
L1_PA = 0x80009000
L0_PA = 0x8000A000
PAYLOAD_END = 0x8000C000
TEST_VA = 0x40000000
ALIAS_VA = TEST_VA + 0x1000
UNMAPPED_PA = 0x90000000
ROM_PA = 0x1000
XIC_GLOBAL_ERROR = 0x0C000008
SATP = (1 << 60) | (L2_ROOT_PA >> 12)
MARKER = 0x99
SENTINEL = 0x5A5

PTE_V, PTE_R, PTE_W, PTE_X, PTE_A, PTE_D = (
    1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 6, 1 << 7)
IDENTITY_LEAF = ((0x80000000 >> 12) << 10) | (
    PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D)

CSR_TVEC = 1
CSR_SATP = 6
A_LR = 0
A_SC = 1
A_SWAP = 2
A_ADD = 3


def encode_addi_d(immediate, source, destination):
    return ((0xA << 28) | (source << 19) | (destination << 14) |
            (immediate & 0x3FFF))


def encode_slli_d(count, source, destination):
    return ((0xA << 28) | (5 << 24) | (source << 19) |
            (destination << 14) | (count & 0x3F))


def encode_ori_d(immediate, source, destination):
    return ((0xA << 28) | (3 << 24) | (source << 19) |
            (destination << 14) | (immediate & 0x3FFF))


def encode_o_type(opcode, source_mode, source, destination_mode,
                  destination, displacement=0):
    return ((opcode << 26) | (source_mode << 23) | (source << 18) |
            (destination_mode << 15) | (destination << 10) |
            (displacement & 0x3FF))


def encode_load_d(address, destination):
    return encode_o_type(1, 1, address, 0, destination)


def encode_store_d(source, address):
    return encode_o_type(1, 0, source, 1, address)


def encode_store_w(source, address):
    return encode_o_type(17, 0, source, 1, address)


def encode_a_type(operation, width, source, address, destination, *,
                  aq=False, rl=False):
    return ((0x70 << 25) | (int(aq) << 24) | (int(rl) << 23) |
            (source << 18) | (address << 13) | (destination << 8) |
            (width << 7) | (operation << 3))


def lr_w(address, destination, *, aq=False):
    return encode_a_type(A_LR, 0, 0, address, destination, aq=aq)


def lr_d(address, destination, *, aq=False):
    return encode_a_type(A_LR, 1, 0, address, destination, aq=aq)


def sc_w(source, address, destination, *, rl=False):
    return encode_a_type(A_SC, 0, source, address, destination, rl=rl)


def sc_d(source, address, destination, *, rl=False):
    return encode_a_type(A_SC, 1, source, address, destination, rl=rl)


def amoswap_w(source, address, destination):
    return encode_a_type(A_SWAP, 0, source, address, destination)


def amoswap_d(source, address, destination):
    return encode_a_type(A_SWAP, 1, source, address, destination)


def amoadd_w(source, address, destination):
    return encode_a_type(A_ADD, 0, source, address, destination)


def encode_csrrw(destination, source, csr):
    return ((9 << 28) | (destination << 19) | (source << 14) | (csr << 2))


def encode_sfence_vm():
    return (9 << 28) | (9 << 24)


def encode_fence(predecessor, successor):
    return (0x71 << 25) | (predecessor << 21) | (successor << 17)


def encode_s_type(opcode):
    return opcode << 20


def encode_s_operand(opcode, mode, register, displacement=0):
    return ((opcode << 20) | (mode << 17) | (register << 12) |
            (displacement & 0xFFF))


def br_self():
    return (0x60 << 25) | 0xFFFFF


def load_imm(register, value):
    value &= (1 << 64) - 1
    chunks = []
    while value:
        chunks.append(value & 0xFFF)
        value >>= 12
    words = [encode_addi_d(0, 0, register)]
    for chunk in reversed(chunks):
        words.append(encode_slli_d(12, register, register))
        if chunk:
            words.append(encode_ori_d(chunk, register, register))
    return words


def trap_preamble():
    return load_imm(30, HANDLER) + [encode_csrrw(0, 30, CSR_TVEC)]


def p39_preamble():
    return trap_preamble() + load_imm(30, SATP) + [
        encode_csrrw(0, 30, CSR_SATP)]


def put_words(payload, address, words):
    for index, word in enumerate(words):
        struct.pack_into("<I", payload, address - RAM_ENTRY + index * 4, word)


def bare_payload(body, *, handler=None, data=None):
    payload = bytearray(PAYLOAD_END - RAM_ENTRY)
    if RAM_ENTRY + len(body) * 4 > HANDLER:
        raise RuntimeError("test body overruns trap handler")
    put_words(payload, RAM_ENTRY, body)
    put_words(payload, HANDLER, handler or [
        encode_addi_d(MARKER, 0, 31), br_self()])
    for address, value in (data or {}).items():
        struct.pack_into("<Q", payload, address - RAM_ENTRY, value)
    return payload


def leaf(physical, flags):
    return ((physical >> 12) << 10) | flags


def p39_payload(body, leaves, *, handler=None, data=None):
    payload = bare_payload(body, handler=handler, data=data)

    def put_qword(address, value):
        struct.pack_into("<Q", payload, address - RAM_ENTRY, value)

    put_qword(L2_ROOT_PA + 2 * 8, IDENTITY_LEAF)
    put_qword(L2_ROOT_PA + 1 * 8, leaf(L1_PA, PTE_V))
    put_qword(L1_PA, leaf(L0_PA, PTE_V))
    for index, value in leaves.items():
        put_qword(L0_PA + index * 8, value)
    return payload


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


class QMP:
    def __init__(self, process):
        self.process = process
        self.events = []

    def read(self):
        line = self.process.stdout.readline()
        if not line:
            error = self.process.stderr.read()
            raise RuntimeError(f"QMP connection closed:\n{error}")
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


def run(qemu, workdir, name, payload, *, reads=(), extra_args=(), stop=200):
    kernel = workdir / f"{name}.elf"
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
        for address, size in reads:
            output = workdir / f"{name}-{address:x}-{size}.bin"
            error = qmp.command(
                "human-monitor-command",
                {"command-line":
                 f'pmemsave 0x{address:x} {size} "{output}"'})
            if error:
                raise RuntimeError(f"pmemsave failed: {error.strip()}")
            memory[address] = int.from_bytes(output.read_bytes(), "little")
        return registers, memory
    finally:
        process.terminate()
        process.communicate(timeout=10)


def field(registers, name):
    match = re.search(
        rf"\b{name}\s*=0x([0-9a-f]+)", registers, re.IGNORECASE)
    if match is None:
        raise RuntimeError(f"cannot find {name} in:\n{registers}")
    return int(match.group(1), 16)


class Checks:
    def __init__(self):
        self.count = 0

    def equal(self, actual, expected, message):
        self.count += 1
        if actual != expected:
            raise AssertionError(
                f"{message}: got {actual:#x}, expected {expected:#x}")

    def true(self, condition, message):
        self.count += 1
        if not condition:
            raise AssertionError(message)


def test_lr_sc_basics(qemu, workdir, checks):
    d0, d1, d2, d3, d4, d5 = [DATA_BASE + index * 0x10
                               for index in range(6)]
    initial = {
        d0: 0xAABBCCDD80000001,
        d1: 0x0123456789ABCDEF,
        d2: 0x2222222222222222,
        d3: 0x3333333333333333,
        d4: 0x4444444444444444,
        d5: 0x5555555555555555,
    }
    body = []
    body += load_imm(10, d0) + load_imm(11, 0x11223344)
    body += [lr_w(10, 12), sc_w(11, 10, 13)]
    body += load_imm(14, d1) + load_imm(15, 0xFEDCBA9876543210)
    body += [lr_d(14, 16), sc_d(15, 14, 17)]
    body += load_imm(18, d2) + load_imm(19, 0xDEAD)
    body += [sc_d(19, 18, 20)]
    body += load_imm(21, d3) + load_imm(22, d4) + load_imm(23, 0xBAD)
    body += [lr_d(21, 24), sc_d(23, 22, 25), sc_d(23, 21, 26)]
    body += load_imm(27, d5) + load_imm(28, 0x12345678)
    body += [lr_d(27, 29), sc_w(28, 27, 30), sc_d(28, 27, 31), br_self()]
    reads = tuple((address, 8) for address in initial)
    regs, mem = run(
        qemu, workdir, "lr-sc-basics", bare_payload(body, data=initial),
        reads=reads)

    checks.equal(field(regs, "x12"), 0xFFFFFFFF80000001,
                 "LR.W sign extension")
    checks.equal(field(regs, "x13"), 0, "SC.W success")
    checks.equal(mem[d0], 0xAABBCCDD11223344, "SC.W exact-width store")
    checks.equal(field(regs, "x16"), initial[d1], "LR.D value")
    checks.equal(field(regs, "x17"), 0, "SC.D success")
    checks.equal(mem[d1], 0xFEDCBA9876543210, "SC.D store")
    checks.equal(field(regs, "x20"), 1, "SC without LR")
    checks.equal(mem[d2], initial[d2], "failed SC without LR did not store")
    checks.equal(field(regs, "x25"), 1, "SC address mismatch")
    checks.equal(field(regs, "x26"), 1,
                 "address-mismatch SC cleared reservation")
    checks.equal(mem[d3], initial[d3], "address mismatch preserved LR word")
    checks.equal(mem[d4], initial[d4], "address mismatch preserved SC word")
    checks.equal(field(regs, "x30"), 1, "SC width mismatch")
    checks.equal(field(regs, "x31"), 1,
                 "width-mismatch SC cleared reservation")
    checks.equal(mem[d5], initial[d5], "width mismatch did not store")
    print("  LR/SC W/D success and mismatch failures: PASS")


def test_sc_success_clears_reservation(qemu, workdir, checks):
    address = DATA_BASE + 0x80
    first = 0x1122334455667788
    second = 0x8877665544332211
    body = load_imm(10, address)
    body += load_imm(11, first) + load_imm(12, second)
    body += [
        lr_d(10, 13),
        sc_d(11, 10, 14),
        sc_d(12, 10, 15),
        br_self(),
    ]
    regs, mem = run(
        qemu, workdir, "sc-success-clears-reservation",
        bare_payload(body, data={address: 0x0102030405060708}),
        reads=((address, 8),))

    checks.equal(field(regs, "x14"), 0, "first matching SC succeeded")
    checks.equal(field(regs, "x15"), 1,
                 "successful SC cleared reservation")
    checks.equal(mem[address], first,
                 "second SC without LR left memory unchanged")
    print("  successful SC clears reservation before next SC: PASS")


def test_register_aliases(qemu, workdir, checks):
    addresses = [DATA_BASE + 0x100 + index * 0x10 for index in range(5)]
    data = {address: 0x100 + index for index, address in enumerate(addresses)}
    body = []
    body += load_imm(10, addresses[0]) + load_imm(12, 0xAAAA)
    body += [lr_d(10, 11), sc_d(12, 10, 10)]
    body += load_imm(13, addresses[1]) + load_imm(14, 0xBBBB)
    body += [lr_d(13, 15), sc_d(14, 13, 14)]
    body += load_imm(16, addresses[2]) + load_imm(17, 0xCCCC)
    body += [lr_d(16, 0), sc_d(17, 16, 0)]
    body += load_imm(18, addresses[3])
    body += [lr_d(18, 19), sc_d(0, 18, 19)]
    body += load_imm(20, addresses[4])
    body += [lr_d(20, 21), sc_d(20, 20, 22), br_self()]
    reads = tuple((address, 8) for address in addresses)
    regs, mem = run(
        qemu, workdir, "register-aliases", bare_payload(body, data=data),
        reads=reads)

    checks.equal(field(regs, "x10"), 0, "rd=rs1 SC status")
    checks.equal(mem[addresses[0]], 0xAAAA, "rd=rs1 address snapshot")
    checks.equal(field(regs, "x14"), 0, "rd=rs2 SC status")
    checks.equal(mem[addresses[1]], 0xBBBB, "rd=rs2 source snapshot")
    checks.equal(field(regs, "x0"), 0, "x0 remains zero")
    checks.equal(mem[addresses[2]], 0xCCCC, "rd=x0 does not suppress LR/SC")
    checks.equal(field(regs, "x19"), 0, "SC with source x0 succeeded")
    checks.equal(mem[addresses[3]], 0, "source x0 stored zero")
    checks.equal(field(regs, "x22"), 0, "rs1=rs2 SC status")
    checks.equal(mem[addresses[4]], addresses[4],
                 "rs1=rs2 captured address as source")
    print("  register aliases, x0, and source snapshots: PASS")


def test_local_invalidation(qemu, workdir, checks):
    addresses = [DATA_BASE + 0x200 + index * 0x20 for index in range(4)]
    initial = {
        addresses[0]: 0x1111222233334444,
        addresses[1]: 0x2222333344445555,
        addresses[1] + 8: 0xAAAAAAAAAAAAAAAA,
        addresses[2]: 0x3333444455556666,
        addresses[3]: 0x4444555566667777,
        addresses[3] + 8: 0xBBBBBBBBBBBBBBBB,
    }
    body = []
    body += load_imm(10, addresses[0]) + load_imm(11, 0xDEADBEEF)
    body += load_imm(12, 0x1111111111111111)
    body += [lr_d(10, 13), encode_store_w(11, 10), sc_d(12, 10, 14)]
    body += load_imm(15, addresses[1]) + load_imm(16, addresses[1] + 8)
    body += load_imm(17, 0xABABABABABABABAB)
    body += load_imm(18, 0xCDCDCDCDCDCDCDCD)
    body += [lr_d(15, 19), encode_store_d(17, 16), sc_d(18, 15, 20)]
    body += load_imm(21, addresses[2]) + load_imm(22, addresses[2] + 4)
    body += load_imm(23, 0xCAFEBABE) + load_imm(24, 0x2323232323232323)
    body += [lr_d(21, 25), amoswap_w(23, 22, 26), sc_d(24, 21, 27)]
    body += load_imm(8, addresses[3]) + load_imm(9, addresses[3] + 8)
    body += load_imm(5, 0xDADADADADADADADA)
    body += load_imm(6, 0xEFEFEFEFEFEFEFEF)
    body += [lr_d(8, 7), amoswap_d(5, 9, 28), sc_d(6, 8, 29), br_self()]
    reads = tuple((address, 8) for address in initial)
    regs, mem = run(
        qemu, workdir, "local-invalidation",
        bare_payload(body, data=initial), reads=reads)

    checks.equal(field(regs, "x14"), 1,
                 "overlapping ordinary store invalidates")
    checks.equal(mem[addresses[0]], 0x11112222DEADBEEF,
                 "failed SC left ordinary store intact")
    checks.equal(field(regs, "x20"), 0,
                 "non-overlapping ordinary store preserves")
    checks.equal(mem[addresses[1]], 0xCDCDCDCDCDCDCDCD,
                 "preserved reservation completed SC")
    checks.equal(mem[addresses[1] + 8], 0xABABABABABABABAB,
                 "non-overlapping ordinary store completed")
    checks.equal(field(regs, "x26"), 0x33334444,
                 "overlapping AMOSWAP.W old value")
    checks.equal(field(regs, "x27"), 1, "overlapping atomic write invalidates")
    checks.equal(mem[addresses[2]], 0xCAFEBABE55556666,
                 "failed SC left overlapping AMO intact")
    checks.equal(field(regs, "x28"), initial[addresses[3] + 8],
                 "non-overlapping AMO old value")
    checks.equal(field(regs, "x29"), 0,
                 "non-overlapping atomic write preserves")
    checks.equal(mem[addresses[3]], 0xEFEFEFEFEFEFEFEF,
                 "SC after non-overlapping AMO")
    checks.equal(mem[addresses[3] + 8], 0xDADADADADADADADA,
                 "non-overlapping AMO store")
    print("  local overlapping/non-overlapping write invalidation: PASS")


def test_context_and_fences(qemu, workdir, checks):
    d0, d1, d2 = [DATA_BASE + 0x300 + index * 0x10 for index in range(3)]
    data = {d0: 0x10, d1: 0x20, d2: 0x30}
    body = []
    body += load_imm(10, d0) + load_imm(11, 0x1010)
    body += [lr_d(10, 12, aq=True), encode_fence(3, 3),
             encode_fence(15, 15), encode_s_type(0x80A),
             sc_d(11, 10, 13, rl=True)]
    body += load_imm(14, d1) + load_imm(15, 0x2020)
    body += [lr_d(14, 16), encode_sfence_vm(), sc_d(15, 14, 17)]
    body += load_imm(18, d2) + load_imm(19, 0x3030)
    body += [lr_d(18, 20), encode_csrrw(0, 0, CSR_SATP),
             sc_d(19, 18, 21), br_self()]
    regs, mem = run(
        qemu, workdir, "context-and-fences", bare_payload(body, data=data),
        reads=tuple((address, 8) for address in data))

    checks.equal(field(regs, "x13"), 0,
                 "AQ/RL, FENCE.RW/ALL, and FENCE.I preserve reservation")
    checks.equal(mem[d0], 0x1010, "SC after representative fences")
    checks.equal(field(regs, "x17"), 1, "SFENCE.VM clears reservation")
    checks.equal(mem[d1], data[d1], "SC after SFENCE.VM did not store")
    checks.equal(field(regs, "x21"), 1, "satp write clears reservation")
    checks.equal(mem[d2], data[d2], "SC after satp write did not store")
    print("  fence preservation and translation-context clearing: PASS")


def test_trap_clears(qemu, workdir, checks):
    address = DATA_BASE + 0x380
    source = 0xFEEDFACECAFEBEEF
    body = trap_preamble() + load_imm(10, address) + load_imm(11, source)
    body += [lr_d(10, 12)]
    sys_pc = RAM_ENTRY + len(body) * 4
    body += [encode_s_type(0x809), br_self()]
    handler = [sc_d(11, 10, 20), encode_addi_d(MARKER, 0, 21), br_self()]
    regs, mem = run(
        qemu, workdir, "trap-clears",
        bare_payload(body, handler=handler, data={address: 0x1234}),
        reads=((address, 8),))

    checks.equal(field(regs, "CAUSE"), 9, "SYS trap cause")
    checks.equal(field(regs, "EPC"), sys_pc, "SYS trap epc")
    checks.equal(field(regs, "TVAL"), 0, "SYS trap tval")
    checks.equal(field(regs, "x20"), 1, "trap entry cleared reservation")
    checks.equal(field(regs, "x21"), MARKER, "trap handler completed")
    checks.equal(mem[address], 0x1234, "handler SC did not store")
    print("  trap entry reservation clearing: PASS")


def test_p39_alias_and_ad(qemu, workdir, checks):
    physical = DATA_BASE
    flags = PTE_V | PTE_R | PTE_W | PTE_A
    body = p39_preamble()
    body += load_imm(10, TEST_VA) + load_imm(11, ALIAS_VA)
    body += load_imm(12, 0xA1A2A3A4A5A6A7A8)
    body += [lr_d(10, 13), sc_d(12, 11, 14), br_self()]
    leaves = {0: leaf(physical, flags), 1: leaf(physical, flags)}
    regs, mem = run(
        qemu, workdir, "p39-physical-alias",
        p39_payload(body, leaves, data={physical: 0x1111222233334444}),
        reads=((physical, 8), (L0_PA, 8), (L0_PA + 8, 8)))

    checks.equal(field(regs, "x13"), 0x1111222233334444,
                 "LR through first virtual alias")
    checks.equal(field(regs, "x14"), 0, "SC through physical alias")
    checks.equal(mem[physical], 0xA1A2A3A4A5A6A7A8,
                 "physical-alias SC store")
    checks.equal(mem[L0_PA], leaves[0], "LR leaf remains clean")
    checks.equal(mem[L0_PA + 8], leaves[1] | PTE_D,
                 "successful alias SC sets D")

    p0 = DATA_BASE + 0x1000
    p1 = DATA_BASE + 0x2000
    clean = PTE_V | PTE_R | PTE_W
    body = p39_preamble()
    body += load_imm(10, TEST_VA) + load_imm(11, ALIAS_VA)
    body += load_imm(12, 0x9999999999999999)
    body += [lr_d(10, 13), sc_d(12, 11, 14), br_self()]
    leaves = {
        0: leaf(p0, clean | PTE_A),
        1: leaf(p1, clean),
    }
    regs, mem = run(
        qemu, workdir, "p39-failed-sc-ad",
        p39_payload(body, leaves, data={p0: 0x40, p1: 0x41}),
        reads=((p1, 8), (L0_PA + 8, 8)))
    checks.equal(field(regs, "x14"), 1, "P39 mismatch SC status")
    checks.equal(mem[p1], 0x41, "P39 mismatch SC did not store")
    checks.equal(mem[L0_PA + 8], leaves[1] | PTE_A,
                 "failed mismatch SC sets A but not D")

    body = p39_preamble() + load_imm(10, TEST_VA)
    body += load_imm(11, 0x5152535455565758)
    body += [lr_d(10, 12), sc_d(11, 10, 13), br_self()]
    successful_leaf = leaf(p0, clean)
    regs, mem = run(
        qemu, workdir, "p39-successful-sc-ad",
        p39_payload(body, {0: successful_leaf}, data={p0: 0x50}),
        reads=((p0, 8), (L0_PA, 8)))
    checks.equal(field(regs, "x13"), 0, "P39 matching SC status")
    checks.equal(mem[p0], 0x5152535455565758, "P39 matching SC store")
    checks.equal(mem[L0_PA], successful_leaf | PTE_A | PTE_D,
                 "successful SC sets exact A and D")
    print("  P39 physical alias identity and exact SC A/D state: PASS")


def test_p39_faults(qemu, workdir, checks):
    physical = DATA_BASE + 0x3000

    body = p39_preamble() + load_imm(10, TEST_VA)
    body += load_imm(12, SENTINEL) + [lr_d(10, 12), br_self()]
    execute_only = leaf(physical, PTE_V | PTE_X | PTE_A)
    regs, mem = run(
        qemu, workdir, "p39-lr-permission",
        p39_payload(body, {0: execute_only}, data={physical: 0x60}),
        reads=((physical, 8), (L0_PA, 8)))
    checks.equal(field(regs, "CAUSE"), 13, "LR load-page-fault")
    checks.equal(field(regs, "TVAL"), TEST_VA, "LR page-fault tval")
    checks.equal(field(regs, "x12"), SENTINEL, "faulting LR preserves rd")
    checks.equal(mem[physical], 0x60, "faulting LR preserved data")
    checks.equal(mem[L0_PA], execute_only, "permission fault did not set A/D")

    body = p39_preamble() + load_imm(10, TEST_VA)
    body += load_imm(11, 0x6161) + load_imm(12, SENTINEL)
    body += [lr_d(10, 13), sc_d(11, 10, 12), br_self()]
    read_only = leaf(physical, PTE_V | PTE_R | PTE_A)
    regs, mem = run(
        qemu, workdir, "p39-sc-permission",
        p39_payload(body, {0: read_only}, data={physical: 0x61}),
        reads=((physical, 8), (L0_PA, 8)))
    checks.equal(field(regs, "CAUSE"), 14, "SC store-page-fault")
    checks.equal(field(regs, "TVAL"), TEST_VA, "SC page-fault tval")
    checks.equal(field(regs, "x12"), SENTINEL, "faulting SC preserves rd")
    checks.equal(mem[physical], 0x61, "permission-faulting SC did not store")
    checks.equal(mem[L0_PA], read_only, "SC permission fault did not set D")

    body = p39_preamble() + load_imm(10, TEST_VA)
    body += load_imm(12, SENTINEL) + [lr_d(10, 12), br_self()]
    inaccessible = leaf(UNMAPPED_PA, PTE_V | PTE_R | PTE_W)
    regs, mem = run(
        qemu, workdir, "p39-lr-access",
        p39_payload(body, {0: inaccessible}), reads=((L0_PA, 8),))
    checks.equal(field(regs, "CAUSE"), 5, "P39 LR load-access-fault")
    checks.equal(field(regs, "TVAL"), TEST_VA, "P39 LR access-fault tval")
    checks.equal(field(regs, "x12"), SENTINEL,
                 "access-faulting LR preserves rd")
    checks.equal(mem[L0_PA], inaccessible | PTE_A,
                 "P39 LR final access fault may set A only")

    body = p39_preamble() + load_imm(10, TEST_VA)
    body += load_imm(11, 0x6262) + load_imm(12, SENTINEL)
    body += [sc_d(11, 10, 12), br_self()]
    regs, mem = run(
        qemu, workdir, "p39-sc-access",
        p39_payload(body, {0: inaccessible}), reads=((L0_PA, 8),))
    checks.equal(field(regs, "CAUSE"), 7, "P39 SC store-access-fault")
    checks.equal(field(regs, "TVAL"), TEST_VA, "P39 SC access-fault tval")
    checks.equal(field(regs, "x12"), SENTINEL,
                 "access-faulting SC preserves rd")
    checks.equal(mem[L0_PA], inaccessible | PTE_A,
                 "P39 SC final access fault sets A but not D")
    print("  P39 atomic page, permission, and access faults: PASS")


def run_bare_fault(qemu, workdir, checks, name, instruction, address,
                   expected_cause, *, data=None):
    body = trap_preamble() + load_imm(10, address)
    body += load_imm(11, 0x7777) + load_imm(12, SENTINEL)
    fault_pc = RAM_ENTRY + len(body) * 4
    body += [instruction, br_self()]
    reads = tuple((location, 8) for location in (data or {}))
    regs, mem = run(
        qemu, workdir, name, bare_payload(body, data=data), reads=reads)
    checks.equal(field(regs, "CAUSE"), expected_cause, f"{name} cause")
    checks.equal(field(regs, "EPC"), fault_pc, f"{name} epc")
    checks.equal(field(regs, "TVAL"), address, f"{name} tval")
    checks.equal(field(regs, "x12"), SENTINEL, f"{name} preserves rd")
    checks.equal(field(regs, "x31"), MARKER, f"{name} entered handler")
    for location, value in (data or {}).items():
        checks.equal(mem[location], value,
                     f"{name} preserved sentinel at {location:#x}")


def test_bare_faults(qemu, workdir, checks):
    low = 0x0123456789ABCDEF
    high = 0xFEDCBA9876543210

    run_bare_fault(
        qemu, workdir, checks, "lr-misaligned", lr_w(10, 12),
        DATA_BASE + 2, 4)
    run_bare_fault(
        qemu, workdir, checks, "sc-d-misaligned", sc_d(11, 10, 12),
        DATA_BASE + 4, 6, data={DATA_BASE: low, DATA_BASE + 8: high})
    run_bare_fault(
        qemu, workdir, checks, "amoadd-w-misaligned",
        amoadd_w(11, 10, 12), DATA_BASE + 2, 6,
        data={DATA_BASE: low, DATA_BASE + 8: high})
    run_bare_fault(
        qemu, workdir, checks, "lr-access", lr_d(10, 12),
        UNMAPPED_PA, 5)
    run_bare_fault(
        qemu, workdir, checks, "sc-access", sc_d(11, 10, 12),
        UNMAPPED_PA, 7)
    print("  precise bare alignment and access faults: PASS")


def test_mmio_rom_rejection(qemu, workdir, checks):
    body = trap_preamble() + load_imm(10, XIC_GLOBAL_ERROR)
    body += load_imm(11, 0xFFFFFFFFFFFFFFFF) + load_imm(12, SENTINEL)
    fault_pc = RAM_ENTRY + len(body) * 4
    body += [amoswap_d(11, 10, 12), br_self()]
    handler = [
        encode_load_d(10, 22),
        encode_addi_d(MARKER, 0, 31),
        br_self(),
    ]
    regs, _ = run(
        qemu, workdir, "mmio-atomic-rejection",
        bare_payload(body, handler=handler))
    checks.equal(field(regs, "CAUSE"), 7, "MMIO AMO access-fault")
    checks.equal(field(regs, "EPC"), fault_pc, "MMIO AMO epc")
    checks.equal(field(regs, "TVAL"), XIC_GLOBAL_ERROR, "MMIO AMO tval")
    checks.equal(field(regs, "x12"), SENTINEL, "MMIO AMO preserves rd")
    checks.equal(field(regs, "x22"), 0, "rejected MMIO AMO has no write")
    checks.equal(field(regs, "x31"), MARKER, "MMIO handler completed")

    rom_value = 0xC00FFFFE9A000000
    body = trap_preamble() + load_imm(10, ROM_PA)
    body += load_imm(11, 0x1020304050607080) + load_imm(12, SENTINEL)
    fault_pc = RAM_ENTRY + len(body) * 4
    body += [amoswap_d(11, 10, 12), br_self()]
    regs, mem = run(
        qemu, workdir, "rom-atomic-rejection", bare_payload(body),
        reads=((ROM_PA, 8),))
    checks.equal(field(regs, "CAUSE"), 7, "ROM AMO access-fault")
    checks.equal(field(regs, "EPC"), fault_pc, "ROM AMO epc")
    checks.equal(field(regs, "TVAL"), ROM_PA, "ROM AMO tval")
    checks.equal(field(regs, "x12"), SENTINEL, "ROM AMO preserves rd")
    checks.equal(mem[ROM_PA], rom_value, "rejected ROM AMO has no write")
    checks.equal(field(regs, "x31"), MARKER, "ROM handler completed")
    print("  bare MMIO/ROM atomic rejection without side effects: PASS")


def test_atomic_code_and_pte_writes(qemu, workdir, checks):
    target = RAM_ENTRY + 0x600
    old_instruction = encode_addi_d(0x11, 0, 21)
    new_instruction = encode_addi_d(0x22, 0, 21)
    body = load_imm(10, target) + load_imm(11, new_instruction)
    first_jsr_pc = RAM_ENTRY + len(body) * 4
    body += [encode_s_operand(
        0x807, 7, 0, target - (first_jsr_pc + 4))]
    body += [amoswap_w(11, 10, 12), encode_s_type(0x80A)]
    second_jsr_pc = RAM_ENTRY + len(body) * 4
    body += [encode_s_operand(
        0x807, 7, 0, target - (second_jsr_pc + 4)), br_self()]
    payload = bare_payload(body)
    put_words(payload, target, [old_instruction, encode_s_type(0x808)])
    regs, mem = run(
        qemu, workdir, "atomic-code-write", payload,
        reads=((target, 4),))
    checks.equal(
        field(regs, "x12"),
        old_instruction | 0xFFFFFFFF00000000,
        "AMOSWAP.W returned old instruction")
    checks.equal(mem[target], new_instruction,
                 "AMOSWAP.W changed instruction RAM")
    checks.equal(field(regs, "x21"), 0x22,
                 "FENCE.I observed atomic code write")

    initial = leaf(L0_PA, PTE_V | PTE_R | PTE_W | PTE_A)
    replacement = leaf(DATA_BASE, PTE_V | PTE_R | PTE_W | PTE_A)
    body = p39_preamble() + load_imm(10, TEST_VA)
    body += load_imm(11, replacement)
    body += [amoswap_d(11, 10, 12), br_self()]
    regs, mem = run(
        qemu, workdir, "atomic-pte-alias",
        p39_payload(body, {0: initial}),
        reads=((L0_PA, 8),))
    checks.equal(field(regs, "x12"), initial | PTE_D,
                 "self-aliased AMO observed published D")
    checks.equal(mem[L0_PA], replacement | PTE_D,
                 "self-aliased AMO preserved exact D")

    sc_initial = leaf(L0_PA, PTE_V | PTE_R | PTE_W | PTE_A)
    sc_replacement = leaf(
        DATA_BASE + 0x1000, PTE_V | PTE_R | PTE_W | PTE_A)
    body = p39_preamble() + load_imm(10, TEST_VA)
    body += load_imm(11, sc_replacement)
    body += [lr_d(10, 12), sc_d(11, 10, 13), br_self()]
    regs, mem = run(
        qemu, workdir, "sc-pte-alias",
        p39_payload(body, {0: sc_initial}),
        reads=((L0_PA, 8),))
    checks.equal(field(regs, "x12"), sc_initial,
                 "self-aliased LR read clean leaf")
    checks.equal(field(regs, "x13"), 0,
                 "self-aliased clean-leaf SC made progress")
    checks.equal(mem[L0_PA], sc_replacement | PTE_D,
                 "self-aliased SC preserved exact D")
    print("  atomic code invalidation and self-aliased PTE D: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", type=pathlib.Path)
    args = parser.parse_args()
    qemu = args.qemu.resolve()
    checks = Checks()

    with tempfile.TemporaryDirectory(
            prefix="pdp12-atomic-", dir=pathlib.Path.cwd()) as temporary:
        workdir = pathlib.Path(temporary)
        print("PDP-12 atomic tests:")
        test_lr_sc_basics(qemu, workdir, checks)
        test_sc_success_clears_reservation(qemu, workdir, checks)
        test_register_aliases(qemu, workdir, checks)
        test_local_invalidation(qemu, workdir, checks)
        test_context_and_fences(qemu, workdir, checks)
        test_trap_clears(qemu, workdir, checks)
        test_p39_alias_and_ad(qemu, workdir, checks)
        test_p39_faults(qemu, workdir, checks)
        test_bare_faults(qemu, workdir, checks)
        test_mmio_rom_rejection(qemu, workdir, checks)
        test_atomic_code_and_pte_writes(qemu, workdir, checks)
    print(f"PDP-12 atomic tests: ALL PASS ({checks.count} assertions)")


if __name__ == "__main__":
    main()
