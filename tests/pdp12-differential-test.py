#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Replay PDP-V reference-emulator vectors against qemu-system-pdp12.

Each vector in tests/data/pdp12/reference-vectors.json was produced by
executing one instruction word on the repository's reference emulator
(simulator/reference-emulator) with a fixed harness state, and records the
architectural result the emulator computed: the next PC, the whole pstatus
value, every nonzero general register, every touched memory word and the trap
cause/tval/epc when the step trapped.

This test rebuilds that exact initial state inside the guest, executes the
same instruction word, stops the machine at the retirement boundary and
compares the architectural state.  A difference is a QEMU/reference
divergence, not a tolerance.
"""

import argparse
import concurrent.futures
import json
import pathlib
import re
import struct
import subprocess
import sys
import tempfile

RAM_ENTRY = 0x80001000          # first setup instruction / ELF entry
INSN_PC = 0x80001800            # the instruction under test
TRAP_HANDLER = 0x80001900       # tvec: a one-instruction self branch
DATA_LIMIT = 0x80010000
VIRTUAL_ENTRY = 0xFFFFFFC000001000
RAM_SIZE = "128M"
SCRATCH = 31                    # harness scratch register, never in a vector

CSR_NUMBERS = {
    "pstatus": 0,
    "tvec": 1,
    "epc": 2,
    "kscratch": 5,
    "satp": 6,
    "ie": 8,
    "timecmp": 11,
}


# --- instruction encoders ----------------------------------------------------

def encode_addi_d(imm14, src, dst):
    return (0xA << 28) | (src << 19) | (dst << 14) | (imm14 & 0x3FFF)


def encode_slli_d(count, src, dst):
    return (0xA << 28) | (5 << 24) | (src << 19) | (dst << 14) | (count & 0x3F)


def encode_ori_d(imm14, src, dst):
    return ((0xA << 28) | (3 << 24) | (src << 19) |
            (dst << 14) | (imm14 & 0x3FFF))


def encode_csrrw(rd, rs, csr):
    return (9 << 28) | (rd << 19) | (rs << 14) | (csr << 2)


def encode_branch(condition, offset20):
    return (0x60 << 25) | (condition << 20) | (offset20 & 0xFFFFF)


def load_imm(reg, value):
    """Materialise an unsigned 64-bit constant from 12-bit chunks."""
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


def build_setup(vector):
    """Instructions that install the vector's architectural start state."""
    insns = []
    # The platform boot contract leaves the handoff registers set; the vectors
    # start from an all-zero register file.
    for register in range(1, 31):
        insns.append(encode_addi_d(0, 0, register))
    insns += load_imm(SCRATCH, TRAP_HANDLER)
    insns.append(encode_csrrw(0, SCRATCH, CSR_NUMBERS["tvec"]))
    for name, value in sorted(vector.get("csrs", {}).items()):
        if name == "tvec":
            continue
        insns += load_imm(SCRATCH, int(value, 16))
        insns.append(encode_csrrw(0, SCRATCH, CSR_NUMBERS[name]))
    for index, value in sorted(vector.get("registers", {}).items(),
                               key=lambda pair: int(pair[0])):
        register = int(index)
        if register == SCRATCH or register == 0:
            raise RuntimeError(
                f"{vector['name']}: illegal register {register}")
        insns += load_imm(register, int(value, 16))
    flags = vector["flags"]
    # The reference emulator's start state is Kernel mode with PPV = User,
    # which is the P0 reset state.  Since P0 Section 5.1 made PPV
    # software-writable, this write has to reinstate it explicitly or it
    # would install PPV = Kernel and diverge from the recorded vector.
    pstatus = ((1 if flags["c"] else 0) | (2 if flags["v"] else 0) |
               (4 if flags["z"] else 0) | (8 if flags["n"] else 0) |
               (2 << 8))
    insns += load_imm(SCRATCH, pstatus)
    insns.append(encode_csrrw(0, SCRATCH, CSR_NUMBERS["pstatus"]))
    # Branch to the instruction under test without disturbing the flags.
    offset = (INSN_PC - (RAM_ENTRY + (len(insns) + 1) * 4)) // 4
    insns.append(encode_branch(0, offset))
    return insns


def build_payload(vector):
    """Assemble the guest image and return (payload, setup_length)."""
    setup = build_setup(vector)
    end = max([INSN_PC + 8, TRAP_HANDLER + 4] +
              [int(address, 16) + 8
               for address in vector.get("memory", {})
               if int(address, 16) < DATA_LIMIT] +
              [int(address, 16) + 8
               for address in vector["expect"].get("memory", {})
               if int(address, 16) < DATA_LIMIT])
    payload = bytearray(end - RAM_ENTRY)

    def put_word(address, word):
        struct.pack_into("<I", payload, address - RAM_ENTRY, word)

    for index, word in enumerate(setup):
        put_word(RAM_ENTRY + index * 4, word)
    if RAM_ENTRY + len(setup) * 4 > INSN_PC:
        raise RuntimeError(f"{vector['name']}: setup overruns the test slot")
    put_word(INSN_PC, int(vector["word"], 16))
    put_word(INSN_PC + 4, encode_branch(0, -1))
    put_word(TRAP_HANDLER, encode_branch(0, -1))
    for address, value in vector.get("memory", {}).items():
        physical = int(address, 16)
        if physical < DATA_LIMIT:
            struct.pack_into("<Q", payload, physical - RAM_ENTRY,
                             int(value, 16))
    return bytes(payload), len(setup)


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


# --- QMP ---------------------------------------------------------------------

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


def parse_field(text, name):
    match = re.search(rf"\b{name}\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    if match is None:
        raise RuntimeError(f"cannot find {name} in:\n{text}")
    return int(match.group(1), 16)


def run_vector(qemu, tmpdir, vector):
    """Execute one vector and return the list of differences (empty = pass)."""
    payload, setup_length = build_payload(vector)
    kernel = tmpdir / f"{vector['name']}.elf"
    make_kernel(kernel, payload)
    stop = setup_length + 1

    command = [
        str(qemu), "-M", "pdp12-virt",
        "-global", f"pdp12-cpu.stop-after-insns={stop}",
        "-m", RAM_SIZE, "-kernel", str(kernel),
        "-display", "none", "-audio", "none", "-S", "-qmp", "stdio",
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
        for address in sorted(vector["expect"].get("memory", {})):
            physical = int(address, 16)
            output = tmpdir / f"{vector['name']}-{physical:x}.bin"
            error = qmp.command(
                "human-monitor-command",
                {"command-line": f'pmemsave 0x{physical:x} 8 "{output}"'})
            if error:
                raise RuntimeError(f"pmemsave failed: {error.strip()}")
            memory[address] = struct.unpack("<Q", output.read_bytes())[0]
    finally:
        process.terminate()
        process.communicate(timeout=30)

    expect = vector["expect"]
    differences = []

    def check(label, actual, wanted):
        if actual != wanted:
            differences.append(
                f"{label}: qemu=0x{actual:x} reference=0x{wanted:x}")

    check("pc", parse_field(registers, "PC"), int(expect["pc"], 16))
    check("pstatus", parse_field(registers, "PSTATUS"),
          int(expect["pstatus"], 16))
    wanted = expect.get("registers", {})
    wanted_registers = {int(index): int(value, 16)
                        for index, value in wanted.items()}
    # A vector may mark a destination as platform-dependent (the time CSR is
    # a platform counter, so the oracle's snapshot is not an architectural
    # value); the register is then only required to exist and not to trap.
    platform_dependent = {int(index)
                          for index in vector.get("platformDependent", [])}
    for register in range(1, 31):
        if register in platform_dependent:
            continue
        check(f"x{register}", parse_field(registers, f"x{register}"),
              wanted_registers.get(register, 0))
    for address, value in memory.items():
        check(f"mem[{address}]", value,
              int(expect["memory"][address], 16))
    trap = expect["trap"]
    if trap is None:
        check("cause", parse_field(registers, "CAUSE"), 0)
    else:
        check("cause", parse_field(registers, "CAUSE"), int(trap["cause"], 16))
        check("tval", parse_field(registers, "TVAL"), int(trap["tval"], 16))
        check("epc", parse_field(registers, "EPC"), int(trap["epc"], 16))
    return differences


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", type=pathlib.Path)
    parser.add_argument(
        "--vectors", type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent /
        "data/pdp12/reference-vectors.json")
    parser.add_argument("--filter", default=None)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    qemu = args.qemu.resolve()

    document = json.loads(args.vectors.read_text())
    vectors = document["vectors"]
    if args.filter:
        vectors = [v for v in vectors if re.search(args.filter, v["name"])]
    if document.get("insnPc") and int(document["insnPc"], 16) != INSN_PC:
        raise RuntimeError("vector file uses a different instruction slot")
    if document.get("trapHandler") and \
            int(document["trapHandler"], 16) != TRAP_HANDLER:
        raise RuntimeError("vector file uses a different trap handler")

    print(f"PDP-12 differential vectors ({document['profile']}, "
          f"{len(vectors)} cases):")
    failures = []
    with tempfile.TemporaryDirectory(prefix="pdp12-diff-") as tmp:
        tmpdir = pathlib.Path(tmp)
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            futures = {
                pool.submit(run_vector, qemu, tmpdir, vector): vector
                for vector in vectors
            }
            for future in concurrent.futures.as_completed(futures):
                vector = futures[future]
                try:
                    differences = future.result()
                except Exception as error:      # pylint: disable=broad-except
                    differences = [f"harness error: {error!r}"]
                if differences:
                    failures.append((vector, differences))

    groups = {}
    for vector in vectors:
        groups[vector["group"]] = groups.get(vector["group"], 0) + 1
    for group in sorted(groups):
        print(f"  {group}: {groups[group]} vectors")
    if failures:
        print(f"  FAILURES: {len(failures)}")
        for vector, differences in sorted(failures,
                                          key=lambda item: item[0]["name"]):
            print(f"    {vector['name']} ({vector['mnemonic']}, "
                  f"word {vector['word']}):")
            for difference in differences:
                print(f"      {difference}")
        sys.exit(1)
    print(f"PDP-12 differential vectors: ALL {len(vectors)} PASS")


if __name__ == "__main__":
    main()
