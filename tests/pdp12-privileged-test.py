#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""PDP-12 PDP-V-P0 privileged tests: CSRs, SYS/RTE, interrupts and the
S0/S1 MMIO transfer restrictions.

The expectations follow the normative profiles and the reference emulator:
knowledge/01-isa-spec/PRIVILEGED_PROFILE_v0.1.md sections 4 to 11 for the CSR
set, trap entry, trap return and interrupt selection, and
SCALAR_EXECUTION_PROFILE_v0.1.md section 9 / SCALAR_LINUX_PROFILE_v0.1.md
section 10 for the side-effecting-MMIO restrictions.

The timer expectations follow knowledge/03-qemu/PDPV_VIRT_PLATFORM_v0.1.md
section 5: time is a 10 MHz counter advanced by QEMU virtual time, so the
tests that depend on the rate run under -icount, where each instruction
advances virtual time by a fixed number of nanoseconds.
"""

import argparse
import json
import pathlib
import re
import struct
import subprocess
import tempfile

RAM_ENTRY = 0x80001000
HANDLER = 0x80001900
USER_CODE = 0x80001A00
DATA = 0x80002000
PAYLOAD_END = 0x80003000
VIRTUAL_ENTRY = 0xFFFFFFC000001000
MARKER = 0x99

# pdpv-virt platform registers used by the privileged tests.
TIMER_TIME = 0x02000000
TIMER_TIMECMP = 0x02000008
TIMER_SOFTIRQ = 0x02000010
XIC_SOURCE_CONFIG = 0x0C001000
XIC_ENABLE = 0x0C040000
XIC_CLAIM_COMPLETE = 0x0C040028
XIC_ACTIVE = 0x0C040030
UART_IER = 0x10000001
NPU_DOORBELL = 0x10008000
NPU_IRQ_SOURCE = 32
PLATFORM_CONTROL = 0x10010000

CSR_PSTATUS, CSR_TVEC, CSR_EPC, CSR_CAUSE = 0, 1, 2, 3
CSR_TVAL, CSR_KSCRATCH, CSR_SATP, CSR_IP = 4, 5, 6, 7
CSR_IE, CSR_HARTID, CSR_TIME, CSR_TIMECMP = 8, 9, 10, 11

IRQ_SOFTWARE, IRQ_TIMER, IRQ_EXTERNAL = 1, 5, 9
INTERRUPT = 1 << 63

# pdpv-virt v0.1 Section 5: a 10 MHz timebase, so one tick is 100 ns of QEMU
# virtual time. -icount shift=7 makes every instruction 128 ns, which keeps
# the timer schedule deterministic and independent of host speed. 100
# instructions are then exactly 12800 ns, or 128 ticks.
TIMEBASE_HZ = 10_000_000
NS_PER_TICK = 1_000_000_000 // TIMEBASE_HZ
ICOUNT_SHIFT = 7
ICOUNT = ["-icount", f"shift={ICOUNT_SHIFT}"]
INSNS_PER_100_TICKS = 100
TICKS_PER_100_INSNS = (INSNS_PER_100_TICKS << ICOUNT_SHIFT) // NS_PER_TICK


# --- encoders ---------------------------------------------------------------

def encode_addi_d(imm14, src, dst):
    return (0xA << 28) | (src << 19) | (dst << 14) | (imm14 & 0x3FFF)


def encode_slli_d(count, src, dst):
    return (0xA << 28) | (5 << 24) | (src << 19) | (dst << 14) | (count & 0x3F)


def encode_ori_d(imm14, src, dst):
    return ((0xA << 28) | (3 << 24) | (src << 19) |
            (dst << 14) | (imm14 & 0x3FFF))


def encode_c_type(subop, rd=0, rs=0, csr=0):
    return (9 << 28) | (subop << 24) | (rd << 19) | (rs << 14) | (csr << 2)


def csrrw(rd, rs, csr):
    return encode_c_type(0, rd, rs, csr)


def csrrs(rd, rs, csr):
    return encode_c_type(1, rd, rs, csr)


def encode_o_type(op, src_mode, src_reg, dst_mode, dst_reg, disp=0):
    return ((op << 26) | (src_mode << 23) | (src_reg << 18) |
            (dst_mode << 15) | (dst_reg << 10) | (disp & 0x3FF))


def encode_s_type(opcode, mode=0, reg=0, disp=0):
    return (opcode << 20) | (mode << 17) | (reg << 12) | (disp & 0xFFF)


def encode_branch(condition, offset20):
    return (0x60 << 25) | (condition << 20) | (offset20 & 0xFFFFF)


def br_self():
    return encode_branch(0, -1)


def nop():
    return 0x80C00000


def load_imm(reg, value):
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


# --- program assembly -------------------------------------------------------

def assemble(body, handler=None, user=None, data=None):
    """Place `body` at RAM_ENTRY, `handler` at HANDLER and `user` at
    USER_CODE, returning the guest payload."""
    payload = bytearray(PAYLOAD_END - RAM_ENTRY)

    def put(address, words):
        for index, word in enumerate(words):
            struct.pack_into("<I", payload, address - RAM_ENTRY + index * 4,
                             word)

    if RAM_ENTRY + len(body) * 4 > HANDLER:
        raise RuntimeError("test body overruns the trap handler")
    put(RAM_ENTRY, body)
    put(HANDLER, handler or [encode_addi_d(MARKER, 0, 20), br_self()])
    if user is not None:
        put(USER_CODE, user)
    for address, value in (data or {}).items():
        struct.pack_into("<Q", payload, address - RAM_ENTRY, value)
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


def run(qemu, tmpdir, name, payload, stop, reads=(), extra_args=()):
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
        for address in reads:
            output = tmpdir / f"{name}-{address:x}.bin"
            error = qmp.command(
                "human-monitor-command",
                {"command-line": f'pmemsave 0x{address:x} 8 "{output}"'})
            if error:
                raise RuntimeError(f"pmemsave failed: {error.strip()}")
            memory[address] = struct.unpack("<Q", output.read_bytes())[0]
        return registers, memory
    finally:
        process.terminate()
        process.communicate(timeout=30)


def field(text, name):
    match = re.search(rf"\b{name}\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    if match is None:
        raise RuntimeError(f"cannot find {name} in:\n{text}")
    return int(match.group(1), 16)


def preamble():
    """Install the trap vector; returns the instruction list."""
    return load_imm(30, HANDLER) + [csrrw(0, 30, CSR_TVEC)]


# --- SYS, BRK and RTE -------------------------------------------------------

def test_sys_and_brk(qemu, tmpdir):
    """SYS and BRK enter the trap path with the specified cause and tval."""
    for name, word, cause, tval_is_pc in (
            ("sys", encode_s_type(0x809), 9, False),
            ("brk", encode_s_type(0x80B), 3, True)):
        body = preamble()
        fault_index = len(body)
        body = body + [word, br_self()]
        registers, _ = run(qemu, tmpdir, name, assemble(body),
                           len(body) + 2)
        fault_pc = RAM_ENTRY + fault_index * 4
        assert field(registers, "CAUSE") == cause, registers
        assert field(registers, "EPC") == fault_pc, registers
        assert field(registers, "TVAL") == (fault_pc if tval_is_pc else 0)
        assert field(registers, "x20") == MARKER
        print(f"  {name.upper()} trap entry (cause {cause}, tval): PASS")


def test_sys_from_user(qemu, tmpdir):
    """RTE to User mode, then SYS reports environment-call-from-user."""
    body = preamble() + load_imm(29, USER_CODE) + [csrrw(0, 29, CSR_EPC)]
    body += [encode_c_type(8), br_self()]
    user = [encode_s_type(0x809), br_self()]
    registers, _ = run(qemu, tmpdir, "sys_user",
                       assemble(body, user=user), len(body) + 4)
    assert field(registers, "CAUSE") == 8, registers
    assert field(registers, "EPC") == USER_CODE, registers
    assert field(registers, "TVAL") == 0, registers
    # Trap entry from User: PRV becomes Kernel and PPV records User.
    assert field(registers, "PSTATUS") & 0x3C0 == (2 << 8), registers
    assert field(registers, "x20") == MARKER
    print("  SYS from User (cause 8, PPV=User): PASS")


def test_platform_control_from_user(qemu, tmpdir):
    """User writes to platform control must raise a store-access fault."""
    body = preamble() + load_imm(29, USER_CODE) + [csrrw(0, 29, CSR_EPC)]
    body += [encode_c_type(8), br_self()]
    user = load_imm(11, PLATFORM_CONTROL) + load_imm(12, 0x5555)
    user += [encode_o_type(17, 0, 12, 1, 11), br_self()]
    registers, _ = run(
        qemu, tmpdir, "platform_control_user",
        assemble(body, user=user), len(body) + len(user) + 2)
    fault_pc = USER_CODE + (len(user) - 2) * 4
    assert field(registers, "CAUSE") == 7, registers
    assert field(registers, "EPC") == fault_pc, registers
    assert field(registers, "TVAL") == PLATFORM_CONTROL, registers
    assert field(registers, "x20") == MARKER, registers
    print("  User platform-control write rejected: PASS")


def test_c_type_decode_before_privilege(qemu, tmpdir):
    """Malformed User C-Type is illegal; well-formed C-Type is privileged."""
    malformed = (
        ("reserved_subop", encode_c_type(3)),
        ("reserved_sfence_fields", encode_c_type(9, rd=1)),
        ("unimplemented_csr", encode_c_type(0, csr=0xFFF)),
        ("nonzero_low_bits", encode_c_type(0) | 1),
    )
    cases = malformed + (
        ("well_formed_kernel_only", csrrs(1, 0, CSR_HARTID)),
    )
    for name, word in cases:
        body = preamble() + load_imm(29, USER_CODE)
        body += [csrrw(0, 29, CSR_EPC), encode_c_type(8), br_self()]
        registers, _ = run(
            qemu, tmpdir, f"ctype_{name}",
            assemble(body, user=[word, br_self()]), len(body) + 4)
        expected = 10 if name == "well_formed_kernel_only" else 2
        assert field(registers, "CAUSE") == expected, registers
        assert field(registers, "EPC") == USER_CODE, registers
        assert field(registers, "TVAL") == word, registers
        assert field(registers, "x20") == MARKER, registers
    print("  User C-Type malformed/privileged trap differential: PASS")


# --- CSR behaviour ----------------------------------------------------------

def test_csr_semantics(qemu, tmpdir):
    """ie masking, timecmp/kscratch round trip, hartid and computed ip."""
    body = preamble()
    body += load_imm(10, 0xFFFFFFFFFFFFFFFF)
    body += [csrrw(0, 10, CSR_IE), csrrs(11, 0, CSR_IE)]     # x11 = ie
    body += load_imm(12, 0x123456789ABCDEF0)
    body += [csrrw(0, 12, CSR_KSCRATCH), csrrs(13, 0, CSR_KSCRATCH)]
    body += [csrrs(14, 0, CSR_HARTID)]
    body += [csrrw(0, 0, CSR_TIMECMP)]                       # timecmp = 0
    body += [csrrs(15, 0, CSR_IP)]                           # timer pending
    body += load_imm(16, 0xFFFFFFFFFFFFFFFF)
    body += [csrrw(0, 16, CSR_TIMECMP), csrrs(17, 0, CSR_IP)]
    body += [csrrs(18, 0, CSR_TIME), csrrs(19, 0, CSR_TIME)]
    body += [br_self()]
    registers, _ = run(qemu, tmpdir, "csrs", assemble(body), len(body))

    assert field(registers, "x11") == 0x222, "ie mask"
    assert field(registers, "x13") == 0x123456789ABCDEF0, "kscratch"
    assert field(registers, "x14") == 0, "hartid"
    assert field(registers, "x15") & (1 << IRQ_TIMER), "timer pending"
    assert field(registers, "x17") & (1 << IRQ_TIMER) == 0, "timer cleared"
    # time is a platform counter, not an instruction counter: consecutive
    # reads never go backwards, but they may land inside the same 100 ns tick.
    assert field(registers, "x19") >= field(registers, "x18"), "time monotonic"
    print("  CSR ie mask, kscratch, hartid, ip and time: PASS")


# --- platform timebase ------------------------------------------------------

def test_time_source(qemu, tmpdir):
    """One 10 MHz counter backs the time CSR and the timer MMIO page."""
    body = preamble() + load_imm(10, TIMER_TIME)
    body += [csrrs(14, 0, CSR_TIME)]
    body += [encode_o_type(1, 1, 10, 0, 15)]        # MOV (x10), x15
    body += [csrrs(16, 0, CSR_TIME)]
    body += [br_self()]
    registers, _ = run(qemu, tmpdir, "time_mmio", assemble(body), len(body))
    csr_before = field(registers, "x14")
    mmio = field(registers, "x15")
    csr_after = field(registers, "x16")
    assert csr_before <= mmio <= csr_after, \
        f"MMIO TIME {mmio:#x} outside CSR reads {csr_before:#x}/{csr_after:#x}"
    print("  time CSR and timer MMIO share one counter: PASS")

    # Under icount the counter is a pure function of retired instructions, so
    # both the ordering and the 10 MHz rate are exact. Each instruction is
    # 128 ns and a tick is 100 ns, so consecutive reads must differ.
    body = preamble() + load_imm(10, TIMER_TIME)
    body += [csrrs(14, 0, CSR_TIME)]
    body += [encode_o_type(1, 1, 10, 0, 15)]        # MOV (x10), x15
    body += [csrrs(16, 0, CSR_TIME)]
    body += [nop()] * (INSNS_PER_100_TICKS - 3)
    body += [csrrs(17, 0, CSR_TIME)]
    body += [br_self()]
    registers, _ = run(qemu, tmpdir, "time_rate", assemble(body), len(body),
                       extra_args=ICOUNT)
    csr_before = field(registers, "x14")
    mmio = field(registers, "x15")
    csr_after = field(registers, "x16")
    assert csr_before < mmio < csr_after, \
        f"MMIO TIME {mmio:#x} is not live between {csr_before:#x} and " \
        f"{csr_after:#x}"
    elapsed = field(registers, "x17") - csr_before
    assert elapsed == TICKS_PER_100_INSNS, \
        f"{INSNS_PER_100_TICKS} instructions advanced time by {elapsed} " \
        f"ticks, expected {TICKS_PER_100_INSNS}"
    print(f"  time advances at {TIMEBASE_HZ} Hz of virtual time: PASS")


# --- interrupts -------------------------------------------------------------

def test_timer_interrupt_expired(qemu, tmpdir):
    """An expired comparator is taken at the next retirement boundary."""
    body = preamble()
    body += load_imm(10, 1 << IRQ_TIMER) + [csrrw(0, 10, CSR_IE)]
    body += [csrrw(0, 0, CSR_TIMECMP)]            # timecmp = 0: already past
    body += load_imm(12, 0x10)
    enable_index = len(body)
    body += [csrrw(0, 12, CSR_PSTATUS)]           # IE = 1
    body += [nop()] * 4 + [br_self()]
    registers, _ = run(qemu, tmpdir, "timer_expired", assemble(body),
                       len(body) + 2)
    assert field(registers, "CAUSE") == INTERRUPT | IRQ_TIMER, registers
    assert field(registers, "TVAL") == 0, registers
    # The source was already pending, so the interrupt is taken when the
    # instruction that enabled it retires and epc is the next instruction.
    assert field(registers, "EPC") == RAM_ENTRY + (enable_index + 1) * 4, \
        registers
    # Trap entry cleared IE and saved the enabled state in PIE.
    assert field(registers, "PSTATUS") & 0x30 == 0x20, registers
    assert field(registers, "x20") == MARKER
    print("  Timer interrupt entry at an exact boundary: PASS")


def test_timer_interrupt_deadline(qemu, tmpdir):
    """A comparator ahead of the counter fires when virtual time reaches it."""
    body = preamble()
    body += load_imm(10, 1 << IRQ_TIMER) + [csrrw(0, 10, CSR_IE)]
    read_index = len(body)
    body += [csrrs(11, 0, CSR_TIME)]                        # x11 = time
    body += [encode_addi_d(TICKS_PER_100_INSNS, 11, 11)]    # + 100 insns
    body += [csrrw(0, 11, CSR_TIMECMP)]
    body += load_imm(12, 0x10)
    enable_index = len(body)
    body += [csrrw(0, 12, CSR_PSTATUS)]                     # IE = 1
    wait_index = len(body)
    wait_length = 2 * INSNS_PER_100_TICKS
    body += [nop()] * wait_length + [br_self()]
    registers, _ = run(qemu, tmpdir, "timer_deadline", assemble(body),
                       len(body) + 2, extra_args=ICOUNT)

    assert field(registers, "CAUSE") == INTERRUPT | IRQ_TIMER, registers
    assert field(registers, "TVAL") == 0, registers
    assert field(registers, "x20") == MARKER, registers
    assert field(registers, "TIME") >= field(registers, "TIMECMP"), registers
    taken = (field(registers, "EPC") - RAM_ENTRY) // 4 - 1
    assert enable_index < taken, \
        f"interrupt taken at retirement {taken}, before the deadline"
    assert wait_index <= taken < wait_index + wait_length, \
        f"interrupt taken at retirement {taken}, outside the wait window"
    # The comparator was 100 instructions of virtual time ahead of the read.
    assert abs(taken - (read_index + INSNS_PER_100_TICKS)) <= 4, \
        f"interrupt taken at retirement {taken}, expected about " \
        f"{read_index + INSNS_PER_100_TICKS}"
    print("  Timer interrupt entry at a virtual-time deadline: PASS")


def test_timer_interrupt_masked(qemu, tmpdir):
    """A pending timer source is not taken while IE or the ie bit is clear."""
    for name, ie_value, pstatus in (("global", 1 << IRQ_TIMER, 0),
                                    ("source", 0, 0x10)):
        body = preamble()
        body += load_imm(10, ie_value) + [csrrw(0, 10, CSR_IE)]
        body += [csrrw(0, 0, CSR_TIMECMP)]                   # always pending
        body += load_imm(12, pstatus) + [csrrw(0, 12, CSR_PSTATUS)]
        body += [nop()] * 8 + [br_self()]
        registers, _ = run(qemu, tmpdir, f"timer_masked_{name}",
                           assemble(body), len(body) + 4)
        assert field(registers, "x20") == 0, f"{name}: interrupt taken"
        assert field(registers, "CAUSE") == 0, registers
        print(f"  Timer interrupt masked by {name} enable: PASS")


def test_software_interrupt(qemu, tmpdir):
    """A software interrupt raised through the platform SOFTIRQ register."""
    body = preamble()
    body += load_imm(10, 1 << IRQ_SOFTWARE) + [csrrw(0, 10, CSR_IE)]
    body += load_imm(11, TIMER_SOFTIRQ) + load_imm(12, 1)
    body += load_imm(13, 0x10) + [csrrw(0, 13, CSR_PSTATUS)]
    store_index = len(body)
    body += [encode_o_type(1, 0, 12, 1, 11)]      # MOV x12, (x11): legal MMIO
    body += [nop()] * 4 + [br_self()]
    registers, _ = run(qemu, tmpdir, "soft_irq", assemble(body),
                       len(body) + 2)
    assert field(registers, "CAUSE") == INTERRUPT | IRQ_SOFTWARE, registers
    assert field(registers, "EPC") == RAM_ENTRY + (store_index + 1) * 4
    assert field(registers, "x20") == MARKER
    print("  Software interrupt through SOFTIRQ MMIO: PASS")


def test_external_interrupt(qemu, tmpdir):
    """A device source routed by the interrupt controller to the hart."""
    body = preamble()
    body += load_imm(10, 1 << IRQ_EXTERNAL) + [csrrw(0, 10, CSR_IE)]
    body += load_imm(11, XIC_SOURCE_CONFIG + 8 * NPU_IRQ_SOURCE)
    body += load_imm(12, 1)
    body += [encode_o_type(1, 0, 12, 1, 11)]      # priority 1, level-high
    body += load_imm(11, XIC_ENABLE) + load_imm(12, 1 << NPU_IRQ_SOURCE)
    body += [encode_o_type(1, 0, 12, 1, 11)]
    body += load_imm(13, NPU_DOORBELL) + load_imm(14, 1)
    body += load_imm(15, 0x10) + [csrrw(0, 15, CSR_PSTATUS)]
    doorbell_index = len(body)
    body += [encode_o_type(17, 0, 14, 1, 13)]     # MOV.WU x14, (x13)
    body += [nop()] * 4 + [br_self()]
    registers, _ = run(qemu, tmpdir, "ext_irq", assemble(body),
                       len(body) + 2)
    assert field(registers, "CAUSE") == INTERRUPT | IRQ_EXTERNAL, registers
    assert field(registers, "EPC") == RAM_ENTRY + (doorbell_index + 1) * 4
    assert field(registers, "x20") == MARKER
    print("  External interrupt through the interrupt controller: PASS")


def test_uart_external_rte(qemu, tmpdir):
    """Take UART source 1, claim/complete it, and RTE to the exact EPC."""
    handler = []
    handler += [csrrs(21, 0, CSR_EPC)]
    handler += load_imm(22, XIC_CLAIM_COMPLETE)
    handler += [encode_o_type(1, 1, 22, 0, 23)]   # claim source 1
    handler += load_imm(25, UART_IER) + load_imm(26, 0)
    handler += [encode_o_type(13, 0, 26, 1, 25)]  # deassert UART THRE IRQ
    handler += [encode_o_type(1, 0, 23, 1, 22)]   # complete source 1
    handler += load_imm(20, MARKER)
    handler += [encode_c_type(8)]                  # RTE

    body = preamble()
    body += load_imm(10, XIC_SOURCE_CONFIG + 8)
    body += load_imm(11, 1)
    body += [encode_o_type(1, 0, 11, 1, 10)]      # priority 1, level-high
    body += load_imm(10, XIC_ENABLE) + load_imm(11, 1 << 1)
    body += [encode_o_type(1, 0, 11, 1, 10)]
    body += load_imm(12, 1 << IRQ_EXTERNAL) + [csrrw(0, 12, CSR_IE)]
    body += load_imm(13, 0x10) + [csrrw(0, 13, CSR_PSTATUS)]
    body += load_imm(14, UART_IER) + load_imm(15, 2)
    uart_enable_index = len(body)
    body += [encode_o_type(13, 0, 15, 1, 14)]     # enable THRE interrupt
    return_pc = RAM_ENTRY + len(body) * 4
    body += load_imm(24, 0x525445) + [br_self()]

    registers, memory = run(
        qemu, tmpdir, "uart_ext_rte", assemble(body, handler=handler),
        len(body) + len(handler) + 4, reads=(XIC_ACTIVE,))
    assert field(registers, "CAUSE") == INTERRUPT | IRQ_EXTERNAL, registers
    assert field(registers, "EPC") == return_pc, registers
    assert field(registers, "x21") == return_pc, registers
    assert field(registers, "x23") == 1, registers
    assert field(registers, "x24") == 0x525445, registers
    assert field(registers, "x20") == MARKER, registers
    assert field(registers, "IP") & (1 << IRQ_EXTERNAL) == 0, registers
    assert memory[XIC_ACTIVE] == 0
    assert return_pc == RAM_ENTRY + (uart_enable_index + 1) * 4
    print("  UART source 1 trap, claim/complete, exact-EPC RTE: PASS")


def test_interrupt_priority(qemu, tmpdir):
    """External outranks timer, and timer outranks software."""
    cases = (
        ("timer_over_software", (1 << IRQ_TIMER) | (1 << IRQ_SOFTWARE),
         False, IRQ_TIMER),
        ("external_over_timer",
         (1 << IRQ_EXTERNAL) | (1 << IRQ_TIMER) | (1 << IRQ_SOFTWARE),
         True, IRQ_EXTERNAL),
    )
    for name, ie_value, external, expected in cases:
        body = preamble()
        body += load_imm(10, ie_value) + [csrrw(0, 10, CSR_IE)]
        body += load_imm(11, TIMER_SOFTIRQ) + load_imm(12, 1)
        body += [encode_o_type(1, 0, 12, 1, 11)]         # software pending
        body += [csrrw(0, 0, CSR_TIMECMP)]               # timer pending
        if external:
            body += load_imm(13, XIC_SOURCE_CONFIG + 8 * NPU_IRQ_SOURCE)
            body += load_imm(14, 1)
            body += [encode_o_type(1, 0, 14, 1, 13)]
            body += load_imm(13, XIC_ENABLE)
            body += load_imm(14, 1 << NPU_IRQ_SOURCE)
            body += [encode_o_type(1, 0, 14, 1, 13)]
            body += load_imm(15, NPU_DOORBELL) + load_imm(16, 1)
            body += [encode_o_type(17, 0, 16, 1, 15)]    # external pending
        body += load_imm(17, 0x10) + [csrrw(0, 17, CSR_PSTATUS)]
        body += [nop()] * 4 + [br_self()]
        registers, _ = run(qemu, tmpdir, name, assemble(body), len(body) + 2)
        assert field(registers, "CAUSE") == INTERRUPT | expected, registers
        assert field(registers, "x20") == MARKER
        print(f"  Interrupt priority {name.replace('_', ' ')}: PASS")


# --- MMIO transfer legality -------------------------------------------------

def mmio_case(qemu, tmpdir, name, setup, instruction, cause, tval):
    """Run one MMIO form and check the fault it produces (or its absence)."""
    body = preamble() + setup
    fault_index = len(body)
    body += [instruction, br_self()]
    registers, _ = run(qemu, tmpdir, f"mmio_{name}", assemble(body),
                       len(body) + 2)
    fault_pc = RAM_ENTRY + fault_index * 4
    if cause is None:
        assert field(registers, "x20") == 0, f"{name}: unexpected trap"
        assert field(registers, "CAUSE") == 0, registers
    else:
        assert field(registers, "x20") == MARKER, f"{name}: no trap"
        assert field(registers, "CAUSE") == cause, \
            f"{name}: cause {field(registers, 'CAUSE')}"
        assert field(registers, "TVAL") == tval, \
            f"{name}: tval {field(registers, 'TVAL'):#x}"
        assert field(registers, "EPC") == fault_pc, registers
    return registers


def test_mmio_transfer_legality(qemu, tmpdir):
    """Only a permitted final MOV transfer may complete on device memory."""
    setup = (load_imm(10, TIMER_TIME) + load_imm(11, TIMER_TIMECMP) +
             load_imm(12, DATA) + load_imm(13, 0x1234))

    # Permitted: memory-to-register and register-to-memory moves.
    registers = mmio_case(qemu, tmpdir, "load_ok", setup,
                          encode_o_type(1, 1, 10, 0, 14), None, 0)
    assert field(registers, "x14") != 0, "TIME read returned zero"
    mmio_case(qemu, tmpdir, "store_ok", setup,
              encode_o_type(1, 0, 13, 1, 11), None, 0)

    # Rejected forms, all before the device transaction is issued.
    forbidden = (
        ("autoincrement_source", encode_o_type(1, 2, 10, 0, 14), 5,
         TIMER_TIME),
        ("autoincrement_destination", encode_o_type(1, 0, 13, 2, 11), 7,
         TIMER_TIMECMP),
        ("autodecrement_destination", encode_o_type(1, 0, 13, 4, 11), 7,
         TIMER_TIMECMP - 8),
        ("read_modify_write", encode_o_type(2, 0, 13, 1, 11), 5,
         TIMER_TIMECMP),
        ("compare_source", encode_o_type(6, 1, 10, 0, 14), 5, TIMER_TIME),
        ("memory_to_memory_source", encode_o_type(1, 1, 10, 1, 12), 5,
         TIMER_TIME),
        ("memory_to_memory_destination", encode_o_type(1, 1, 12, 1, 11), 7,
         TIMER_TIMECMP),
        ("deferred_pointer", encode_o_type(1, 3, 10, 0, 14), 5, TIMER_TIME),
        ("unary_clear", encode_s_type(0x801, 1, 11), 7, TIMER_TIMECMP),
    )
    for name, instruction, cause, tval in forbidden:
        mmio_case(qemu, tmpdir, name, setup, instruction, cause, tval)
        print(f"  MMIO {name.replace('_', ' ')} rejected: PASS")

    # A permitted form whose width the device does not implement still fails.
    mmio_case(qemu, tmpdir, "narrow_width", setup,
              encode_o_type(13, 0, 13, 1, 11), 7, TIMER_TIMECMP)
    print("  MMIO unimplemented transfer width rejected: PASS")

    # Alignment outranks MMIO legality and the device transaction.
    misaligned = load_imm(15, TIMER_TIMECMP + 4)
    mmio_case(qemu, tmpdir, "misaligned_priority", setup + misaligned,
              encode_o_type(1, 0, 13, 2, 15), 6, TIMER_TIMECMP + 4)
    print("  MMIO alignment fault outranks legality/transaction: PASS")

    # XIC exposes only its normative register map and only at 64-bit width.
    xic_setup = load_imm(10, 0x0C000000) + load_imm(11, 0x1234)
    mmio_case(qemu, tmpdir, "xic_narrow_read", xic_setup,
              encode_o_type(17, 1, 10, 0, 12), 5, 0x0C000000)
    mmio_case(qemu, tmpdir, "xic_reserved_read",
              load_imm(10, 0x0C000100),
              encode_o_type(1, 1, 10, 0, 12), 5, 0x0C000100)
    mmio_case(qemu, tmpdir, "xic_read_only_write", xic_setup,
              encode_o_type(1, 0, 11, 1, 10), 7, 0x0C000000)
    print("  XIC width, reserved-offset and read-only access faults: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", type=pathlib.Path)
    args = parser.parse_args()
    qemu = args.qemu.resolve()

    with tempfile.TemporaryDirectory(prefix="pdp12-priv-") as tmp:
        tmpdir = pathlib.Path(tmp)
        print("PDP-12 privileged and MMIO tests:")
        test_sys_and_brk(qemu, tmpdir)
        test_sys_from_user(qemu, tmpdir)
        test_platform_control_from_user(qemu, tmpdir)
        test_c_type_decode_before_privilege(qemu, tmpdir)
        test_csr_semantics(qemu, tmpdir)
        test_time_source(qemu, tmpdir)
        test_timer_interrupt_expired(qemu, tmpdir)
        test_timer_interrupt_deadline(qemu, tmpdir)
        test_timer_interrupt_masked(qemu, tmpdir)
        test_software_interrupt(qemu, tmpdir)
        test_external_interrupt(qemu, tmpdir)
        test_uart_external_rte(qemu, tmpdir)
        test_interrupt_priority(qemu, tmpdir)
        test_mmio_transfer_legality(qemu, tmpdir)
    print("PDP-12 privileged and MMIO tests: ALL PASS")


if __name__ == "__main__":
    main()
