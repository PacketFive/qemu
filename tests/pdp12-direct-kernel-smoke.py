#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Smoke-test PDP-12 direct-kernel startup, loader, FDT, handoff,
and execute a small deterministic program to verify PC/register/retirement.

The device-tree expectations follow
knowledge/03-qemu/PDPV_VIRT_PLATFORM_v0.1.md sections 5 and 12: the timer
node publishes the 10 MHz timebase the platform mandates and the interrupt
controller identifies itself as the XIC.
"""

import argparse
import json
import os
import pathlib
import re
import select
import struct
import subprocess
import tempfile
import time


TIMER_BASE = 0x02000000
TIMER_SIZE = 0x1000
XIC_BASE = 0x0C000000
XIC_SIZE = 0x100000
XIC_PHANDLE = 1
XIC_MAX_SOURCE = 255
XIC_CONTEXT_COUNT = 1
TIMEBASE_HZ = 10_000_000
UART_IRQ = 1
UART_TRIGGER_LEVEL_HIGH = 0
VIRTIO_BLOCK_BASE = 0x10001000
VIRTIO_BLOCK_SIZE = 0x1000
VIRTIO_BLOCK_IRQ = 2
PLATFORM_CONTROL_BASE = 0x10010000
PLATFORM_CONTROL_SIZE = 0x1000
NPU_IRQ = 32

RAM_ENTRY = 0x80001000
VIRTUAL_ENTRY = 0xFFFFFFC000001000
FDT_ADDR = 0x80800000
HANDOFF_ADDR = 0x80801000
EARLY_OBJECT_END = 0x80A00000
PAYLOAD = b"PDPVHEAD"

# Four instructions validate direct-kernel execution and retirement:
#  0x80001000: ADDI.D 42, x0, x10
#  0x80001004: ADDI.D 1, x10, x11
#  0x80001008: NOP
#  0x8000100c: NOP
# Expected: retired=4, PC=0x80001010, x10=42, x11=43

PROGRAM = struct.pack("<IIII", 0xA002802A, 0xA052C001, 0x80C00000, 0x80C00000)
PROGRAM_STOP = 4  # stop after 4 instructions
EXPECTED_PC = RAM_ENTRY + 16
EXPECTED_X10 = 42
EXPECTED_X11 = 43
# P0 section 12 reset state: Kernel mode with previous mode User.
PSTATUS_RESET = 0x200
TIMECMP_RESET = 0xFFFFFFFFFFFFFFFF
# The machine is paused across system_reset, which freezes virtual time, so a
# re-based 10 MHz counter reads far below a millisecond of ticks.
MAX_RESET_TICKS = 10_000


def make_kernel(path, code=None):
    payload = code if code else PAYLOAD
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, 2, 0xFF50, 1, VIRTUAL_ENTRY, 64, 0, 0,
        64, 56, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1, 5, 0x1000, VIRTUAL_ENTRY, RAM_ENTRY,
        len(payload), max(len(payload), 16), 0x1000,
    )
    path.write_bytes(ehdr + phdr + bytes(0x1000 - len(ehdr) - len(phdr)) +
                     payload)


FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def parse_fdt(blob):
    """Return {node path: {property name: value bytes}} for a flat DTB."""
    (magic, total, off_struct, off_strings, _rsvmap, version,
     _last, _boot, _size_strings, _size_struct) = struct.unpack(
        ">10I", blob[:40])
    if magic != 0xD00DFEED or version < 16 or total != len(blob):
        raise RuntimeError("packed FDT header is invalid")
    strings = blob[off_strings:]
    nodes = {}
    path = []
    offset = off_struct
    while True:
        token = struct.unpack_from(">I", blob, offset)[0]
        offset += 4
        if token == FDT_END:
            break
        if token == FDT_NOP:
            continue
        if token == FDT_BEGIN_NODE:
            end = blob.index(b"\0", offset)
            path.append(blob[offset:end].decode())
            nodes["/" + "/".join(path[1:])] = {}
            offset = (end + 4) & ~3
        elif token == FDT_END_NODE:
            path.pop()
        elif token == FDT_PROP:
            length, name_offset = struct.unpack_from(">II", blob, offset)
            offset += 8
            name_end = strings.index(b"\0", name_offset)
            name = strings[name_offset:name_end].decode()
            nodes["/" + "/".join(path[1:])][name] = blob[offset:offset + length]
            offset = (offset + length + 3) & ~3
        else:
            raise RuntimeError(f"unknown FDT token {token} at {offset - 4}")
    return nodes


def check_fdt(blob, expected_bootargs=None):
    """The board must publish the pdpv-virt timer and XIC description."""
    nodes = parse_fdt(blob)

    def prop(path, name):
        if path not in nodes:
            raise RuntimeError(f"FDT has no node {path}")
        if name not in nodes[path]:
            raise RuntimeError(f"FDT node {path} has no {name}")
        return nodes[path][name]

    def cell(path, name):
        return struct.unpack(">I", prop(path, name))[0]

    def strings(path, name):
        return prop(path, name).rstrip(b"\0").decode().split("\0")

    if strings("/", "compatible") != ["pdpv,pdpv-virt"]:
        raise RuntimeError(
            f"root compatible: {strings('/', 'compatible')}")
    chosen = nodes.get("/chosen", {})
    actual_bootargs = chosen.get("bootargs")
    if expected_bootargs is None:
        if actual_bootargs is not None:
            raise RuntimeError("unexpected FDT bootargs")
    elif actual_bootargs != expected_bootargs.encode() + b"\0":
        raise RuntimeError(
            f"FDT bootargs {actual_bootargs!r}, expected "
            f"{expected_bootargs!r}")

    timer = "/soc/timer@2000000"
    if strings(timer, "compatible") != ["pdpv,timer-ipi-v1"]:
        raise RuntimeError(f"timer compatible: {strings(timer, 'compatible')}")
    if cell(timer, "timebase-frequency") != TIMEBASE_HZ:
        raise RuntimeError(
            f"timebase-frequency {cell(timer, 'timebase-frequency')}")
    if struct.unpack(">4I", prop(timer, "reg")) != (
            0, TIMER_BASE, 0, TIMER_SIZE):
        raise RuntimeError("timer reg does not match the platform map")

    xic = "/soc/interrupt-controller@c000000"
    if strings(xic, "compatible") != ["pdpv,xic-v1"]:
        raise RuntimeError(f"XIC compatible: {strings(xic, 'compatible')}")
    if prop(xic, "interrupt-controller") != b"":
        raise RuntimeError("XIC interrupt-controller must be a flag")
    if (cell(xic, "phandle") != XIC_PHANDLE or
            cell(xic, "#interrupt-cells") != 2):
        raise RuntimeError("XIC phandle or interrupt cells are invalid")
    if (cell(xic, "pdpv,maximum-source") != XIC_MAX_SOURCE or
            cell(xic, "pdpv,context-count") != XIC_CONTEXT_COUNT):
        raise RuntimeError("XIC source or context count is invalid")
    if struct.unpack(">4I", prop(xic, "reg")) != (0, XIC_BASE, 0, XIC_SIZE):
        raise RuntimeError("XIC reg does not match the platform map")

    uart = "/soc/serial@10000000"
    if cell(uart, "interrupt-parent") != XIC_PHANDLE:
        raise RuntimeError("UART interrupt-parent does not reference the XIC")
    if struct.unpack(">2I", prop(uart, "interrupts")) != (
            UART_IRQ, UART_TRIGGER_LEVEL_HIGH):
        raise RuntimeError("UART interrupt specifier differs from the wiring")

    virtio = "/soc/virtio_mmio@10001000"
    if strings(virtio, "compatible") != ["virtio,mmio"]:
        raise RuntimeError(
            f"virtio-block compatible: {strings(virtio, 'compatible')}")
    if struct.unpack(">4I", prop(virtio, "reg")) != (
            0, VIRTIO_BLOCK_BASE, 0, VIRTIO_BLOCK_SIZE):
        raise RuntimeError("virtio-block reg does not match the platform map")
    if cell(virtio, "interrupt-parent") != XIC_PHANDLE:
        raise RuntimeError(
            "virtio-block interrupt-parent does not reference the XIC")
    if struct.unpack(">2I", prop(virtio, "interrupts")) != (
            VIRTIO_BLOCK_IRQ, UART_TRIGGER_LEVEL_HIGH):
        raise RuntimeError(
            "virtio-block interrupt specifier differs from the wiring")
    if prop(virtio, "dma-coherent") != b"":
        raise RuntimeError("virtio-block must publish coherent DMA")

    control = "/soc/platform-control@10010000"
    if strings(control, "compatible") != [
            "pdpv,reset-power-hart-start-v1"]:
        raise RuntimeError(
            f"platform-control compatible: "
            f"{strings(control, 'compatible')}")
    if struct.unpack(">4I", prop(control, "reg")) != (
            0, PLATFORM_CONTROL_BASE, 0, PLATFORM_CONTROL_SIZE):
        raise RuntimeError(
            "platform-control reg does not match the platform map")

    npu = "/soc/npu@10008000"
    if cell(npu, "interrupt-parent") != XIC_PHANDLE:
        raise RuntimeError("NPU interrupt-parent does not reference the XIC")
    if struct.unpack(">2I", prop(npu, "interrupts")) != (
            NPU_IRQ, UART_TRIGGER_LEVEL_HIGH):
        raise RuntimeError("NPU interrupt specifier differs from the wiring")
    if prop("/soc", "ranges") != b"":
        raise RuntimeError("/soc must map child addresses identically")


# Events can be delivered before the reply of the command that caused them,
# so they are queued here instead of being dropped while a reply is read.
PENDING_EVENTS = []
# The QMP stream is buffered here and drained with os.read(): a reply and the
# event that precedes it often arrive in one chunk, and select() cannot see a
# message that already sits in a file object's internal buffer.
STREAM_BUFFERS = {}


def read_message(process, timeout=60):
    """Return the next QMP message, or None if none arrives in @timeout."""
    buffer = STREAM_BUFFERS.get(process, "")
    deadline = time.monotonic() + timeout
    while "\n" not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select(
                [process.stdout], [], [], remaining)[0]:
            STREAM_BUFFERS[process] = buffer
            return None
        chunk = os.read(process.stdout.fileno(), 4096)
        if not chunk:
            STREAM_BUFFERS[process] = buffer
            return None
        buffer += chunk.decode()
    line, STREAM_BUFFERS[process] = buffer.split("\n", 1)
    return json.loads(line)


def qmp_command(process, execute, arguments=None):
    request = {"execute": execute}
    if arguments is not None:
        request["arguments"] = arguments
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.flush()
    while True:
        response = read_message(process)
        if response is None:
            raise RuntimeError(f"no QMP reply to {execute}")
        if "event" in response:
            PENDING_EVENTS.append(response)
            continue
        if "error" in response:
            raise RuntimeError(f"QMP command failed: {response['error']!r}")
        if "return" in response:
            return response["return"]


def read_physical(process, tmpdir, name, address, size):
    output = tmpdir / name
    result = qmp_command(
        process,
        "human-monitor-command",
        {"command-line": f'pmemsave 0x{address:x} {size} "{output}"'},
    )
    if result:
        raise RuntimeError(f"pmemsave failed: {result.strip()}")
    data = output.read_bytes()
    if len(data) != size:
        raise RuntimeError(
            f"pmemsave returned {len(data)} bytes, expected {size}"
        )
    return data


def wait_for_events(process, event_name, timeout=60):
    """Return the expected event, queued earlier or read from the stream.

    Returns None if the event does not arrive within @timeout seconds, so a
    machine that never reaches the expected state fails instead of hanging.
    """
    for index, event in enumerate(PENDING_EVENTS):
        if event["event"] == event_name:
            return PENDING_EVENTS.pop(index)
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        msg = read_message(process, remaining)
        if msg is None:
            return None
        if "event" in msg:
            if msg["event"] == event_name:
                return msg
            PENDING_EVENTS.append(msg)


def parse_cpu_state(text):
    match = re.search(
        r"PC=0x([0-9a-f]+).*RETIRED=([0-9]+)",
        text,
        re.IGNORECASE,
    )
    x10_match = re.search(r"x10\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    x11_match = re.search(r"x11\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    if match is None:
        raise RuntimeError(f"cannot parse PC/RETIRED:\n{text}")
    pc = int(match.group(1), 16)
    retired = int(match.group(2))
    x10 = int(x10_match.group(1), 16) if x10_match else None
    x11 = int(x11_match.group(1), 16) if x11_match else None
    return pc, retired, x10, x11


def run_loader_smoke(qemu, tmpdir):
    """Original loader/FDT/handoff checks."""
    kernel = tmpdir / "head.elf"
    trace = tmpdir / "trace.log"
    bootargs = "console=ttyS0 earlycon init=/init"
    make_kernel(kernel)

    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-m", "32M",
        "-kernel", str(kernel),
        "-append", bootargs,
        "-display", "none",
        "-audio", "none",
        "-S",
        "-qmp", "stdio",
        "-trace",
        f"enable=pdp12_virt_direct_kernel_*,file={trace}",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    failure = None
    try:
        greeting = read_message(process)
        if greeting is None or "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting!r}")
        qmp_command(process, "qmp_capabilities")

        loaded = read_physical(
            process, tmpdir, "loaded.bin", RAM_ENTRY, 16
        )
        if loaded != PAYLOAD + bytes(16 - len(PAYLOAD)):
            raise RuntimeError("PT_LOAD bytes or zero-filled tail differ")

        fdt_header = read_physical(
            process, tmpdir, "fdt-header.bin", FDT_ADDR, 8
        )
        fdt_magic, fdt_size = struct.unpack(">II", fdt_header)
        if fdt_magic != 0xD00DFEED or not (40 <= fdt_size <= 0x1000):
            raise RuntimeError("packed FDT header is invalid")
        check_fdt(
            read_physical(process, tmpdir, "fdt.bin", FDT_ADDR, fdt_size),
            bootargs,
        )

        handoff = read_physical(
            process, tmpdir, "handoff.bin", HANDOFF_ADDR, 72
        )
        fields = struct.unpack("<QIIQQQQQQQ", handoff)
        expected = (
            0x46464F4856504450, 1, 72, FDT_ADDR,
            0, 0, 0, 0, 9, 0,
        )
        if fields != expected:
            raise RuntimeError(f"PDPVHOFF differs: {fields!r}")
    except Exception as error:
        failure = error
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=10)
    if failure is not None:
        raise RuntimeError(
            f"loader smoke failed (QEMU status {process.returncode})"
            f"\nstderr:\n{stderr}"
        ) from failure

    evidence = trace.read_text()
    loaded_contract = (
        "pdp12_virt_direct_kernel_loaded entry=0x80001000 "
        "kernel_size=16 fdt=0x80800000 "
    )
    if loaded_contract not in evidence or (
        "handoff=0x80801000 flags=0x9" not in evidence
    ):
        raise RuntimeError(
            f"loader trace missing\ntrace:\n{evidence}"
            f"\nstderr:\n{stderr}"
        )
    contract = (
        "pdp12_virt_direct_kernel_reset pc=0x80001000 "
        "a0=0x0 a1=0x80800000 "
        "a2=0x80801000 pstatus=0x200 satp=0x0"
    )
    if contract not in evidence:
        raise RuntimeError(
            f"reset-contract trace missing\ntrace:\n{evidence}"
            f"\nstderr:\n{stderr}"
        )


def run_execution_smoke(qemu, tmpdir):
    """Execute a small program and verify PC/register/retirement (Finding 8)."""
    kernel = tmpdir / "exec.elf"
    make_kernel(kernel, PROGRAM)

    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-global", f"pdp12-cpu.stop-after-insns={PROGRAM_STOP}",
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
    failure = None
    try:
        greeting = read_message(process)
        if greeting is None or "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting!r}")
        qmp_command(process, "qmp_capabilities")
        qmp_command(process, "cont")
        wait_for_events(process, "STOP")

        registers = qmp_command(
            process,
            "human-monitor-command",
            {"command-line": "info registers"},
        )
        pc, retired, x10, x11 = parse_cpu_state(registers)
        if pc != EXPECTED_PC:
            raise RuntimeError(
                f"PC=0x{pc:x} expected 0x{EXPECTED_PC:x}\n{registers}")
        if retired != PROGRAM_STOP:
            raise RuntimeError(
                f"retired={retired} expected {PROGRAM_STOP}\n{registers}")
        if x10 != EXPECTED_X10:
            raise RuntimeError(
                f"x10={x10} expected {EXPECTED_X10}\n{registers}")
        if x11 != EXPECTED_X11:
            raise RuntimeError(
                f"x11={x11} expected {EXPECTED_X11}\n{registers}")
    except Exception as error:
        failure = error
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=10)
    if failure is not None:
        raise RuntimeError(
            f"execution smoke failed (QEMU status {process.returncode})"
            f"\nstderr:\n{stderr}"
        ) from failure


def run_initrd_smoke(qemu, tmpdir):
    """Load an initrd and verify both boot-data descriptions and placement."""
    kernel = tmpdir / "initrd-kernel.elf"
    initrd = tmpdir / "initrd.img"
    initrd_data = bytes((index * 37) & 0xFF for index in range(0x3211))
    make_kernel(kernel)
    initrd.write_bytes(initrd_data)

    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-m", "32M",
        "-kernel", str(kernel),
        "-initrd", str(initrd),
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
    failure = None
    try:
        greeting = read_message(process)
        if greeting is None or "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting!r}")
        qmp_command(process, "qmp_capabilities")

        fdt_header = read_physical(
            process, tmpdir, "initrd-fdt-header.bin", FDT_ADDR, 8
        )
        fdt_magic, fdt_size = struct.unpack(">II", fdt_header)
        if fdt_magic != 0xD00DFEED or not (40 <= fdt_size <= 0x1000):
            raise RuntimeError("initrd FDT header is invalid")
        nodes = parse_fdt(read_physical(
            process, tmpdir, "initrd-fdt.bin", FDT_ADDR, fdt_size
        ))
        chosen = nodes.get("/chosen", {})
        if "bootargs" in chosen:
            raise RuntimeError("FDT retained bootargs without -append")
        initrd_start = struct.unpack(
            ">Q", chosen.get("linux,initrd-start", b""))[0]
        initrd_end = struct.unpack(
            ">Q", chosen.get("linux,initrd-end", b""))[0]

        if initrd_start & 0xFFF:
            raise RuntimeError(f"initrd start is unaligned: {initrd_start:#x}")
        if initrd_end - initrd_start != len(initrd_data):
            raise RuntimeError("FDT initrd range has the wrong size")
        if not (HANDOFF_ADDR + 72 <= initrd_start < initrd_end <=
                EARLY_OBJECT_END):
            raise RuntimeError("initrd is outside the fixed early window")
        if initrd_start < FDT_ADDR + fdt_size:
            raise RuntimeError("initrd overlaps the packed FDT")
        loaded = read_physical(
            process, tmpdir, "initrd-loaded.bin",
            initrd_start, len(initrd_data)
        )
        if loaded != initrd_data:
            raise RuntimeError("loaded initrd bytes differ")

        handoff = read_physical(
            process, tmpdir, "initrd-handoff.bin", HANDOFF_ADDR, 72
        )
        fields = struct.unpack("<QIIQQQQQQQ", handoff)
        expected = (
            0x46464F4856504450, 1, 72, FDT_ADDR,
            initrd_start, initrd_end, 0, 0, 0xB, 0,
        )
        if fields != expected:
            raise RuntimeError(f"initrd PDPVHOFF differs: {fields!r}")
    except Exception as error:
        failure = error
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=10)
    if failure is not None:
        raise RuntimeError(
            f"initrd smoke failed (QEMU status {process.returncode})"
            f"\nstderr:\n{stderr}"
        ) from failure


def run_oversized_initrd_smoke(qemu, tmpdir):
    """An initrd that cannot fit the early leaf must be rejected."""
    kernel = tmpdir / "oversized-kernel.elf"
    initrd = tmpdir / "oversized-initrd.img"
    make_kernel(kernel)
    initrd.write_bytes(bytes(0x200000))
    result = subprocess.run(
        [
            str(qemu), "-M", "pdp12-virt", "-m", "32M",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-display", "none", "-audio", "none",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if result.returncode == 0 or "does not fit" not in result.stderr:
        raise RuntimeError(
            "oversized initrd was not rejected as an early-window error"
            f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")


def register(text, name):
    match = re.search(rf"\b{name}\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    if match is None:
        raise RuntimeError(f"cannot find {name} in:\n{text}")
    return int(match.group(1), 16)


def run_system_reset_smoke(qemu, tmpdir):
    """system_reset must re-apply the direct-kernel entry contract.

    The board hart is created with cpu_create() and is not part of the
    machine reset container, so the board registers the CPU reset itself and
    the direct-kernel handler only overrides the post-reset state. Both parts
    are checked here: after a guest-visible reset the architectural reset
    must have happened (retirement counter cleared, time re-based) and the
    kernel entry contract must have been re-applied on top of it, in that
    order, so the program runs again from its entry point.
    """
    kernel = tmpdir / "reset.elf"
    trace = tmpdir / "reset-trace.log"
    make_kernel(kernel, PROGRAM)

    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-global", f"pdp12-cpu.stop-after-insns={PROGRAM_STOP}",
        "-m", "32M",
        "-kernel", str(kernel),
        "-display", "none",
        "-audio", "none",
        "-S",
        "-qmp", "stdio",
        "-trace", f"enable=pdp12_virt_direct_kernel_reset,file={trace}",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    failure = None
    try:
        greeting = read_message(process)
        if greeting is None or "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting!r}")
        qmp_command(process, "qmp_capabilities")
        qmp_command(process, "cont")
        if wait_for_events(process, "STOP") is None:
            raise RuntimeError("program did not stop before the reset")
        registers = qmp_command(
            process, "human-monitor-command",
            {"command-line": "info registers"})
        pc, retired, x10, x11 = parse_cpu_state(registers)
        if (pc, retired, x10, x11) != (
                EXPECTED_PC, PROGRAM_STOP, EXPECTED_X10, EXPECTED_X11):
            raise RuntimeError(f"first run ended in a bad state:\n{registers}")

        qmp_command(process, "system_reset")
        if wait_for_events(process, "RESET") is None:
            raise RuntimeError("no RESET event after system_reset")
        registers = qmp_command(
            process, "human-monitor-command",
            {"command-line": "info registers"})
        pc, retired, x10, x11 = parse_cpu_state(registers)
        if pc != RAM_ENTRY:
            raise RuntimeError(
                f"reset PC=0x{pc:x} expected the kernel entry "
                f"0x{RAM_ENTRY:x}:\n{registers}")
        if retired != 0:
            raise RuntimeError(
                f"system_reset kept the retirement counter:\n{registers}")
        if (x10, x11) != (0, FDT_ADDR):
            raise RuntimeError(f"stale boot arguments:\n{registers}")
        if register(registers, "x12") != HANDOFF_ADDR:
            raise RuntimeError(f"handoff pointer not restored:\n{registers}")
        if register(registers, "PSTATUS") != PSTATUS_RESET:
            raise RuntimeError(f"stale privilege state:\n{registers}")
        for name in ("SATP", "CAUSE", "EPC", "TVAL", "TVEC", "IE", "IP"):
            if register(registers, name) != 0:
                raise RuntimeError(f"stale {name} after reset:\n{registers}")
        if register(registers, "TIMECMP") != TIMECMP_RESET:
            raise RuntimeError(f"comparator not re-armed:\n{registers}")
        if register(registers, "TIME") > MAX_RESET_TICKS:
            raise RuntimeError(f"time counter not re-based:\n{registers}")

        # The retirement budget only re-arms if the counter was reset, so a
        # second STOP proves the whole reset took effect.
        qmp_command(process, "cont")
        if wait_for_events(process, "STOP") is None:
            raise RuntimeError("program did not re-run after the reset")
        registers = qmp_command(
            process, "human-monitor-command",
            {"command-line": "info registers"})
        pc, retired, x10, x11 = parse_cpu_state(registers)
        if (pc, retired, x10, x11) != (
                EXPECTED_PC, PROGRAM_STOP, EXPECTED_X10, EXPECTED_X11):
            raise RuntimeError(
                f"re-run after reset ended in a bad state:\n{registers}")
    except Exception as error:
        failure = error
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=10)
    if failure is not None:
        raise RuntimeError(
            f"system-reset smoke failed (QEMU status {process.returncode})"
            f"\nstderr:\n{stderr}"
        ) from failure

    contract = (
        "pdp12_virt_direct_kernel_reset pc=0x80001000 "
        "a0=0x0 a1=0x80800000 "
        "a2=0x80801000 pstatus=0x200 satp=0x0"
    )
    applied = trace.read_text().count(contract)
    if applied != 2:
        raise RuntimeError(
            f"entry contract applied {applied} times, expected one cold "
            f"reset and one system_reset\ntrace:\n{trace.read_text()}")


def run_smoke(qemu):
    with tempfile.TemporaryDirectory(prefix="pdp12-qemu-") as tmp:
        tmpdir = pathlib.Path(tmp)
        run_loader_smoke(qemu, tmpdir)
        run_initrd_smoke(qemu, tmpdir)
        run_oversized_initrd_smoke(qemu, tmpdir)
        run_execution_smoke(qemu, tmpdir)
        run_system_reset_smoke(qemu, tmpdir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "qemu",
        type=pathlib.Path,
        help="path to qemu-system-pdp12",
    )
    args = parser.parse_args()
    run_smoke(args.qemu.resolve())
    print("PDP-12 direct-kernel smoke: PASS")


if __name__ == "__main__":
    main()
