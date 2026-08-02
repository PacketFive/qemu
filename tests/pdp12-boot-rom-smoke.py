#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Smoke-test the pdpv-virt Boot ROM path.

knowledge/03-qemu/PDPV_VIRT_PLATFORM_v0.1.md sections 3 and 4 place an
immutable Boot ROM at 0x00001000 and make it the reset vector, and section 14
lists the reset fetch as conformance evidence. Starting the machine without
-kernel must therefore execute ROM instructions and reach a defined idle
state instead of trapping into an unmapped trap vector.
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

ROM_BASE = 0x00001000
ROM_SIZE = 0x0000F000
# The stub parks the hart: WFI, then a branch back to it for a spurious wake.
ROM_STUB = struct.pack("<II", 0x9A000000, 0xC00FFFFE)
PARKED_PC = ROM_BASE + 4
# P0 section 12 reset state: Kernel mode with previous mode User.
PSTATUS_RESET = 0x200
TIMECMP_RESET = 0xFFFFFFFFFFFFFFFF
# pdpv-virt v0.1 section 5 counts at 10 MHz, so one second of run time is
# 10^7 ticks; the machine is paused across the reset, which freezes virtual
# time, so a re-based counter reads far below a millisecond of ticks.
MIN_RUNNING_TICKS = 1_000_000
MAX_RESET_TICKS = 10_000


class QMP:
    def __init__(self, process):
        self.process = process
        self.events = []
        self.buffer = ""

    def read(self, timeout=60):
        """Read one QMP message, failing instead of hanging on a stuck VM.

        The stream is buffered here and drained with os.read(): a reply and
        the event that precedes it often arrive in one chunk, and select()
        cannot see a message that already sits in a file object's buffer.
        """
        deadline = time.monotonic() + timeout
        while "\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select(
                    [self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError(f"no QMP message within {timeout}s")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("QMP connection closed")
            self.buffer += chunk.decode()
        line, self.buffer = self.buffer.split("\n", 1)
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


def start(qemu, extra_args):
    command = [
        str(qemu), "-M", "pdp12-virt", "-m", "32M",
        "-display", "none", "-audio", "none", "-serial", "null",
        "-qmp", "stdio", *extra_args,
    ]
    return subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)


def field(text, name):
    match = re.search(rf"\b{name}\s*=0x([0-9a-f]+)", text, re.IGNORECASE)
    if match is None:
        raise RuntimeError(f"cannot find {name} in:\n{text}")
    return int(match.group(1), 16)


def retired(text):
    match = re.search(r"RETIRED=([0-9]+)", text)
    if match is None:
        raise RuntimeError(f"cannot find RETIRED in:\n{text}")
    return int(match.group(1))


def read_physical(qmp, tmpdir, name, address, size):
    output = tmpdir / name
    error = qmp.command(
        "human-monitor-command",
        {"command-line": f'pmemsave 0x{address:x} {size} "{output}"'})
    if error:
        raise RuntimeError(f"pmemsave failed: {error.strip()}")
    data = output.read_bytes()
    if len(data) != size:
        raise RuntimeError(f"short physical read at 0x{address:x}")
    return data


def test_reset_fetch(qemu, tmpdir):
    """The first fetch after reset retires a Boot ROM instruction."""
    trace = tmpdir / "boot-rom.log"
    process = start(qemu, [
        "-S", "-global", "pdp12-cpu.stop-after-insns=1",
        "-trace", f"enable=pdp12_virt_boot_rom_*,file={trace}",
    ])
    failure = None
    try:
        qmp = QMP(process)
        if "QMP" not in qmp.read():
            raise RuntimeError("invalid QMP greeting")
        qmp.command("qmp_capabilities")

        image = read_physical(qmp, tmpdir, "rom.bin", ROM_BASE, len(ROM_STUB))
        if image != ROM_STUB:
            raise RuntimeError(f"Boot ROM image differs: {image.hex()}")
        tail = read_physical(qmp, tmpdir, "rom-tail.bin",
                             ROM_BASE + ROM_SIZE - 8, 8)
        if tail != bytes(8):
            raise RuntimeError("Boot ROM does not cover its whole range")

        qmp.command("cont")
        qmp.wait_event("STOP")
        registers = qmp.command(
            "human-monitor-command", {"command-line": "info registers"})
        if field(registers, "PC") != PARKED_PC:
            raise RuntimeError(f"reset fetch did not advance:\n{registers}")
        if retired(registers) != 1:
            raise RuntimeError(f"no ROM instruction retired:\n{registers}")
        if field(registers, "CAUSE") != 0 or field(registers, "EPC") != 0:
            raise RuntimeError(f"reset fetch trapped:\n{registers}")
    except Exception as error:
        failure = error
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=10)
    if failure is not None:
        raise RuntimeError(
            f"reset-fetch smoke failed (QEMU status {process.returncode})"
            f"\nstderr:\n{stderr}") from failure

    evidence = trace.read_text()
    for line in (f"pdp12_virt_boot_rom_installed base=0x{ROM_BASE:x} "
                 f"size=0x{ROM_SIZE:x} stub_size={len(ROM_STUB)}",
                 f"pdp12_virt_boot_rom_reset pc=0x{ROM_BASE:x}"):
        if line not in evidence:
            raise RuntimeError(f"missing trace {line!r}:\n{evidence}")
    print("  Reset fetch executes Boot ROM at 0x1000: PASS")


def test_parked_without_kernel(qemu, tmpdir):
    """Without -kernel the machine runs and parks instead of aborting."""
    process = start(qemu, [])
    failure = None
    try:
        qmp = QMP(process)
        if "QMP" not in qmp.read():
            raise RuntimeError("invalid QMP greeting")
        qmp.command("qmp_capabilities")
        time.sleep(1)
        status = qmp.command("query-status")
        if not status["running"]:
            raise RuntimeError(f"machine is not running: {status!r}")
        registers = qmp.command(
            "human-monitor-command", {"command-line": "info registers"})
        if field(registers, "PC") != PARKED_PC:
            raise RuntimeError(f"hart is not parked in ROM:\n{registers}")
        if retired(registers) != 1:
            raise RuntimeError(f"parked hart kept executing:\n{registers}")
        if field(registers, "CAUSE") != 0:
            raise RuntimeError(f"parked hart trapped:\n{registers}")
        qmp.command("quit")
        status = process.wait(timeout=10)
        if status != 0:
            raise RuntimeError(f"QEMU exited with status {status}")
    except Exception as error:
        failure = error
        process.kill()
    stderr = process.communicate(timeout=10)[1]
    if failure is not None:
        raise RuntimeError(f"parked-boot smoke failed\nstderr:\n{stderr}") \
            from failure
    if stderr.strip():
        raise RuntimeError(f"unexpected diagnostics:\n{stderr}")
    print("  Machine without -kernel parks in ROM and exits cleanly: PASS")


def test_system_reset_rearms_rom_boot(qemu, tmpdir):
    """system_reset must re-run the CPU reset, not leave stale hart state.

    The hart is created with cpu_create() and therefore is not reachable from
    the machine reset container, so the board has to register its reset
    explicitly. Without that registration a guest-visible reset leaves the
    parked PC, the retirement counter and the time origin untouched, which is
    exactly what this test pins down: after system_reset the machine must be
    back on the pdpv-virt v0.1 Section 4 reset vector with the P0 Section 12
    reset state, and it must execute the Boot ROM again.
    """
    process = start(qemu, [])
    failure = None
    try:
        qmp = QMP(process)
        if "QMP" not in qmp.read():
            raise RuntimeError("invalid QMP greeting")
        qmp.command("qmp_capabilities")
        time.sleep(1)
        registers = qmp.command(
            "human-monitor-command", {"command-line": "info registers"})
        if field(registers, "PC") != PARKED_PC or retired(registers) != 1:
            raise RuntimeError(f"hart is not parked in ROM:\n{registers}")
        running_time = field(registers, "TIME")
        if running_time < MIN_RUNNING_TICKS:
            raise RuntimeError(
                f"time counter did not advance ({running_time} ticks):"
                f"\n{registers}")

        # Reset while paused so the virtual clock cannot advance between the
        # reset and the register read.
        qmp.command("stop")
        qmp.command("system_reset")
        qmp.wait_event("RESET")
        registers = qmp.command(
            "human-monitor-command", {"command-line": "info registers"})
        if field(registers, "PC") != ROM_BASE:
            raise RuntimeError(
                f"system_reset did not restore the reset vector:\n{registers}")
        if retired(registers) != 0:
            raise RuntimeError(
                f"system_reset kept the retirement counter:\n{registers}")
        reset_time = field(registers, "TIME")
        if reset_time > MAX_RESET_TICKS or reset_time * 4 > running_time:
            raise RuntimeError(
                f"system_reset did not rebase the time counter "
                f"({reset_time} ticks after {running_time}):\n{registers}")
        if field(registers, "TIMECMP") != TIMECMP_RESET:
            raise RuntimeError(
                f"system_reset did not re-arm the comparator:\n{registers}")
        if field(registers, "PSTATUS") != PSTATUS_RESET:
            raise RuntimeError(f"stale privilege state:\n{registers}")
        for name in ("SATP", "CAUSE", "EPC", "TVAL", "TVEC", "IE", "IP",
                     "KSCRATCH", "x10", "x11", "x12"):
            if field(registers, name) != 0:
                raise RuntimeError(f"stale {name} after reset:\n{registers}")

        # The re-armed machine must execute the ROM again from the vector.
        qmp.command("cont")
        time.sleep(1)
        registers = qmp.command(
            "human-monitor-command", {"command-line": "info registers"})
        if field(registers, "PC") != PARKED_PC or retired(registers) != 1:
            raise RuntimeError(
                f"hart did not re-park in ROM after reset:\n{registers}")
        if field(registers, "CAUSE") != 0:
            raise RuntimeError(f"hart trapped after reset:\n{registers}")
        qmp.command("quit")
        status = process.wait(timeout=10)
        if status != 0:
            raise RuntimeError(f"QEMU exited with status {status}")
    except Exception as error:
        failure = error
        process.kill()
    stderr = process.communicate(timeout=10)[1]
    if failure is not None:
        raise RuntimeError(f"reset smoke failed\nstderr:\n{stderr}") \
            from failure
    print("  system_reset without -kernel re-arms the Boot ROM: PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", type=pathlib.Path)
    args = parser.parse_args()
    qemu = args.qemu.resolve()

    with tempfile.TemporaryDirectory(prefix="pdp12-boot-rom-") as tmp:
        tmpdir = pathlib.Path(tmp)
        print("PDP-12 Boot ROM smoke:")
        test_reset_fetch(qemu, tmpdir)
        test_parked_without_kernel(qemu, tmpdir)
        test_system_reset_rearms_rom_boot(qemu, tmpdir)
    print("PDP-12 Boot ROM smoke: PASS")


if __name__ == "__main__":
    main()
