#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the repository's linked Linux head ELF under normal TCG."""

import argparse
import json
import pathlib
import re
import socket
import struct
import subprocess
import tempfile


# Keep the original, exact early-C checkpoint fixed rather than deriving it
# from the oracle used for the new compiled-early-C checks.
CHECKPOINT_PC = 0xFFFFFFC0000010F4
STACK_VA = 0xFFFFFFC000210000
TVEC_VA = 0xFFFFFFC000001120
SATP = 0x1000000000080400
BOOT_DATA_PA = 0x80220000
MARKER_PA = BOOT_DATA_PA + 0x10
COMPILED_RESULT_PA = BOOT_DATA_PA + 0x18
FDT_PA = 0x80800000
HANDOFF_PA = 0x80801000
CURRENT_COMPILED_WAIT_PC = 0xFFFFFFC0000012C0
CURRENT_COMPILED_RETIRED = 176


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
                    f"QMP command failed: {response['error']!r}"
                )
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


class QTest:
    """Minimal qtest client used only for paused physical-memory writes."""

    def __init__(self, connection):
        self.connection = connection
        self.stream = connection.makefile("rb")

    def write(self, address, data):
        request = (
            f"write 0x{address:x} 0x{len(data):x} 0x{data.hex()}\n"
        )
        self.connection.sendall(request.encode("ascii"))
        while True:
            response = self.stream.readline()
            if not response:
                raise RuntimeError("qtest connection closed")
            text = response.decode("ascii").strip()
            if text == "OK":
                return
            if text.startswith("FAIL"):
                raise RuntimeError(f"qtest write failed: {text}")
            if not text.startswith("IRQ "):
                raise RuntimeError(f"unexpected qtest response: {text}")

    def close(self):
        self.stream.close()
        self.connection.close()


def build_linux_head_artifact(repo, output):
    """Generate once and execute those exact bytes in the Node oracle."""
    script = r"""
const fs = require('node:fs');
const path = require('node:path');
const root = process.argv[1];
const output = process.argv[2];
const req = (name) => require(path.join(
  root, 'simulator/reference-emulator/src', name
));
const s0 = require(path.join(
  root, 'knowledge/01-isa-spec/machine-readable/pdpv-s0-v0.1.json'
));
const s1 = require(path.join(
  root, 'knowledge/01-isa-spec/machine-readable/pdpv-s1-v0.1.json'
));
const a0 = require(path.join(
  root, 'knowledge/01-isa-spec/machine-readable/pdpv-a0-v0.1.json'
));
const p0 = require(path.join(
  root, 'knowledge/01-isa-spec/machine-readable/pdpv-p0-v0.1.json'
));
const p1 = require(path.join(
  root, 'knowledge/01-isa-spec/machine-readable/pdpv-p1-v0.1.json'
));
const m0 = require(path.join(
  root, 'knowledge/01-isa-spec/machine-readable/pdpv-m0-v0.1.json'
));
const platformDocument = require(path.join(
  root, 'knowledge/03-qemu/machine-readable/pdpv-virt-v0.1.json'
));
const { createDecoder } = req('decoder');
const { createExecutor } = req('executor');
const { createLoadedPdpvVirtSystem } = req('elf-loader');
const { buildPdpvVirtFdt } = req('fdt');
const { buildLinuxHeadElf } = req('linux-head-elf');
const { parseRelocatableElf } = req('elf-object');
const { runLinuxHeadThroughCompiledEarlyC } = req('linux-head-program');
const { loadMultiHartProfile } = req('profile');
const {
  PdpvVirtMemory,
  loadPdpvVirtProfile
} = req('pdpv-virt');

const image = buildLinuxHeadElf();
const relocatable = parseRelocatableElf(image.object.bytes);
const objectSymbol = (name) => {
  const symbol = relocatable.symbols.find((entry) => entry.name === name);
  if (!symbol) {
    throw new Error(`relocatable object has no ${name} symbol`);
  }
  return symbol.value;
};
fs.writeFileSync(output, image.bytes);
const execute = createExecutor(createDecoder(
  loadMultiHartProfile(s0, p0, p1, m0, s1, a0)
));
const platform = loadPdpvVirtProfile(platformDocument);
const fdtPA = 0x80800000n;
const handoffPA = 0x80801000n;
const hex = (value) => `0x${BigInt(value).toString(16)}`;

function runScenario(mutate) {
  const memory = new PdpvVirtMemory(0x8000000);
  const { system } = createLoadedPdpvVirtSystem(
    execute,
    platform,
    image.bytes,
    {
      memory,
      hartCount: 1,
      deviceTree: { address: fdtPA, bytes: buildPdpvVirtFdt() },
      handoffAddress: handoffPA
    }
  );
  mutate(memory);
  const result = runLinuxHeadThroughCompiledEarlyC(system, image.program);
  return {
    retired: result.retired,
    pc: hex(result.state.pc),
    marker: hex(memory.read64(image.program.constants.markerPA)),
    compiledResult: hex(
      memory.read64(image.program.constants.compiledResultPA)
    ),
    a0: hex(result.state.registers[10]),
    a1: hex(result.state.registers[11]),
    jsr: result.trace.filter((entry) => entry.instruction === 'JSR').length,
    rts: result.trace.filter((entry) => entry.instruction === 'RTS').length,
    fdtStage: result.trace.some(
      (entry) => entry.stage === 'compiled-fdt-header'
    )
  };
}

const noMutation = () => {};
const badHandoff = (memory) => memory.write64(handoffPA + 56n, 0x19n);
const badFdt = (memory) => memory.write8(fdtPA, 0);
const bothBad = (memory) => {
  badHandoff(memory);
  badFdt(memory);
};
const constants = image.program.constants;
const labels = image.program.labels;
console.log(JSON.stringify({
  constants: {
    bootDataPA: hex(constants.bootDataPA),
    markerPA: hex(constants.markerPA),
    compiledResultPA: hex(constants.compiledResultPA),
    stackTopVA: hex(constants.stackTopVA),
    trapVectorVA: hex(constants.trapVectorVA),
    rootPA: hex(constants.rootPA),
    entryPA: hex(constants.entryPA),
    kernelPA: hex(constants.kernelPA),
    kernelVA: hex(constants.kernelVA),
    compiledEarlyCWaitVA: hex(constants.compiledEarlyCWaitVA)
  },
  labels: {
    compiledEarlyCWaitPA: hex(labels.pdpv_compiled_early_c_wait),
    validateHandoffPA: hex(labels.pdpv_validate_handoff_header),
    validateFdtPA: hex(labels.pdpv_validate_fdt_header)
  },
  objectSymbols: {
    validateHandoffOffset: hex(objectSymbol('pdpv_validate_handoff_header')),
    validateFdtOffset: hex(objectSymbol('pdpv_validate_fdt_header'))
  },
  scenarios: {
    valid: runScenario(noMutation),
    badHandoff: runScenario(badHandoff),
    badFdt: runScenario(badFdt),
    bothBad: runScenario(bothBad)
  }
}));
"""
    result = subprocess.run(
        ["node", "-e", script, str(repo), str(output)],
        cwd=repo,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"invalid Linux-head reference metadata:\n{result.stdout}"
        ) from error


def as_int(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def cross_check_reference(metadata):
    constants = {key: as_int(value)
                 for key, value in metadata["constants"].items()}
    labels = {key: as_int(value)
              for key, value in metadata["labels"].items()}
    object_symbols = {
        key: as_int(value)
        for key, value in metadata["objectSymbols"].items()
    }
    scenarios = metadata["scenarios"]
    valid = scenarios["valid"]

    derived_wait_va = (
        constants["kernelVA"]
        + labels["compiledEarlyCWaitPA"]
        - constants["kernelPA"]
    )
    if derived_wait_va != constants["compiledEarlyCWaitVA"]:
        raise RuntimeError("generated compiled wait label/constant disagree")
    linked_symbols = {
        "validateHandoffPA": (
            constants["entryPA"] +
            object_symbols["validateHandoffOffset"]
        ),
        "validateFdtPA": (
            constants["entryPA"] + object_symbols["validateFdtOffset"]
        ),
    }
    for name, expected in linked_symbols.items():
        if labels[name] != expected:
            raise RuntimeError(
                f"linked {name}=0x{labels[name]:x}, relocatable symbol "
                f"resolves to 0x{expected:x}"
            )

    fixed_constants = {
        "bootDataPA": BOOT_DATA_PA,
        "markerPA": MARKER_PA,
        "compiledResultPA": COMPILED_RESULT_PA,
        "stackTopVA": STACK_VA,
        "trapVectorVA": TVEC_VA,
    }
    for name, expected in fixed_constants.items():
        if constants[name] != expected:
            raise RuntimeError(
                f"generated {name}=0x{constants[name]:x}, expected "
                f"0x{expected:x}"
            )
    derived_satp = (1 << 60) | (constants["rootPA"] >> 12)
    if derived_satp != SATP:
        raise RuntimeError(
            f"generated P39 SATP 0x{derived_satp:x} != 0x{SATP:x}"
        )

    current_valid = (
        valid["retired"],
        as_int(valid["marker"]),
        as_int(valid["compiledResult"]),
        as_int(valid["pc"]),
    )
    expected_valid = (
        CURRENT_COMPILED_RETIRED,
        2,
        0,
        CURRENT_COMPILED_WAIT_PC,
    )
    if current_valid != expected_valid:
        raise RuntimeError(
            f"Node compiled-early-C reference {current_valid!r} != "
            f"{expected_valid!r}"
        )
    if as_int(valid["pc"]) != derived_wait_va:
        raise RuntimeError(
            "Node reference did not stop at generated wait label"
        )
    if (as_int(valid["a0"]), as_int(valid["a1"])) != (FDT_PA, HANDOFF_PA):
        raise RuntimeError(
            "Node reference restored non-physical boot arguments"
        )
    if valid["jsr"] < 2 or valid["rts"] < 2 or not valid["fdtStage"]:
        raise RuntimeError("Node reference did not execute both validators")

    expected_results = {
        "badHandoff": 4,
        "badFdt": 2 << 32,
        "bothBad": 4,
    }
    for name, expected in expected_results.items():
        scenario = scenarios[name]
        if as_int(scenario["compiledResult"]) != expected:
            raise RuntimeError(
                f"Node {name} result differs: {scenario!r}"
            )
        if as_int(scenario["pc"]) != derived_wait_va:
            raise RuntimeError(f"Node {name} missed compiled wait")
    if scenarios["badHandoff"]["fdtStage"] or scenarios["bothBad"]["fdtStage"]:
        raise RuntimeError("Node malformed handoff did not skip FDT validator")

    return constants


def read_physical(qmp, tmpdir, name, address, size):
    output = tmpdir / name
    result = qmp.command(
        "human-monitor-command",
        {"command-line": f'pmemsave 0x{address:x} {size} "{output}"'},
    )
    if result:
        raise RuntimeError(f"pmemsave failed: {result.strip()}")
    data = output.read_bytes()
    if len(data) != size:
        raise RuntimeError(f"short physical read at 0x{address:x}")
    return data


def parse_cpu_state(text):
    match = re.search(
        r"PC=0x([0-9a-f]+).*SATP=0x([0-9a-f]+) "
        r"TVEC=0x([0-9a-f]+) RETIRED=([0-9]+)",
        text,
        re.IGNORECASE,
    )
    registers = {
        int(index): int(value, 16)
        for index, value in re.findall(
            r"x(\d+)\s*=0x([0-9a-f]+)", text, re.IGNORECASE
        )
    }
    needed = (0, 2, 10, 11)
    if match is None or not all(index in registers for index in needed):
        raise RuntimeError(f"cannot parse PDP-12 CPU state:\n{text}")
    return {
        "pc": int(match.group(1), 16),
        "satp": int(match.group(2), 16),
        "tvec": int(match.group(3), 16),
        "retired": int(match.group(4)),
        "registers": registers,
    }


def start_qtest_listener(path):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    listener.settimeout(10)
    return listener


def run_qemu(
    qemu,
    kernel,
    tmpdir,
    name,
    retired,
    wait_pc,
    expected_result,
    mutations=(),
):
    qtest_path = tmpdir / f"{name}.qtest"
    listener = start_qtest_listener(qtest_path)
    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-accel", "tcg,thread=single",
        "-global", f"pdp12-cpu.stop-after-insns={retired}",
        "-m", "32M",
        "-kernel", str(kernel),
        "-display", "none",
        "-audio", "none",
        "-S",
        "-qtest", f"unix:{qtest_path}",
        "-qmp", "stdio",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    qtest = None
    failure = None
    try:
        connection, _ = listener.accept()
        qtest = QTest(connection)
        qmp = QMP(process)
        greeting = qmp.read()
        if "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting!r}")
        qmp.command("qmp_capabilities")

        for address, data in mutations:
            qtest.write(address, data)

        flags = struct.unpack(
            "<Q",
            read_physical(
                qmp, tmpdir, f"{name}-flags.bin", HANDOFF_PA + 56, 8
            ),
        )[0]
        fdt_magic = struct.unpack(
            ">I",
            read_physical(qmp, tmpdir, f"{name}-fdt.bin", FDT_PA, 4),
        )[0]
        expected_flags = 0x19 if any(
            address == HANDOFF_PA + 56 for address, _ in mutations
        ) else 0x9
        expected_magic = 0x000DFEED if any(
            address == FDT_PA for address, _ in mutations
        ) else 0xD00DFEED
        if (flags, fdt_magic) != (expected_flags, expected_magic):
            raise RuntimeError(
                f"{name} boot-input mutation "
                f"{(flags, fdt_magic)!r} differs"
            )

        qmp.command("cont")
        qmp.wait_event("STOP")
        registers = qmp.command(
            "human-monitor-command",
            {"command-line": "info registers"},
        )
        state = parse_cpu_state(registers)
        expected_state = {
            "pc": wait_pc,
            "satp": SATP,
            "tvec": TVEC_VA,
            "retired": retired,
        }
        actual_state = {key: state[key] for key in expected_state}
        if actual_state != expected_state:
            raise RuntimeError(
                f"{name} CPU state {actual_state!r} != {expected_state!r}"
            )
        expected_registers = {
            0: 0,
            2: STACK_VA,
            10: FDT_PA,
            11: HANDOFF_PA,
        }
        actual_registers = {
            index: state["registers"][index] for index in expected_registers
        }
        if actual_registers != expected_registers:
            raise RuntimeError(
                f"{name} restored registers {actual_registers!r} != "
                f"{expected_registers!r}"
            )

        boot_data = read_physical(
            qmp, tmpdir, f"{name}-boot-data.bin", BOOT_DATA_PA, 0x20
        )
        fdt, handoff, marker, compiled_result = struct.unpack(
            "<QQQQ", boot_data
        )
        publication = (fdt, handoff, marker, compiled_result)
        expected_publication = (
            FDT_PA, HANDOFF_PA, 2, expected_result
        )
        if publication != expected_publication:
            raise RuntimeError(
                f"{name} boot-data {publication!r} != "
                f"{expected_publication!r}"
            )
        return state
    except Exception as error:
        failure = error
    finally:
        listener.close()
        if qtest is not None:
            qtest.close()
        process.terminate()
        _, stderr = process.communicate(timeout=10)
    if failure is not None:
        raise RuntimeError(
            f"Linux head {name} failed (QEMU status {process.returncode})"
            f"\nstderr:\n{stderr}"
        ) from failure


def run_original_checkpoint(qemu, kernel, tmpdir):
    command = [
        str(qemu),
        "-M", "pdp12-virt",
        "-accel", "tcg,thread=single",
        "-global", "pdp12-cpu.stop-after-insns=75",
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
        qmp = QMP(process)
        greeting = qmp.read()
        if "QMP" not in greeting:
            raise RuntimeError(f"invalid QMP greeting: {greeting!r}")
        qmp.command("qmp_capabilities")
        qmp.command("cont")
        qmp.wait_event("STOP")

        registers = qmp.command(
            "human-monitor-command",
            {"command-line": "info registers"},
        )
        state = parse_cpu_state(registers)
        checkpoint = (
            state["pc"],
            state["satp"],
            state["tvec"],
            state["retired"],
            state["registers"][2],
            state["registers"][0],
        )
        expected_checkpoint = (
            CHECKPOINT_PC, SATP, TVEC_VA, 75, STACK_VA, 0
        )
        if checkpoint != expected_checkpoint:
            raise RuntimeError(
                f"checkpoint CPU state {checkpoint!r} != "
                f"{expected_checkpoint!r}"
            )

        boot_data = read_physical(
            qmp, tmpdir, "checkpoint-boot-data.bin", BOOT_DATA_PA, 0x20
        )
        if struct.unpack("<QQQQ", boot_data) != (
            FDT_PA, HANDOFF_PA, 1, 0
        ):
            raise RuntimeError("early-C boot-data publication differs")

        table_addresses = (
            0x80400010,
            0x80400800,
            0x80401000,
            0x80402000,
            0x80402008,
            0x80402010,
            0x80402020,
        )
        expected_ptes = (
            0,
            0x20100801,
            0x2000004B,
            0x2000004B,
            0x200800C7,
            0x201000C7,
            0x20200003,
        )
        ptes = tuple(
            struct.unpack(
                "<Q",
                read_physical(
                    qmp, tmpdir, f"pte-{index}.bin", address, 8
                ),
            )[0]
            for index, address in enumerate(table_addresses)
        )
        if ptes != expected_ptes:
            raise RuntimeError(
                f"P39 page-table state {ptes!r} != {expected_ptes!r}"
            )
    except Exception as error:
        failure = error
    finally:
        process.terminate()
        _, stderr = process.communicate(timeout=10)
    if failure is not None:
        raise RuntimeError(
            f"Linux head checkpoint failed (QEMU status "
            f"{process.returncode})\nstderr:\n{stderr}"
        ) from failure


def run_smoke(qemu, repo):
    with tempfile.TemporaryDirectory(prefix="pdp12-linux-head-") as tmp:
        tmpdir = pathlib.Path(tmp)
        kernel = tmpdir / "linux-head.elf"
        metadata = build_linux_head_artifact(repo, kernel)
        constants = cross_check_reference(metadata)
        scenarios = metadata["scenarios"]

        run_original_checkpoint(qemu, kernel, tmpdir)

        cases = (
            ("compiled-valid", "valid", 0, ()),
            (
                "compiled-bad-handoff",
                "badHandoff",
                4,
                ((HANDOFF_PA + 56, struct.pack("<Q", 0x19)),),
            ),
            (
                "compiled-bad-fdt",
                "badFdt",
                2 << 32,
                ((FDT_PA, b"\x00"),),
            ),
            (
                "compiled-both-bad",
                "bothBad",
                4,
                (
                    (HANDOFF_PA + 56, struct.pack("<Q", 0x19)),
                    (FDT_PA, b"\x00"),
                ),
            ),
        )
        wait_pc = constants["compiledEarlyCWaitVA"]
        for qemu_name, reference_name, expected_result, mutations in cases:
            reference = scenarios[reference_name]
            run_qemu(
                qemu,
                kernel,
                tmpdir,
                qemu_name,
                reference["retired"],
                wait_pc,
                expected_result,
                mutations,
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu", type=pathlib.Path)
    parser.add_argument(
        "--repo",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args()
    run_smoke(args.qemu.resolve(), args.repo.resolve())
    print(
        "PDP-12 linked Linux head smoke: PASS "
        "(marker=1 retired=75; marker=2 retired=176; corruptions checked)"
    )


if __name__ == "__main__":
    main()
