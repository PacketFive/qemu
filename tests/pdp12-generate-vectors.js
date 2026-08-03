// SPDX-License-Identifier: GPL-2.0-or-later
'use strict';

const path = require('path');
const fs = require('fs');

const { loadPagingProfile } = require('../../simulator/reference-emulator/src/profile');
const { createDecoder } = require('../../simulator/reference-emulator/src/decoder');
const { createExecutor } = require('../../simulator/reference-emulator/src/executor');
const {
  KERNEL_MODE,
  USER_MODE,
  MASK64,
  createState,
  unsigned64
} = require('../../simulator/reference-emulator/src/state');
const { PdpvVirtMemory } = require('../../simulator/reference-emulator/src/pdpv-virt');

const s0Manifest = require('../../knowledge/01-isa-spec/machine-readable/pdpv-s0-v0.1.json');
const s1Manifest = require('../../knowledge/01-isa-spec/machine-readable/pdpv-s1-v0.1.json');
const p0Manifest = require('../../knowledge/01-isa-spec/machine-readable/pdpv-p0-v0.1.json');
const p1Manifest = require('../../knowledge/01-isa-spec/machine-readable/pdpv-p1-v0.1.json');
const a0Manifest = require('../../knowledge/01-isa-spec/machine-readable/pdpv-a0-v0.1.json');

const profile = loadPagingProfile(s0Manifest, p0Manifest, p1Manifest, s1Manifest, a0Manifest);
const decode = createDecoder(profile);
const step = createExecutor(decode);

// Constants
const INSN_PC = 0x80001800n;
const TRAP_HANDLER = 0x80001900n;
const DATA_BASE = 0x80002000n;
const DATA_END = 0x8000F800n;
const UNMAPPED_ADDR = 0x90000000n;

// Formatting helpers
function fmt64(value) {
  return '0x' + unsigned64(value).toString(16).padStart(16, '0');
}

function fmt32(value) {
  return '0x' + (value >>> 0).toString(16).padStart(8, '0');
}

// Encoding helpers
function oType(opcode, srcReg, dstReg, srcMode = 0, dstMode = 0, displacement = 0) {
  return ((opcode << 26) |
    (srcMode << 23) |
    (srcReg << 18) |
    (dstMode << 15) |
    (dstReg << 10) |
    (displacement & 0x3ff)) >>> 0;
}

function sType(opcode, dstReg = 0, dstMode = 0, displacement = 0) {
  return ((opcode << 20) |
    (dstMode << 17) |
    (dstReg << 12) |
    (displacement & 0xfff)) >>> 0;
}

function bType(condition, offset) {
  const branchOpcode = 96;
  return ((branchOpcode << 25) |
    (condition << 20) |
    (offset & 0xfffff)) >>> 0;
}

function iType(subop, srcReg, dstReg, immediate) {
  return (0xa0000000 |
    (subop << 24) |
    (srcReg << 19) |
    (dstReg << 14) |
    (immediate & 0x3fff)) >>> 0;
}

function uType(operation, dstReg, immediate) {
  return (0xb0000000 |
    (operation << 27) |
    (dstReg << 22) |
    (immediate & 0x3fffff)) >>> 0;
}

function cType(subop, rd = 0, rs = 0, csr = 0) {
  return (0x90000000 |
    (subop << 24) |
    (rd << 19) |
    (rs << 14) |
    (csr << 2)) >>> 0;
}

function aType(operation, width, aq, rl, rs2, rs1, rd, reserved = 0) {
  return (0xE0000000 |
    (aq << 24) |
    (rl << 23) |
    (rs2 << 18) |
    (rs1 << 13) |
    (rd << 8) |
    (width << 7) |
    (operation << 3) |
    reserved) >>> 0;
}

function fType(predecessor, successor, reserved = 0) {
  return (0xE2000000 |
    (predecessor << 21) |
    (successor << 17) |
    reserved) >>> 0;
}

// pstatus packing (matches executor's pstatusValue)
function pstatusValue(flags, privileged) {
  let value = 0n;
  value |= flags.c ? 1n : 0n;
  value |= flags.v ? 1n << 1n : 0n;
  value |= flags.z ? 1n << 2n : 0n;
  value |= flags.n ? 1n << 3n : 0n;
  value |= privileged.interruptEnable ? 1n << 4n : 0n;
  value |= privileged.previousInterruptEnable ? 1n << 5n : 0n;
  value |= BigInt(privileged.mode) << 6n;
  value |= BigInt(privileged.previousMode) << 8n;
  value |= BigInt(privileged.previousFlags ?? 0) << 12n;
  if (privileged.paging !== undefined) {
    value |= privileged.paging.kua ? (1n << 10n) : 0n;
    value |= privileged.paging.mxr ? (1n << 11n) : 0n;
  }
  return value;
}

// Validation
function validateRegister(reg) {
  if (reg === 31) {
    throw new Error('Register 31 is reserved for the replay harness');
  }
}

// S-Type opcodes (from manifests)
const CLR = 2049, INC = 2050, DEC = 2051, NEG = 2052, COM = 2053;
const JMP = 2054, JSR = 2055, RTS = 2056, SYS = 2057, FENCEI = 2058;
const BRK = 2059, NOP = 2060;

// Vector definitions
const vectorDefs = [];

function addVector(def) {
  if (def.registers) {
    for (const key of Object.keys(def.registers)) {
      validateRegister(Number(key));
    }
  }
  vectorDefs.push(def);
}

// ===== O-TYPE 64-BIT (opcodes 1..12) =====

// MOV (opcode 1)
addVector({ name: 'mov-d-basic', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6), registers: { 5: 0x123456789ABCDEF0n }, flags: { c: true } });
addVector({ name: 'mov-d-zero', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6), registers: { 5: 0n }, flags: { c: false } });
addVector({ name: 'mov-d-negative', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6), registers: { 5: 0x8000000000000000n }, flags: { c: true } });
addVector({ name: 'mov-d-dst-x0', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 0), registers: { 5: 42n }, flags: {} });

// ADD (opcode 2)
addVector({ name: 'add-d-basic', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 5, 6), registers: { 5: 3n, 6: 5n }, flags: {} });
addVector({ name: 'add-d-carry', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 5, 6), registers: { 5: 1n, 6: 0xFFFFFFFFFFFFFFFFn }, flags: {} });
addVector({ name: 'add-d-overflow', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 5, 6), registers: { 5: 1n, 6: 0x7FFFFFFFFFFFFFFFn }, flags: {} });
addVector({ name: 'add-d-zero-result', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 5, 6), registers: { 5: 0n, 6: 0n }, flags: {} });
addVector({ name: 'add-d-both-neg', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 5, 6), registers: { 5: 0xFFFFFFFFFFFFFFFEn, 6: 0xFFFFFFFFFFFFFFFEn }, flags: {} });

// SUB (opcode 3)
addVector({ name: 'sub-d-basic', group: 'o-type', mnemonic: 'SUB',
  word: oType(3, 5, 6), registers: { 5: 3n, 6: 10n }, flags: {} });
addVector({ name: 'sub-d-borrow', group: 'o-type', mnemonic: 'SUB',
  word: oType(3, 5, 6), registers: { 5: 10n, 6: 3n }, flags: {} });
addVector({ name: 'sub-d-overflow', group: 'o-type', mnemonic: 'SUB',
  word: oType(3, 5, 6), registers: { 5: 1n, 6: 0x8000000000000000n }, flags: {} });
addVector({ name: 'sub-d-equal', group: 'o-type', mnemonic: 'SUB',
  word: oType(3, 5, 6), registers: { 5: 7n, 6: 7n }, flags: {} });

// MUL (opcode 4)
addVector({ name: 'mul-d-basic', group: 'o-type', mnemonic: 'MUL',
  word: oType(4, 5, 6), registers: { 5: 7n, 6: 6n }, flags: { c: true } });
addVector({ name: 'mul-d-zero', group: 'o-type', mnemonic: 'MUL',
  word: oType(4, 5, 6), registers: { 5: 0n, 6: 12345n }, flags: { c: true } });
addVector({ name: 'mul-d-negative', group: 'o-type', mnemonic: 'MUL',
  word: oType(4, 5, 6), registers: { 5: 0xFFFFFFFFFFFFFFFFn, 6: 2n }, flags: { c: true } });

// DIV (opcode 5)
addVector({ name: 'div-d-basic', group: 'o-type', mnemonic: 'DIV',
  word: oType(5, 5, 6), registers: { 5: 3n, 6: 10n }, flags: { c: true } });
addVector({ name: 'div-d-negative', group: 'o-type', mnemonic: 'DIV',
  word: oType(5, 5, 6), registers: { 5: 0xFFFFFFFFFFFFFFFFn, 6: 10n }, flags: {} });
addVector({ name: 'div-d-exact', group: 'o-type', mnemonic: 'DIV',
  word: oType(5, 5, 6), registers: { 5: 5n, 6: 25n }, flags: {} });

// CMP (opcode 6)
addVector({ name: 'cmp-d-equal', group: 'o-type', mnemonic: 'CMP',
  word: oType(6, 5, 6), registers: { 5: 42n, 6: 42n }, flags: {} });
addVector({ name: 'cmp-d-greater', group: 'o-type', mnemonic: 'CMP',
  word: oType(6, 5, 6), registers: { 5: 3n, 6: 10n }, flags: {} });
addVector({ name: 'cmp-d-less', group: 'o-type', mnemonic: 'CMP',
  word: oType(6, 5, 6), registers: { 5: 10n, 6: 3n }, flags: {} });
addVector({ name: 'cmp-d-dst-unchanged', group: 'o-type', mnemonic: 'CMP',
  word: oType(6, 5, 6), registers: { 5: 1n, 6: 5n }, flags: {} });

// AND (opcode 7)
addVector({ name: 'and-d-basic', group: 'o-type', mnemonic: 'AND',
  word: oType(7, 5, 6), registers: { 5: 0xFF00n, 6: 0x0FF0n }, flags: { c: true } });
addVector({ name: 'and-d-zero', group: 'o-type', mnemonic: 'AND',
  word: oType(7, 5, 6), registers: { 5: 0xFF00n, 6: 0x00FFn }, flags: { c: false } });

// OR (opcode 8)
addVector({ name: 'or-d-basic', group: 'o-type', mnemonic: 'OR',
  word: oType(8, 5, 6), registers: { 5: 0xFF00n, 6: 0x00FFn }, flags: { c: true } });
addVector({ name: 'or-d-negative', group: 'o-type', mnemonic: 'OR',
  word: oType(8, 5, 6), registers: { 5: 0x8000000000000000n, 6: 1n }, flags: { c: false } });

// XOR (opcode 9)
addVector({ name: 'xor-d-basic', group: 'o-type', mnemonic: 'XOR',
  word: oType(9, 5, 6), registers: { 5: 0xFFFFn, 6: 0xFF00n }, flags: { c: false } });
addVector({ name: 'xor-d-same', group: 'o-type', mnemonic: 'XOR',
  word: oType(9, 5, 6), registers: { 5: 0x1234n, 6: 0x1234n }, flags: { c: true } });

// SLL (opcode 10)
addVector({ name: 'sll-d-one', group: 'o-type', mnemonic: 'SLL',
  word: oType(10, 5, 6), registers: { 5: 1n, 6: 0x8000000000000001n }, flags: {} });
addVector({ name: 'sll-d-63', group: 'o-type', mnemonic: 'SLL',
  word: oType(10, 5, 6), registers: { 5: 63n, 6: 1n }, flags: {} });
addVector({ name: 'sll-d-zero-count', group: 'o-type', mnemonic: 'SLL',
  word: oType(10, 5, 6), registers: { 5: 0n, 6: 5n }, flags: { c: true } });
addVector({ name: 'sll-d-64-masked', group: 'o-type', mnemonic: 'SLL',
  word: oType(10, 5, 6), registers: { 5: 64n, 6: 0xABn }, flags: { c: false } });

// SRL (opcode 11)
addVector({ name: 'srl-d-one', group: 'o-type', mnemonic: 'SRL',
  word: oType(11, 5, 6), registers: { 5: 1n, 6: 0x8000000000000002n }, flags: {} });
addVector({ name: 'srl-d-63', group: 'o-type', mnemonic: 'SRL',
  word: oType(11, 5, 6), registers: { 5: 63n, 6: 0x8000000000000000n }, flags: {} });
addVector({ name: 'srl-d-zero-count', group: 'o-type', mnemonic: 'SRL',
  word: oType(11, 5, 6), registers: { 5: 0n, 6: 0x8000000000000000n }, flags: { c: false } });

// SRA (opcode 12)
addVector({ name: 'sra-d-one', group: 'o-type', mnemonic: 'SRA',
  word: oType(12, 5, 6), registers: { 5: 1n, 6: 0x8000000000000002n }, flags: {} });
addVector({ name: 'sra-d-63', group: 'o-type', mnemonic: 'SRA',
  word: oType(12, 5, 6), registers: { 5: 63n, 6: 0x8000000000000000n }, flags: {} });
addVector({ name: 'sra-d-positive', group: 'o-type', mnemonic: 'SRA',
  word: oType(12, 5, 6), registers: { 5: 4n, 6: 0x7F00000000000000n }, flags: {} });
addVector({ name: 'sra-d-zero-count', group: 'o-type', mnemonic: 'SRA',
  word: oType(12, 5, 6), registers: { 5: 0n, 6: 0xF000000000000000n }, flags: { c: true } });

// ===== O-TYPE NARROW MOVES (opcodes 13..18) =====

// MOV.BU (opcode 13)
addVector({ name: 'mov-bu-reg', group: 'o-type-narrow', mnemonic: 'MOV.BU',
  word: oType(13, 5, 6), registers: { 5: 0xABn } });
addVector({ name: 'mov-bu-high', group: 'o-type-narrow', mnemonic: 'MOV.BU',
  word: oType(13, 5, 6), registers: { 5: 0xFF80n } });
addVector({ name: 'mov-bu-zero', group: 'o-type-narrow', mnemonic: 'MOV.BU',
  word: oType(13, 5, 6), registers: { 5: 0xFF00n } });

// MOV.BS (opcode 14)
addVector({ name: 'mov-bs-negative', group: 'o-type-narrow', mnemonic: 'MOV.BS',
  word: oType(14, 5, 6), registers: { 5: 0x80n } });
addVector({ name: 'mov-bs-positive', group: 'o-type-narrow', mnemonic: 'MOV.BS',
  word: oType(14, 5, 6), registers: { 5: 0x7Fn } });

// MOV.HU (opcode 15)
addVector({ name: 'mov-hu-reg', group: 'o-type-narrow', mnemonic: 'MOV.HU',
  word: oType(15, 5, 6), registers: { 5: 0x8000n } });

// MOV.HS (opcode 16)
addVector({ name: 'mov-hs-negative', group: 'o-type-narrow', mnemonic: 'MOV.HS',
  word: oType(16, 5, 6), registers: { 5: 0x8000n } });
addVector({ name: 'mov-hs-positive', group: 'o-type-narrow', mnemonic: 'MOV.HS',
  word: oType(16, 5, 6), registers: { 5: 0x1234n } });

// MOV.WU (opcode 17)
addVector({ name: 'mov-wu-reg', group: 'o-type-narrow', mnemonic: 'MOV.WU',
  word: oType(17, 5, 6), registers: { 5: 0x80000000n } });

// MOV.WS (opcode 18)
addVector({ name: 'mov-ws-negative', group: 'o-type-narrow', mnemonic: 'MOV.WS',
  word: oType(18, 5, 6), registers: { 5: 0x80000000n } });
addVector({ name: 'mov-ws-positive', group: 'o-type-narrow', mnemonic: 'MOV.WS',
  word: oType(18, 5, 6), registers: { 5: 0x7FFFFFFFn } });

// Narrow memory operations
addVector({ name: 'mov-bs-load', group: 'o-type-narrow', mnemonic: 'MOV.BS',
  word: oType(14, 5, 6, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x00000000000000FE' } });
addVector({ name: 'mov-hu-load', group: 'o-type-narrow', mnemonic: 'MOV.HU',
  word: oType(15, 5, 6, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x000000000000ABCD' } });
addVector({ name: 'mov-wu-store', group: 'o-type-narrow', mnemonic: 'MOV.WU',
  word: oType(17, 5, 6, 0, 1), registers: { 5: 0xDEADBEEFCAFEBABEn, 6: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'mov-bu-autoinc', group: 'o-type-narrow', mnemonic: 'MOV.BU',
  word: oType(13, 5, 6, 2), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x00000000000000AB' } });
addVector({ name: 'mov-hu-autodec', group: 'o-type-narrow', mnemonic: 'MOV.HU',
  word: oType(15, 5, 6, 4), registers: { 5: 0x80002002n },
  memory: { '0x0000000080002000': '0x0000000000001234' } });
addVector({ name: 'mov-bs-autoinc-deferred', group: 'o-type-narrow', mnemonic: 'MOV.BS',
  word: oType(14, 5, 6, 3), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000080002010', '0x0000000080002010': '0x00000000000000FE' } });
// Narrow store to verify only narrow bytes written
addVector({ name: 'mov-bu-store', group: 'o-type-narrow', mnemonic: 'MOV.BU',
  word: oType(13, 5, 6, 0, 1), registers: { 5: 0xABCDn, 6: 0x80002000n },
  memory: { '0x0000000080002000': '0xFFFFFFFFFFFFFFFF' } });
addVector({ name: 'mov-hs-store', group: 'o-type-narrow', mnemonic: 'MOV.HS',
  word: oType(16, 5, 6, 0, 1), registers: { 5: 0x1234ABCDn, 6: 0x80002000n },
  memory: { '0x0000000080002000': '0xFFFFFFFFFFFFFFFF' } });

// ===== O-TYPE .W (opcodes 19..26) =====

addVector({ name: 'add-w-overflow', group: 'o-type-word', mnemonic: 'ADD.W',
  word: oType(19, 5, 6), registers: { 5: 1n, 6: 0x7FFFFFFFn }, flags: {} });
addVector({ name: 'add-w-no-overflow', group: 'o-type-word', mnemonic: 'ADD.W',
  word: oType(19, 5, 6), registers: { 5: 1n, 6: 2n }, flags: {} });
addVector({ name: 'add-w-carry', group: 'o-type-word', mnemonic: 'ADD.W',
  word: oType(19, 5, 6), registers: { 5: 0xFFFFFFFFn, 6: 1n }, flags: {} });

addVector({ name: 'sub-w-basic', group: 'o-type-word', mnemonic: 'SUB.W',
  word: oType(20, 5, 6), registers: { 5: 1n, 6: 0n }, flags: {} });
addVector({ name: 'sub-w-overflow', group: 'o-type-word', mnemonic: 'SUB.W',
  word: oType(20, 5, 6), registers: { 5: 1n, 6: 0x80000000n }, flags: {} });

addVector({ name: 'mul-w-basic', group: 'o-type-word', mnemonic: 'MUL.W',
  word: oType(21, 5, 6), registers: { 5: 2n, 6: 0x40000000n }, flags: { c: true } });
addVector({ name: 'mul-w-negative', group: 'o-type-word', mnemonic: 'MUL.W',
  word: oType(21, 5, 6), registers: { 5: 0xFFFFFFFFn, 6: 2n }, flags: {} });

addVector({ name: 'div-w-basic', group: 'o-type-word', mnemonic: 'DIV.W',
  word: oType(22, 5, 6), registers: { 5: 0xFFFFFFFFFFFFFFFDn, 6: 10n }, flags: {} });

addVector({ name: 'cmp-w-equal', group: 'o-type-word', mnemonic: 'CMP.W',
  word: oType(23, 5, 6), registers: { 5: 0xFFFFFFFFn, 6: 0xFFFFFFFFFFFFFFFFn }, flags: {} });
addVector({ name: 'cmp-w-less', group: 'o-type-word', mnemonic: 'CMP.W',
  word: oType(23, 5, 6), registers: { 5: 5n, 6: 3n }, flags: {} });

addVector({ name: 'sll-w-basic', group: 'o-type-word', mnemonic: 'SLL.W',
  word: oType(24, 5, 6), registers: { 5: 1n, 6: 0x40000000n }, flags: {} });
addVector({ name: 'sll-w-zero-count', group: 'o-type-word', mnemonic: 'SLL.W',
  word: oType(24, 5, 6), registers: { 5: 0n, 6: 0x12345678n }, flags: { c: true } });
addVector({ name: 'sll-w-mask-32', group: 'o-type-word', mnemonic: 'SLL.W',
  word: oType(24, 5, 6), registers: { 5: 32n, 6: 0x12345678n }, flags: {} });
addVector({ name: 'sll-w-carry-out', group: 'o-type-word', mnemonic: 'SLL.W',
  word: oType(24, 5, 6), registers: { 5: 31n, 6: 1n }, flags: {} });

addVector({ name: 'srl-w-basic', group: 'o-type-word', mnemonic: 'SRL.W',
  word: oType(25, 5, 6), registers: { 5: 1n, 6: 0x80000000n }, flags: {} });
addVector({ name: 'srl-w-carry', group: 'o-type-word', mnemonic: 'SRL.W',
  word: oType(25, 5, 6), registers: { 5: 1n, 6: 3n }, flags: {} });

addVector({ name: 'sra-w-basic', group: 'o-type-word', mnemonic: 'SRA.W',
  word: oType(26, 5, 6), registers: { 5: 1n, 6: 0x80000000n }, flags: {} });
addVector({ name: 'sra-w-positive', group: 'o-type-word', mnemonic: 'SRA.W',
  word: oType(26, 5, 6), registers: { 5: 4n, 6: 0x7F000000n }, flags: {} });

// ===== ADDRESSING MODES =====

// Mode 1 (register-deferred) for ADD src
addVector({ name: 'add-d-mode1-src', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 5, 6, 1), registers: { 5: 0x80002000n, 6: 3n },
  memory: { '0x0000000080002000': '0x0000000000000007' } });

// Mode 2 (autoincrement): load from [reg], then reg += 8
addVector({ name: 'mov-d-mode2-src', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 2), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x00000000DEADBEEF' } });

// Mode 3 (autoincrement-deferred)
addVector({ name: 'mov-d-mode3-src', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 3), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000080002010', '0x0000000080002010': '0xCAFEBABEDEADFACE' } });

// Mode 4 (autodecrement)
addVector({ name: 'mov-d-mode4-src', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 4), registers: { 5: 0x80002008n },
  memory: { '0x0000000080002000': '0x1122334455667788' } });

// Mode 5 (autodecrement-deferred)
addVector({ name: 'mov-d-mode5-src', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 5), registers: { 5: 0x80002008n },
  memory: { '0x0000000080002000': '0x0000000080002010', '0x0000000080002010': '0xAAAABBBBCCCCDDDD' } });

// Mode 6 (indexed): address = reg + displacement
addVector({ name: 'mov-d-mode6-src', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 6, 0, 8), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002008': '0x0FEEDFACEBEEF000' } });

// Mode 7 reg!=0 (indexed-deferred): pointer = [reg + disp], value = [pointer]
addVector({ name: 'mov-d-mode7-idxdefer', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 7, 0, 8), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002008': '0x0000000080002010', '0x0000000080002010': '0xFEDCBA9876543210' } });

// Mode 7 reg=0 (PC-relative): address = PC+4 + sign_ext(displacement)
// PC+4 = 0x80001804. Need target in data area. Max disp = 511 -> 0x80001804+511 = 0x80001A03
// Instead use negative: -4 -> 0x80001804 - 4 = 0x80001800 (in code area, bad)
// Use mode 6 reg=0 (absolute): address = 0 + sign_ext(displacement)
// Positive displacements 0..511 give addresses 0..511 (unmapped) -> access fault
// Let's demonstrate this as an access-fault test
addVector({ name: 'mov-d-mode6-abs-fault', group: 'fault', mnemonic: 'MOV',
  word: oType(1, 0, 6, 6, 0, 0), registers: {} });

// Destination modes
addVector({ name: 'mov-d-store-mode1', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 1), registers: { 5: 0xCAFEn, 6: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'mov-d-store-mode2', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 2), registers: { 5: 0xBEEFn, 6: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'mov-d-store-mode4', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 4), registers: { 5: 0xDEADn, 6: 0x80002008n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'mov-d-store-mode6', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 6, 8), registers: { 5: 0xFACEn, 6: 0x80002000n },
  memory: { '0x0000000080002008': '0x0000000000000000' } });

// Same register: autoincrement source and destination (proves staging)
addVector({ name: 'mov-d-same-reg-autoinc', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 5, 2, 2), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x1111222233334444', '0x0000000080002008': '0x0000000000000000' } });

// ===== S-TYPE =====

// CLR (opcode 2049)
addVector({ name: 'clr-reg', group: 's-type', mnemonic: 'CLR',
  word: sType(CLR, 5), registers: { 5: 0xFFFFFFFFFFFFFFFFn }, flags: { c: true } });
addVector({ name: 'clr-mem', group: 's-type', mnemonic: 'CLR',
  word: sType(CLR, 5, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0xFFFFFFFFFFFFFFFF' }, flags: { c: true } });

// INC (opcode 2050)
addVector({ name: 'inc-basic', group: 's-type', mnemonic: 'INC',
  word: sType(INC, 5), registers: { 5: 5n }, flags: { c: true } });
addVector({ name: 'inc-overflow', group: 's-type', mnemonic: 'INC',
  word: sType(INC, 5), registers: { 5: 0x7FFFFFFFFFFFFFFFn }, flags: { c: true } });
addVector({ name: 'inc-wrap', group: 's-type', mnemonic: 'INC',
  word: sType(INC, 5), registers: { 5: 0xFFFFFFFFFFFFFFFFn }, flags: {} });

// DEC (opcode 2051)
addVector({ name: 'dec-basic', group: 's-type', mnemonic: 'DEC',
  word: sType(DEC, 5), registers: { 5: 5n }, flags: { c: true } });
addVector({ name: 'dec-overflow', group: 's-type', mnemonic: 'DEC',
  word: sType(DEC, 5), registers: { 5: 0x8000000000000000n }, flags: { c: false } });
addVector({ name: 'dec-to-zero', group: 's-type', mnemonic: 'DEC',
  word: sType(DEC, 5), registers: { 5: 1n }, flags: {} });

// NEG (opcode 2052)
addVector({ name: 'neg-basic', group: 's-type', mnemonic: 'NEG',
  word: sType(NEG, 5), registers: { 5: 1n }, flags: {} });
addVector({ name: 'neg-overflow', group: 's-type', mnemonic: 'NEG',
  word: sType(NEG, 5), registers: { 5: 0x8000000000000000n }, flags: {} });
addVector({ name: 'neg-zero', group: 's-type', mnemonic: 'NEG',
  word: sType(NEG, 5), registers: { 5: 0n }, flags: {} });

// COM (opcode 2053)
addVector({ name: 'com-basic', group: 's-type', mnemonic: 'COM',
  word: sType(COM, 5), registers: { 5: 0n }, flags: { c: true } });
addVector({ name: 'com-allones', group: 's-type', mnemonic: 'COM',
  word: sType(COM, 5), registers: { 5: 0xFFFFFFFFFFFFFFFFn }, flags: {} });

// JMP (opcode 2054)
addVector({ name: 'jmp-reg', group: 's-type', mnemonic: 'JMP',
  word: sType(JMP, 5, 0), registers: { 5: 0x80002000n } });
addVector({ name: 'jmp-deferred', group: 's-type', mnemonic: 'JMP',
  word: sType(JMP, 5, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000080002100' } });
addVector({ name: 'jmp-autoinc', group: 's-type', mnemonic: 'JMP',
  word: sType(JMP, 5, 2), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000080002200' } });
addVector({ name: 'jmp-indexed', group: 's-type', mnemonic: 'JMP',
  word: sType(JMP, 5, 6, 8), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002008': '0x0000000080002300' } });

// JSR (opcode 2055)
addVector({ name: 'jsr-reg', group: 's-type', mnemonic: 'JSR',
  word: sType(JSR, 5, 0), registers: { 5: 0x80002000n } });
addVector({ name: 'jsr-deferred', group: 's-type', mnemonic: 'JSR',
  word: sType(JSR, 5, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000080002100' } });

// RTS (opcode 2056)
addVector({ name: 'rts-basic', group: 's-type', mnemonic: 'RTS',
  word: sType(RTS), registers: { 1: 0x80002000n } });

// FENCE.I (opcode 2058)
addVector({ name: 'fence-i', group: 's-type', mnemonic: 'FENCE.I',
  word: sType(FENCEI) });

// NOP (opcode 2060)
addVector({ name: 'nop', group: 's-type', mnemonic: 'NOP',
  word: sType(NOP) });

// BRK (opcode 2059) - breakpoint trap
addVector({ name: 'brk-trap', group: 's-type', mnemonic: 'BRK',
  word: sType(BRK) });

// SYS (opcode 2057) - environment call from kernel
addVector({ name: 'sys-kernel', group: 's-type', mnemonic: 'SYS',
  word: sType(SYS) });

// ===== BRANCHES =====

const branchConditions = [
  { enc: 0, mn: 'BR', taken: {}, notTaken: null },
  { enc: 1, mn: 'BEQ', taken: { z: true }, notTaken: { z: false } },
  { enc: 2, mn: 'BNE', taken: { z: false }, notTaken: { z: true } },
  { enc: 3, mn: 'BLT', taken: { n: true, v: false }, notTaken: { n: false, v: false } },
  { enc: 4, mn: 'BGE', taken: { n: false, v: false }, notTaken: { n: true, v: false } },
  { enc: 5, mn: 'BLTU', taken: { c: false }, notTaken: { c: true } },
  { enc: 6, mn: 'BGEU', taken: { c: true }, notTaken: { c: false } },
  { enc: 7, mn: 'BGT', taken: { z: false, n: false, v: false }, notTaken: { z: true, n: false, v: false } },
  { enc: 8, mn: 'BLE', taken: { z: true, n: false, v: false }, notTaken: { z: false, n: false, v: false } },
  { enc: 9, mn: 'BCS', taken: { c: true }, notTaken: { c: false } },
  { enc: 10, mn: 'BCC', taken: { c: false }, notTaken: { c: true } },
  { enc: 11, mn: 'BVS', taken: { v: true }, notTaken: { v: false } },
  { enc: 12, mn: 'BVC', taken: { v: false }, notTaken: { v: true } },
  { enc: 13, mn: 'BMI', taken: { n: true }, notTaken: { n: false } },
  { enc: 14, mn: 'BPL', taken: { n: false }, notTaken: { n: true } },
];

for (const cond of branchConditions) {
  // Taken with positive offset (+4 words)
  addVector({
    name: `branch-${cond.mn.toLowerCase()}-taken`,
    group: 'branch',
    mnemonic: cond.mn,
    word: bType(cond.enc, 4),
    registers: {},
    flags: cond.taken
  });
  if (cond.notTaken !== null) {
    addVector({
      name: `branch-${cond.mn.toLowerCase()}-nottaken`,
      group: 'branch',
      mnemonic: cond.mn,
      word: bType(cond.enc, 4),
      registers: {},
      flags: cond.notTaken
    });
  }
}

// Branch with negative offset: -1 in 20-bit signed = 0xFFFFF
addVector({ name: 'branch-br-negative', group: 'branch', mnemonic: 'BR',
  word: bType(0, 0xFFFFF),
  registers: {}, flags: {} });

// Branch with large positive offset
addVector({ name: 'branch-beq-far', group: 'branch', mnemonic: 'BEQ',
  word: bType(1, 100),
  registers: {}, flags: { z: true } });

// Reserved condition 15 = illegal
addVector({ name: 'branch-reserved-15', group: 'branch', mnemonic: 'BR',
  word: bType(15, 0), registers: {}, flags: {} });

// ===== I-TYPE =====

// ADDI.D (subop 0)
addVector({ name: 'addi-d-basic', group: 'i-type', mnemonic: 'ADDI.D',
  word: iType(0, 5, 6, 10), registers: { 5: 5n } });
addVector({ name: 'addi-d-negative-imm', group: 'i-type', mnemonic: 'ADDI.D',
  word: iType(0, 5, 6, 0x3FFF), registers: { 5: 5n } }); // imm = -1
addVector({ name: 'addi-d-dst-x0', group: 'i-type', mnemonic: 'ADDI.D',
  word: iType(0, 5, 0, 10), registers: { 5: 5n } });
addVector({ name: 'addi-d-src-x0-li', group: 'i-type', mnemonic: 'ADDI.D',
  word: iType(0, 0, 6, 42), registers: {} });

// SUBI.D (subop 1)
addVector({ name: 'subi-d-basic', group: 'i-type', mnemonic: 'SUBI.D',
  word: iType(1, 5, 6, 3), registers: { 5: 10n } });
addVector({ name: 'subi-d-negative-imm', group: 'i-type', mnemonic: 'SUBI.D',
  word: iType(1, 5, 6, 0x3FFF), registers: { 5: 0n } }); // sub -1 = add 1

// ANDI.D (subop 2)
addVector({ name: 'andi-d-basic', group: 'i-type', mnemonic: 'ANDI.D',
  word: iType(2, 5, 6, 0x0F), registers: { 5: 0xABCDn }, flags: { c: true } });
addVector({ name: 'andi-d-neg-imm', group: 'i-type', mnemonic: 'ANDI.D',
  word: iType(2, 5, 6, 0x3FFF), registers: { 5: 0x8000000000000001n } });

// ORI.D (subop 3)
addVector({ name: 'ori-d-basic', group: 'i-type', mnemonic: 'ORI.D',
  word: iType(3, 5, 6, 0xFF), registers: { 5: 0x100n }, flags: { c: false } });

// XORI.D (subop 4)
addVector({ name: 'xori-d-basic', group: 'i-type', mnemonic: 'XORI.D',
  word: iType(4, 5, 6, 0xFF), registers: { 5: 0xFFn }, flags: { c: true } });
addVector({ name: 'xori-d-neg-imm', group: 'i-type', mnemonic: 'XORI.D',
  word: iType(4, 5, 6, 0x3FFF), registers: { 5: 0xFFFFFFFFFFFFFFFFn } });

// SLLI.D (subop 5)
addVector({ name: 'slli-d-basic', group: 'i-type', mnemonic: 'SLLI.D',
  word: iType(5, 5, 6, 4), registers: { 5: 0x1n } });
addVector({ name: 'slli-d-zero', group: 'i-type', mnemonic: 'SLLI.D',
  word: iType(5, 5, 6, 0), registers: { 5: 0x1n }, flags: { c: true } });
addVector({ name: 'slli-d-max', group: 'i-type', mnemonic: 'SLLI.D',
  word: iType(5, 5, 6, 63), registers: { 5: 0x1n } });

// SRLI.D (subop 6)
addVector({ name: 'srli-d-basic', group: 'i-type', mnemonic: 'SRLI.D',
  word: iType(6, 5, 6, 4), registers: { 5: 0x80n } });
addVector({ name: 'srli-d-max', group: 'i-type', mnemonic: 'SRLI.D',
  word: iType(6, 5, 6, 63), registers: { 5: 0x8000000000000000n } });

// SRAI.D (subop 7)
addVector({ name: 'srai-d-basic', group: 'i-type', mnemonic: 'SRAI.D',
  word: iType(7, 5, 6, 4), registers: { 5: 0x8000000000000000n } });
addVector({ name: 'srai-d-zero-count', group: 'i-type', mnemonic: 'SRAI.D',
  word: iType(7, 5, 6, 0), registers: { 5: 0x8000000000000000n }, flags: { c: false } });

// ADDI.W (subop 8)
addVector({ name: 'addi-w-overflow', group: 'i-type', mnemonic: 'ADDI.W',
  word: iType(8, 5, 6, 1), registers: { 5: 0x7FFFFFFFn } });
addVector({ name: 'addi-w-basic', group: 'i-type', mnemonic: 'ADDI.W',
  word: iType(8, 5, 6, 5), registers: { 5: 3n } });

// SUBI.W (subop 9)
addVector({ name: 'subi-w-basic', group: 'i-type', mnemonic: 'SUBI.W',
  word: iType(9, 5, 6, 1), registers: { 5: 0n } });

// SLLI.W (subop 10)
addVector({ name: 'slli-w-basic', group: 'i-type', mnemonic: 'SLLI.W',
  word: iType(10, 5, 6, 1), registers: { 5: 0x40000000n } });
addVector({ name: 'slli-w-zero', group: 'i-type', mnemonic: 'SLLI.W',
  word: iType(10, 5, 6, 0), registers: { 5: 0x12345678n }, flags: { c: true } });

// SRLI.W (subop 11)
addVector({ name: 'srli-w-basic', group: 'i-type', mnemonic: 'SRLI.W',
  word: iType(11, 5, 6, 1), registers: { 5: 0x80000000n } });

// SRAI.W (subop 12)
addVector({ name: 'srai-w-basic', group: 'i-type', mnemonic: 'SRAI.W',
  word: iType(12, 5, 6, 1), registers: { 5: 0x80000000n } });
addVector({ name: 'srai-w-zero-count', group: 'i-type', mnemonic: 'SRAI.W',
  word: iType(12, 5, 6, 0), registers: { 5: 0x80000000n }, flags: { c: true } });

// ===== U-TYPE =====

addVector({ name: 'lui-positive', group: 'u-type', mnemonic: 'LUI',
  word: uType(0, 6, 0x1234), registers: {} });
addVector({ name: 'lui-negative', group: 'u-type', mnemonic: 'LUI',
  word: uType(0, 6, 0x3FFFFF), registers: {} });
addVector({ name: 'lui-dst-x0', group: 'u-type', mnemonic: 'LUI',
  word: uType(0, 0, 0x1234), registers: {} });
addVector({ name: 'auipc-positive', group: 'u-type', mnemonic: 'AUIPC',
  word: uType(1, 6, 0x1), registers: {} });
addVector({ name: 'auipc-negative', group: 'u-type', mnemonic: 'AUIPC',
  word: uType(1, 6, 0x3FFFFF), registers: {} });
addVector({ name: 'auipc-dst-x0', group: 'u-type', mnemonic: 'AUIPC',
  word: uType(1, 0, 0x100), registers: {} });

// ===== C-TYPE (P0 Privileged) =====

addVector({ name: 'csrrw-kscratch', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x005), registers: { 4: 0x1234n },
  csrs: { kscratch: '0x0000000000000055' } });
addVector({ name: 'csrrs-pstatus', group: 'c-type', mnemonic: 'CSRRS',
  word: cType(1, 3, 4, 0x000), registers: { 4: 0x01n },
  flags: { c: false } });
addVector({ name: 'csrrc-ie', group: 'c-type', mnemonic: 'CSRRC',
  word: cType(2, 3, 4, 0x008), registers: { 4: 0x02n },
  csrs: { ie: '0x0000000000000022' } });
addVector({ name: 'csrrw-tvec', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x001), registers: { 4: 0x80002000n },
  csrs: { tvec: '0x0000000080001900' } });
addVector({ name: 'csrrw-epc', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x002), registers: { 4: 0x80002004n },
  csrs: { epc: '0x0000000080001000' } });
addVector({ name: 'csrrw-timecmp', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x00b), registers: { 4: 1000n } });
addVector({ name: 'csrrs-cause-read', group: 'c-type', mnemonic: 'CSRRS',
  word: cType(1, 3, 0, 0x003), registers: {} });
addVector({ name: 'csrrs-tval-read', group: 'c-type', mnemonic: 'CSRRS',
  word: cType(1, 3, 0, 0x004), registers: {} });
addVector({ name: 'csrrs-ip-read', group: 'c-type', mnemonic: 'CSRRS',
  word: cType(1, 3, 0, 0x007), registers: {} });
addVector({ name: 'csrrs-hartid-read', group: 'c-type', mnemonic: 'CSRRS',
  word: cType(1, 3, 0, 0x009), registers: {} });
// The time CSR is a platform counter: the oracle only advances it when the
// platform does, so its value is marked platform-dependent and a replay
// harness must not compare the destination register against this snapshot.
addVector({ name: 'csrrs-time-read', group: 'c-type', mnemonic: 'CSRRS',
  word: cType(1, 3, 0, 0x00a), registers: {}, platformDependent: ['3'] });
addVector({ name: 'csrrs-nowrite', group: 'c-type', mnemonic: 'CSRRS',
  word: cType(1, 3, 0, 0x005), registers: {},
  csrs: { kscratch: '0x00000000DEADBEEF' } });
addVector({ name: 'csrrc-nowrite', group: 'c-type', mnemonic: 'CSRRC',
  word: cType(2, 3, 0, 0x008), registers: {},
  csrs: { ie: '0x0000000000000022' } });
// Write to read-only cause -> illegal
addVector({ name: 'csrrw-cause-illegal', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x003), registers: { 4: 0n } });
// Write to read-only hartid -> illegal
addVector({ name: 'csrrw-hartid-illegal', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x009), registers: { 4: 0n } });
// Write to read-only time -> illegal
addVector({ name: 'csrrw-time-illegal', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x00a), registers: { 4: 0n } });
// Write to read-only ip -> illegal
addVector({ name: 'csrrw-ip-illegal', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x007), registers: { 4: 0n } });
// Write to read-only tval -> illegal
addVector({ name: 'csrrw-tval-illegal', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x004), registers: { 4: 0n } });
// Unimplemented CSR -> illegal
addVector({ name: 'csr-unimplemented', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0xFFF), registers: { 4: 0n } });
// Misaligned tvec write -> illegal
addVector({ name: 'csrrw-tvec-misaligned', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x001), registers: { 4: 0x80001901n } });
// Misaligned epc write -> illegal
addVector({ name: 'csrrw-epc-misaligned', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x002), registers: { 4: 0x80001801n } });
// Nonzero satp write -> illegal (Bare-only)
addVector({ name: 'csrrw-satp-nonzero', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x006), registers: { 4: 1n } });
// Zero satp write -> valid (no-op in Bare mode)
addVector({ name: 'csrrw-satp-zero', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x006), registers: { 4: 0n } });
// RTE with preset epc
addVector({ name: 'rte-basic', group: 'c-type', mnemonic: 'RTE',
  word: cType(8), registers: {},
  csrs: { epc: '0x0000000080001820' } });
// NOTE: an RTE with a misaligned epc is deliberately absent. epc can only be
// written through a CSR write, which rejects an unaligned value, and no trap
// can deposit a misaligned resume address, so that initial state is not
// architecturally reachable and cannot be installed by a replay harness.
// CSRRW pstatus - full write
addVector({ name: 'csrrw-pstatus-full', group: 'c-type', mnemonic: 'CSRRW',
  word: cType(0, 3, 4, 0x000), registers: { 4: 0x23Fn },
  flags: { c: false, v: false, z: false, n: false } });

// ===== ALIGNMENT FAULTS =====

addVector({ name: 'load-misaligned-64', group: 'fault', mnemonic: 'MOV',
  word: oType(1, 5, 6, 1), registers: { 5: 0x80002004n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'store-misaligned-64', group: 'fault', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 1), registers: { 5: 0xCAFEn, 6: 0x80002004n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'load-misaligned-32', group: 'fault', mnemonic: 'MOV.WU',
  word: oType(17, 5, 6, 1), registers: { 5: 0x80002001n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'load-misaligned-16', group: 'fault', mnemonic: 'MOV.HU',
  word: oType(15, 5, 6, 1), registers: { 5: 0x80002001n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'store-misaligned-32', group: 'fault', mnemonic: 'MOV.WU',
  word: oType(17, 5, 6, 0, 1), registers: { 5: 0xDEADn, 6: 0x80002002n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
addVector({ name: 'store-misaligned-16', group: 'fault', mnemonic: 'MOV.HS',
  word: oType(16, 5, 6, 0, 1), registers: { 5: 0xDEADn, 6: 0x80002001n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });
// Misaligned deferred pointer (mode 3, pointer at non-8-aligned addr)
addVector({ name: 'load-misaligned-deferred-ptr', group: 'fault', mnemonic: 'MOV',
  word: oType(1, 5, 6, 3), registers: { 5: 0x80002004n },
  memory: { '0x0000000080002000': '0x0000000000000000' } });

// ===== DIVIDE FAULTS =====

addVector({ name: 'div-d-by-zero', group: 'fault', mnemonic: 'DIV',
  word: oType(5, 5, 6), registers: { 5: 0n, 6: 10n }, flags: { c: true } });
addVector({ name: 'div-d-int-overflow', group: 'fault', mnemonic: 'DIV',
  word: oType(5, 5, 6), registers: { 5: 0xFFFFFFFFFFFFFFFFn, 6: 0x8000000000000000n }, flags: {} });
addVector({ name: 'div-w-by-zero', group: 'fault', mnemonic: 'DIV.W',
  word: oType(22, 5, 6), registers: { 5: 0n, 6: 10n }, flags: { c: true } });
addVector({ name: 'div-w-int-overflow', group: 'fault', mnemonic: 'DIV.W',
  word: oType(22, 5, 6), registers: { 5: 0xFFFFFFFFFFFFFFFFn, 6: 0x80000000n }, flags: {} });
addVector({ name: 'div-d-by-zero-mem', group: 'fault', mnemonic: 'DIV',
  word: oType(5, 5, 6, 1), registers: { 5: 0x80002000n, 6: 42n },
  memory: { '0x0000000080002000': '0x0000000000000000' }, flags: {} });

// ===== ACCESS FAULTS =====

addVector({ name: 'load-access-fault', group: 'fault', mnemonic: 'MOV',
  word: oType(1, 5, 6, 1), registers: { 5: 0x90000000n } });
addVector({ name: 'store-access-fault', group: 'fault', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 1), registers: { 5: 0xCAFEn, 6: 0x90000000n } });

// ===== ILLEGAL ENCODINGS =====

// Reserved O-Type opcode 0
addVector({ name: 'otype-reserved-0', group: 'illegal', mnemonic: 'RESERVED',
  word: oType(0, 5, 6), registers: {} });
addVector({ name: 'otype-reserved-27', group: 'illegal', mnemonic: 'RESERVED',
  word: oType(27, 5, 6), registers: {} });
addVector({ name: 'otype-reserved-28', group: 'illegal', mnemonic: 'RESERVED',
  word: oType(28, 5, 6), registers: {} });
addVector({ name: 'otype-reserved-31', group: 'illegal', mnemonic: 'RESERVED',
  word: oType(31, 5, 6), registers: {} });
// Two displacement operands
addVector({ name: 'otype-two-displacements', group: 'illegal', mnemonic: 'RESERVED',
  word: oType(1, 5, 6, 6, 6, 8), registers: {} });
// Nonzero displacement when unused
addVector({ name: 'otype-nonzero-unused-disp', group: 'illegal', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 0, 1), registers: {} });
// Reserved S-Type opcode 2048
addVector({ name: 'stype-reserved-2048', group: 'illegal', mnemonic: 'RESERVED',
  word: sType(2048, 5), registers: {} });
// Another reserved S-Type (2061 and above should be reserved)
addVector({ name: 'stype-reserved-2061', group: 'illegal', mnemonic: 'RESERVED',
  word: sType(2061, 5), registers: {} });
// RTS with nonzero fields
addVector({ name: 'rts-nonzero-fields', group: 'illegal', mnemonic: 'RTS',
  word: sType(RTS, 5, 1, 0), registers: {} });
// FENCE.I with nonzero fields
addVector({ name: 'fencei-nonzero-fields', group: 'illegal', mnemonic: 'FENCE.I',
  word: sType(FENCEI, 5, 0, 1), registers: {} });
// NOP with nonzero fields
addVector({ name: 'nop-nonzero-fields', group: 'illegal', mnemonic: 'NOP',
  word: sType(NOP, 0, 1), registers: {} });
// BRK with nonzero fields
addVector({ name: 'brk-nonzero-fields', group: 'illegal', mnemonic: 'BRK',
  word: sType(BRK, 5, 0, 0), registers: {} });
// SYS with nonzero reserved
addVector({ name: 'sys-nonzero-fields', group: 'illegal', mnemonic: 'SYS',
  word: (sType(SYS) | 0x00001) >>> 0, registers: {} });
// Reserved I-Type sub-ops
addVector({ name: 'itype-reserved-13', group: 'illegal', mnemonic: 'RESERVED',
  word: iType(13, 5, 6, 0), registers: {} });
addVector({ name: 'itype-reserved-14', group: 'illegal', mnemonic: 'RESERVED',
  word: iType(14, 5, 6, 0), registers: {} });
addVector({ name: 'itype-reserved-15', group: 'illegal', mnemonic: 'RESERVED',
  word: iType(15, 5, 6, 0), registers: {} });
// SLLI.D with reserved immediate bits
addVector({ name: 'slli-d-reserved-bit', group: 'illegal', mnemonic: 'SLLI.D',
  word: iType(5, 5, 6, 0x40), registers: { 5: 1n } });
// SRLI.D with reserved bits
addVector({ name: 'srli-d-reserved-bit', group: 'illegal', mnemonic: 'SRLI.D',
  word: iType(6, 5, 6, 0x80), registers: { 5: 1n } });
// SLLI.W with reserved bits
addVector({ name: 'slli-w-reserved-bit', group: 'illegal', mnemonic: 'SLLI.W',
  word: iType(10, 5, 6, 0x20), registers: { 5: 1n } });
// Reserved C-Type sub-op
addVector({ name: 'ctype-reserved-subop', group: 'illegal', mnemonic: 'RESERVED',
  word: cType(3), registers: {} });
// C-Type with nonzero low bits
addVector({ name: 'ctype-nonzero-lowbits', group: 'illegal', mnemonic: 'RESERVED',
  word: (cType(0, 3, 4, 0x005) | 0x3) >>> 0, registers: { 4: 0n } });


// ===== ADDITIONAL COVERAGE =====

// x0 as source proves it reads as zero
addVector({ name: 'add-d-src-x0', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 0, 6), registers: { 6: 42n }, flags: {} });
addVector({ name: 'sub-d-src-x0', group: 'o-type', mnemonic: 'SUB',
  word: oType(3, 0, 6), registers: { 6: 42n }, flags: {} });
addVector({ name: 'and-d-dst-x0', group: 'o-type', mnemonic: 'AND',
  word: oType(7, 5, 0), registers: { 5: 0xFFn }, flags: { c: true } });
addVector({ name: 'sll-d-dst-x0', group: 'o-type', mnemonic: 'SLL',
  word: oType(10, 5, 0), registers: { 5: 2n }, flags: {} });

// S-Type memory operands
addVector({ name: 'inc-mem', group: 's-type', mnemonic: 'INC',
  word: sType(INC, 5, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000000000005' }, flags: { c: true } });
addVector({ name: 'dec-mem', group: 's-type', mnemonic: 'DEC',
  word: sType(DEC, 5, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000000000005' }, flags: {} });
addVector({ name: 'neg-mem', group: 's-type', mnemonic: 'NEG',
  word: sType(NEG, 5, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x0000000000000003' }, flags: {} });
addVector({ name: 'com-mem', group: 's-type', mnemonic: 'COM',
  word: sType(COM, 5, 1), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002000': '0x00000000000000FF' }, flags: {} });

// More narrow modes
addVector({ name: 'mov-wu-autodec-deferred', group: 'o-type-narrow', mnemonic: 'MOV.WU',
  word: oType(17, 5, 6, 5), registers: { 5: 0x80002008n },
  memory: { '0x0000000080002000': '0x0000000080002010', '0x0000000080002010': '0x00000000DEADBEEF' } });

// Indexed S-Type
addVector({ name: 'inc-indexed', group: 's-type', mnemonic: 'INC',
  word: sType(INC, 5, 6, 8), registers: { 5: 0x80002000n },
  memory: { '0x0000000080002008': '0x000000000000000A' }, flags: {} });

// Additional SLL carry
addVector({ name: 'sll-d-carry-out', group: 'o-type', mnemonic: 'SLL',
  word: oType(10, 5, 6), registers: { 5: 1n, 6: 0xC000000000000000n }, flags: {} });

// MOV all ones
addVector({ name: 'mov-d-allones', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6), registers: { 5: 0xFFFFFFFFFFFFFFFFn }, flags: { c: false } });

// SRL carry out
addVector({ name: 'srl-d-carry-out', group: 'o-type', mnemonic: 'SRL',
  word: oType(11, 5, 6), registers: { 5: 4n, 6: 0x000000000000000Fn }, flags: {} });

// ADD.W sign extension result
addVector({ name: 'add-w-sign-extend', group: 'o-type-word', mnemonic: 'ADD.W',
  word: oType(19, 5, 6), registers: { 5: 0xFFFFFFFFn, 6: 0xFFFFFFFFn }, flags: {} });

// ADDI.D with large negative imm
addVector({ name: 'addi-d-max-neg', group: 'i-type', mnemonic: 'ADDI.D',
  word: iType(0, 5, 6, 0x2000), registers: { 5: 0n } });

// JSR link register value
addVector({ name: 'jsr-link-value', group: 's-type', mnemonic: 'JSR',
  word: sType(JSR, 5, 0), registers: { 1: 0x99n, 5: 0x80002100n } });

// Branch edge cases with both N and V set
addVector({ name: 'branch-bge-nv-set', group: 'branch', mnemonic: 'BGE',
  word: bType(4, 10), registers: {}, flags: { n: true, v: true } });
addVector({ name: 'branch-blt-nv-set', group: 'branch', mnemonic: 'BLT',
  word: bType(3, 10), registers: {}, flags: { n: true, v: true } });

// ===== EXECUTION ENGINE =====

function buildInitialState(def) {
  const registers = Array(32).fill(0n);
  if (def.registers) {
    for (const [key, val] of Object.entries(def.registers)) {
      const idx = Number(key);
      if (idx > 0 && idx < 31) {
        registers[idx] = BigInt(val);
      }
    }
  }

  const flags = {
    n: Boolean(def.flags?.n),
    z: Boolean(def.flags?.z),
    v: Boolean(def.flags?.v),
    c: Boolean(def.flags?.c)
  };

  const privileged = {
    hartid: 0n,
    mode: KERNEL_MODE,
    previousMode: USER_MODE,
    interruptEnable: false,
    previousInterruptEnable: false,
    tvec: TRAP_HANDLER,
    epc: 0n,
    cause: 0n,
    tval: 0n,
    kscratch: 0n,
    ie: 0n,
    time: 0n,
    timecmp: MASK64,
    paging: { satp: 0n, kua: false, mxr: false, tlbGeneration: 0 }
  };

  if (def.csrs) {
    if (def.csrs.epc) privileged.epc = BigInt(def.csrs.epc);
    if (def.csrs.kscratch) privileged.kscratch = BigInt(def.csrs.kscratch);
    if (def.csrs.ie) privileged.ie = BigInt(def.csrs.ie);
    if (def.csrs.timecmp) privileged.timecmp = BigInt(def.csrs.timecmp);
    if (def.csrs.tvec) privileged.tvec = BigInt(def.csrs.tvec);
  }

  return createState({
    registers,
    pc: INSN_PC,
    flags,
    privileged,
    atomic: {}
  });
}

function buildMemory(def) {
  const mem = new PdpvVirtMemory(0x8000000);
  const tvec = def.csrs?.tvec ? BigInt(def.csrs.tvec) : TRAP_HANDLER;
  const selfBranch = bType(0, 0xFFFFF);
  const tvecOffset = Number(tvec - 0x80000000n);
  const ramView = new DataView(mem.ram.buffer);
  if (tvecOffset >= 0 && tvecOffset < mem.ram.length - 4) {
    ramView.setUint32(tvecOffset, selfBranch, true);
  }

  if (def.memory) {
    for (const [addrStr, valStr] of Object.entries(def.memory)) {
      const addr = BigInt(addrStr);
      if (addr >= 0x80000000n && addr < 0x88000000n) {
        mem.write64(addr, BigInt(valStr));
      }
    }
  }

  return mem;
}

function runVector(def) {
  const state = buildInitialState(def);
  const mem = buildMemory(def);

  const result = step(state, def.word, mem);
  const finalState = result.state;
  const trace = result.trace;

  const isTrap = trace.status === 'trap';
  const finalPstatus = pstatusValue(finalState.flags, finalState.privileged);

  const expectRegs = {};
  for (let i = 1; i <= 30; i++) {
    if (finalState.registers[i] !== 0n) {
      expectRegs[String(i)] = fmt64(finalState.registers[i]);
    }
  }

  const expectMemory = {};
  const memAddresses = new Set();
  if (def.memory) {
    for (const addrStr of Object.keys(def.memory)) {
      const addr = BigInt(addrStr);
      if (addr >= 0x80000000n && addr < 0x88000000n) {
        memAddresses.add(addr);
      }
    }
  }
  if (trace.memoryChanges) {
    for (const change of trace.memoryChanges) {
      // Narrow stores are reported back as the containing aligned word.
      const addr = BigInt(change.address) & ~7n;
      if (addr >= 0x80000000n && addr < 0x88000000n) {
        memAddresses.add(addr);
      }
    }
  }
  for (const addr of memAddresses) {
    expectMemory[fmt64(addr)] = fmt64(mem.read64(addr));
  }

  let trap = null;
  if (isTrap) {
    trap = {
      cause: fmt64(finalState.privileged.cause),
      tval: fmt64(finalState.privileged.tval),
      epc: fmt64(finalState.privileged.epc)
    };
  }

  return {
    pc: fmt64(finalState.pc),
    pstatus: fmt64(finalPstatus),
    registers: expectRegs,
    memory: Object.keys(expectMemory).length > 0 ? expectMemory : undefined,
    trap
  };
}

// ===== ADDITIONAL OPERAND-MODE COVERAGE =====
// A PC-relative literal must sit within the +/-511 byte O-Type displacement
// window around INSN_PC + 4, so it uses the reserved literal slot between the
// harness setup block and the instruction slot.
const PC_LITERAL = 0x80001700n;
const PC_LITERAL_DISP = Number(PC_LITERAL - (INSN_PC + 4n));

// MOV X(PC), Rn : PC-relative source (mode 7, register 0)
addVector({ name: 'mov-d-pcrel-load', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 0, 6, 7, 0, PC_LITERAL_DISP),
  registers: {},
  memory: { [fmt64(PC_LITERAL)]: '0x00000000CAFEBABE' } });
// MOV Rn, X(PC) : PC-relative destination
addVector({ name: 'mov-d-pcrel-store', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 0, 0, 7, PC_LITERAL_DISP),
  registers: { 5: 0x1122334455667788n },
  memory: { [fmt64(PC_LITERAL)]: '0x0000000000000000' } });
// MOV.WU Rn, X(PC) : narrow PC-relative store keeps the upper bytes
addVector({ name: 'mov-wu-pcrel-store', group: 'o-type-narrow',
  mnemonic: 'MOV.WU',
  word: oType(17, 5, 0, 0, 7, PC_LITERAL_DISP),
  registers: { 5: 0xFFFFFFFFAABBCCDDn },
  memory: { [fmt64(PC_LITERAL)]: '0x1111111122222222' } });

// MOV Rn, @(Rm)+ : autoincrement-deferred destination, pointer update is 8
addVector({ name: 'mov-d-dst-mode3', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 3),
  registers: { 5: 0x00000000DEADBEEFn, 6: DATA_BASE },
  memory: {
    [fmt64(DATA_BASE)]: fmt64(DATA_BASE + 0x100n),
    [fmt64(DATA_BASE + 0x100n)]: '0x0000000000000000'
  } });
// MOV Rn, @-(Rm) : autodecrement-deferred destination
addVector({ name: 'mov-d-dst-mode5', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 5),
  registers: { 5: 0x00000000FEEDFACEn, 6: DATA_BASE + 8n },
  memory: {
    [fmt64(DATA_BASE)]: fmt64(DATA_BASE + 0x108n),
    [fmt64(DATA_BASE + 0x108n)]: '0x0000000000000000'
  } });
// MOV Rn, @X(Rm) : indexed-deferred destination
addVector({ name: 'mov-d-dst-mode7-indexed', group: 'o-type', mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 7, 16),
  registers: { 5: 0x0F0F0F0F0F0F0F0Fn, 6: DATA_BASE },
  memory: {
    [fmt64(DATA_BASE + 16n)]: fmt64(DATA_BASE + 0x200n),
    [fmt64(DATA_BASE + 0x200n)]: '0x0000000000000000'
  } });
// MOV.BU Rn, -(Rm) : byte autodecrement destination scales by one
addVector({ name: 'mov-bu-dst-mode4', group: 'o-type-narrow',
  mnemonic: 'MOV.BU',
  word: oType(13, 5, 6, 0, 4),
  registers: { 5: 0x00000000000000A5n, 6: DATA_BASE + 1n },
  memory: { [fmt64(DATA_BASE)]: '0xFFFFFFFFFFFFFFFF' } });
// ADD (Rn)+, (Rm)+ : both operands autoincrement through memory
addVector({ name: 'add-d-mode2-mode2', group: 'o-type', mnemonic: 'ADD',
  word: oType(2, 5, 6, 2, 2),
  registers: { 5: DATA_BASE, 6: DATA_BASE + 0x40n },
  memory: {
    [fmt64(DATA_BASE)]: '0x0000000000000007',
    [fmt64(DATA_BASE + 0x40n)]: '0x0000000000000035'
  } });
// Reserved O-Type opcodes 29 and 30
addVector({ name: 'otype-reserved-29', group: 'illegal', mnemonic: 'RESERVED',
  word: oType(29, 5, 6), registers: {} });
addVector({ name: 'otype-reserved-30', group: 'illegal', mnemonic: 'RESERVED',
  word: oType(30, 5, 6), registers: {} });

// ===== FAULT ORDER AND CONTROL-TARGET ALIGNMENT =====
// S0 Section 13: source faults precede destination faults.
addVector({ name: 'fault-source-before-destination', group: 'fault',
  mnemonic: 'MOV',
  word: oType(1, 5, 6, 1, 1),
  registers: { 5: DATA_BASE + 1n, 6: DATA_BASE + 2n } });
// A well-formed source with a misaligned destination reports the store fault.
addVector({ name: 'fault-destination-misaligned', group: 'fault',
  mnemonic: 'MOV',
  word: oType(1, 5, 6, 1, 1),
  registers: { 5: DATA_BASE, 6: DATA_BASE + 4n },
  memory: { [fmt64(DATA_BASE)]: '0x0000000000000042' } });
// A destination deferred pointer read is a load, even for a store form.
addVector({ name: 'fault-destination-pointer-is-load', group: 'fault',
  mnemonic: 'MOV',
  word: oType(1, 5, 6, 0, 3),
  registers: { 5: 0x1234n, 6: DATA_BASE + 1n } });
// S0 Section 10: a control-transfer target must be 4-byte aligned, and the
// fault retires no staged autoincrement and no link register.
addVector({ name: 'jmp-misaligned-target', group: 's-type', mnemonic: 'JMP',
  word: sType(JMP, 5, 2), registers: { 5: DATA_BASE + 2n } });
addVector({ name: 'jsr-misaligned-target', group: 's-type', mnemonic: 'JSR',
  word: sType(JSR, 5, 0), registers: { 5: DATA_BASE + 1n } });
addVector({ name: 'rts-misaligned-target', group: 's-type', mnemonic: 'RTS',
  word: sType(RTS), registers: { 1: DATA_BASE + 3n } });

// ===== PDP-V-A0 ATOMICS AND ORDERING =====
const atomicNames = [
  'LR', 'SC', 'AMOSWAP', 'AMOADD', 'AMOAND', 'AMOOR', 'AMOXOR',
  'AMOMIN', 'AMOMAX', 'AMOMINU', 'AMOMAXU'
];
const orderingNames = ['', '.AQ', '.RL', '.AQRL'];

/*
 * Every operation, width, and ordering encoding is a reference-emulator
 * vector.  SC intentionally has no reservation in this single-step corpus,
 * so these are failure-path vectors rather than success-only samples.
 * Stateful success, invalidation, alias, P39 and fault-priority cases live in
 * the registered pdp12-atomic test.
 */
for (let operation = 0; operation <= 10; operation++) {
  for (let width = 0; width <= 1; width++) {
    for (let ordering = 0; ordering <= 3; ordering++) {
      const aq = ordering & 1;
      const rl = (ordering >> 1) & 1;
      const suffix = width ? '.D' : '.W';
      const mnemonic = atomicNames[operation] + suffix +
        orderingNames[ordering];
      const name = `a0-${atomicNames[operation].toLowerCase()}-` +
        `${width ? 'd' : 'w'}-${['relaxed', 'aq', 'rl', 'aqrl'][ordering]}`;
      const registers = { 5: DATA_BASE };
      if (operation !== 0) {
        registers[6] = width
          ? 0x8000000000000003n
          : 0x0000000080000003n;
      }
      addVector({
        name,
        group: 'a0-atomic',
        mnemonic,
        word: aType(operation, width, aq, rl,
          operation === 0 ? 0 : 6, 5, 7),
        registers,
        flags: { n: true, c: true },
        memory: {
          [fmt64(DATA_BASE)]: width
            ? '0x7ffffffffffffffd'
            : '0x1122334480000001'
        }
      });
    }
  }
}

// Register aliases, x0 result discard, and .W old-value sign extension.
addVector({ name: 'a0-amoadd-rd-rs2', group: 'a0-atomic',
  mnemonic: 'AMOADD.D',
  word: aType(3, 1, 0, 0, 6, 5, 6),
  registers: { 5: DATA_BASE, 6: 9n },
  memory: { [fmt64(DATA_BASE)]: '0x0000000000000007' } });
addVector({ name: 'a0-amoswap-rd-rs1', group: 'a0-atomic',
  mnemonic: 'AMOSWAP.D',
  word: aType(2, 1, 0, 0, 6, 5, 5),
  registers: { 5: DATA_BASE, 6: 0x1234n },
  memory: { [fmt64(DATA_BASE)]: '0x0000000000000042' } });
addVector({ name: 'a0-amoxor-rd-x0', group: 'a0-atomic',
  mnemonic: 'AMOXOR.W',
  word: aType(6, 0, 0, 0, 6, 5, 0),
  registers: { 5: DATA_BASE, 6: 0xffffffffn },
  memory: { [fmt64(DATA_BASE)]: '0xaabbccdd80000001' } });
addVector({ name: 'a0-lr-w-sign-extension', group: 'a0-atomic',
  mnemonic: 'LR.W',
  word: aType(0, 0, 0, 0, 0, 5, 7),
  registers: { 5: DATA_BASE },
  memory: { [fmt64(DATA_BASE)]: '0x0123456780000001' } });

/*
 * Adversarial source upper halves: the low words determine the architectural
 * result, while a mistaken 64-bit comparison would choose the opposite word.
 */
for (const [operation, mnemonic] of [
  [7, 'AMOMIN.W'],
  [8, 'AMOMAX.W'],
]) {
  addVector({
    name: `a0-${mnemonic.toLowerCase().replace('.', '-')}-source-upper`,
    group: 'a0-atomic',
    mnemonic,
    word: aType(operation, 0, 0, 0, 6, 5, 7),
    registers: { 5: DATA_BASE, 6: 0x00000001fffffffEn },
    memory: { [fmt64(DATA_BASE)]: '0xaabbccdd00000005' }
  });
}
for (const [operation, mnemonic] of [
  [9, 'AMOMINU.W'],
  [10, 'AMOMAXU.W'],
]) {
  addVector({
    name: `a0-${mnemonic.toLowerCase().replace('.', '-')}-source-upper`,
    group: 'a0-atomic',
    mnemonic,
    word: aType(operation, 0, 0, 0, 6, 5, 7),
    registers: { 5: DATA_BASE, 6: 0xffffffff00000005n },
    memory: { [fmt64(DATA_BASE)]: '0xaabbccddfffffffe' }
  });
}

// All 225 legal predecessor/successor combinations are oracle vectors.
for (let predecessor = 1; predecessor <= 15; predecessor++) {
  for (let successor = 1; successor <= 15; successor++) {
    addVector({
      name: `a0-fence-${predecessor.toString(16)}-${successor.toString(16)}`,
      group: 'a0-fence',
      mnemonic: 'FENCE',
      word: fType(predecessor, successor),
      registers: {},
      flags: { z: true, v: true }
    });
  }
}

// Decode, alignment, and bare physical access failures.
addVector({ name: 'a0-lr-reserved-low-bits', group: 'illegal',
  mnemonic: 'LR.D', word: aType(0, 1, 0, 0, 0, 5, 7, 1),
  registers: { 5: DATA_BASE } });
addVector({ name: 'a0-lr-nonzero-rs2', group: 'illegal',
  mnemonic: 'LR.D', word: aType(0, 1, 0, 0, 6, 5, 7),
  registers: { 5: DATA_BASE, 6: 1n } });
addVector({ name: 'a0-reserved-operation', group: 'illegal',
  mnemonic: 'RESERVED', word: aType(11, 1, 0, 0, 6, 5, 7),
  registers: { 5: DATA_BASE, 6: 1n } });
addVector({ name: 'a0-fence-zero-predecessor', group: 'illegal',
  mnemonic: 'FENCE', word: fType(0, 1), registers: {} });
addVector({ name: 'a0-fence-zero-successor', group: 'illegal',
  mnemonic: 'FENCE', word: fType(1, 0), registers: {} });
addVector({ name: 'a0-fence-reserved-low-bits', group: 'illegal',
  mnemonic: 'FENCE', word: fType(1, 1, 1), registers: {} });
addVector({ name: 'a0-lr-w-misaligned', group: 'fault',
  mnemonic: 'LR.W', word: aType(0, 0, 0, 0, 0, 5, 7),
  registers: { 5: DATA_BASE + 2n } });
addVector({ name: 'a0-lr-d-access-fault', group: 'fault',
  mnemonic: 'LR.D', word: aType(0, 1, 0, 0, 0, 5, 7),
  registers: { 5: UNMAPPED_ADDR } });
addVector({ name: 'a0-sc-d-misaligned', group: 'fault',
  mnemonic: 'SC.D', word: aType(1, 1, 0, 0, 6, 5, 7),
  registers: { 5: DATA_BASE + 4n, 6: 1n },
  memory: {
    [fmt64(DATA_BASE)]: '0x0123456789abcdef',
    [fmt64(DATA_BASE + 8n)]: '0xfedcba9876543210'
  } });
addVector({ name: 'a0-sc-d-access-before-mismatch', group: 'fault',
  mnemonic: 'SC.D', word: aType(1, 1, 0, 0, 6, 5, 7),
  registers: { 5: UNMAPPED_ADDR, 6: 1n } });
addVector({ name: 'a0-amo-w-misaligned', group: 'fault',
  mnemonic: 'AMOADD.W', word: aType(3, 0, 0, 0, 6, 5, 7),
  registers: { 5: DATA_BASE + 2n, 6: 1n },
  memory: { [fmt64(DATA_BASE)]: '0xfedcba9876543210' } });
addVector({ name: 'a0-amo-d-access-fault', group: 'fault',
  mnemonic: 'AMOADD.D', word: aType(3, 1, 0, 0, 6, 5, 7),
  registers: { 5: UNMAPPED_ADDR, 6: 1n } });

// ===== MAIN =====

function main() {
  const args = process.argv.slice(2);
  let outputPath = path.resolve(__dirname, 'data/pdp12/reference-vectors.json');
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--output' && args[i + 1]) {
      outputPath = path.resolve(args[i + 1]);
      i++;
    }
  }

  const vectors = [];
  const names = new Set();
  let errors = 0;

  for (const def of vectorDefs) {
    if (names.has(def.name)) {
      console.error(`DUPLICATE vector name: ${def.name}`);
      errors++;
      continue;
    }
    names.add(def.name);

    try {
      const expect = runVector(def);

      const vector = {
        name: def.name,
        group: def.group,
        mnemonic: def.mnemonic,
        word: fmt32(def.word),
        registers: {},
        flags: {
          n: Boolean(def.flags?.n),
          z: Boolean(def.flags?.z),
          v: Boolean(def.flags?.v),
          c: Boolean(def.flags?.c)
        }
      };

      if (def.registers) {
        for (const [key, val] of Object.entries(def.registers)) {
          const idx = Number(key);
          if (idx >= 1 && idx <= 30 && BigInt(val) !== 0n) {
            vector.registers[String(idx)] = fmt64(BigInt(val));
          }
        }
      }

      if (def.platformDependent) {
        vector.platformDependent = [...def.platformDependent];
      }

      if (def.csrs) {
        vector.csrs = {};
        for (const [key, val] of Object.entries(def.csrs)) {
          vector.csrs[key] = val;
        }
      }

      if (def.memory && Object.keys(def.memory).length > 0) {
        vector.memory = {};
        for (const [addr, val] of Object.entries(def.memory)) {
          vector.memory[addr] = val;
        }
      }

      vector.expect = expect;
      vectors.push(vector);
    } catch (err) {
      console.error(`ERROR generating vector "${def.name}": ${err.message}`);
      console.error(err.stack);
      errors++;
    }
  }

  if (errors > 0) {
    console.error(`\n${errors} vector(s) failed generation.`);
    process.exit(1);
  }

  const output = {
    schemaVersion: 1,
    profile: profile.id,
    generator: 'tests/pdp12-generate-vectors.js',
    insnPc: fmt64(INSN_PC),
    trapHandler: fmt64(TRAP_HANDLER),
    vectors
  };

  const dir = path.dirname(outputPath);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + '\n');

  const groups = {};
  for (const v of vectors) {
    groups[v.group] = (groups[v.group] || 0) + 1;
  }
  console.log(`Generated ${vectors.length} vectors to ${outputPath}`);
  console.log('Vectors per group:');
  for (const [group, count] of Object.entries(groups).sort()) {
    console.log(`  ${group}: ${count}`);
  }
}

main();
