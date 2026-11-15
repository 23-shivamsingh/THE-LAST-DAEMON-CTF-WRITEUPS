#!/usr/bin/env python3
"""VMC1 stack-VM disassembler (ISA reversed from vmcore)."""
import struct, sys

OPS = {
    0x00: ('NOP', 0), 0x10: ('PUSH8', 1), 0x11: ('PUSH16', 2),
    0x20: ('PIN', 1),      # push input[imm8]
    0x21: ('PLEN', 0),     # push input length
    0x22: ('PINI', 0),     # pop idx, push input[idx]
    0x30: ('ADD', 0), 0x31: ('SUB', 0), 0x32: ('XOR', 0), 0x33: ('MUL', 0),
    0x34: ('ROL', 1), 0x35: ('ROR', 1), 0x36: ('EQ', 0), 0x37: ('LT', 0),
    0x38: ('LAND', 0), 0x39: ('LOR', 0), 0x3a: ('NOT', 0),
    0x40: ('DUP', 0), 0x41: ('SWAP', 0), 0x42: ('DROP', 0),
    0x50: ('JMP', 2), 0x51: ('JZ', 2), 0x52: ('JNZ', 2),
    0x60: ('LOAD', 0), 0x61: ('STORE', 0),
    0x70: ('CALL', 2), 0x71: ('RET', 0),
    0x7b: ('DECOY', 0), 0x7c: ('CODEBYTE', 1), 0x7d: ('PERIPH', 1),
    0x7e: ('NESTED', 0), 0xfe: ('HALT', 0),
}

def load(path):
    b = open(path, 'rb').read()
    assert b[:4] == b'VMC1'
    ver, flags = b[4], b[5]
    code_len, data_len = struct.unpack_from('<HH', b, 16)
    code = b[20:20+code_len]
    data = b[20+code_len:20+code_len+data_len]
    return ver, flags, code, data, b

def dis(code):
    pc = 0
    out = []
    while pc < len(code):
        op = code[pc]
        name, n = OPS.get(op, ('DB 0x%02x' % op, 0))
        ops = code[pc+1:pc+1+n]
        out.append((pc, name, ops))
        pc += 1 + n
    return out

if __name__ == '__main__':
    ver, flags, code, data, raw = load(sys.argv[1])
    print('ver=%d flags=%#x code=%d data=%d' % (ver, flags, len(code), len(data)))
    for pc, name, ops in dis(code):
        operand = ''
        if len(ops) == 1: operand = '0x%02x' % ops[0]
        elif len(ops) == 2: operand = '0x%04x' % (ops[0] | (ops[1] << 8))
        print('%04x: %-8s %s' % (pc, name, operand))

ROPS = {0x80:'MOV', 0x81:'LDI', 0x82:'LEN', 0x83:'ADD', 0x84:'SUB', 0x85:'XOR',
        0x86:'MUL', 0x87:'ROL', 0x88:'EQ', 0x89:'LT', 0x8a:'JZ', 0x8b:'JNZ',
        0x8c:'LOAD', 0x8d:'STORE', 0x8e:'CALL', 0x8f:'RET', 0x90:'HALT',
        0x91:'MOVR', 0x92:'LDR'}

def reg_dis(code):
    pc = 0
    out = []
    while pc < len(code):
        op = code[pc]
        name = ROPS.get(op, 'DB 0x%02x' % op)
        if op in (0x82, 0x8f): n = 1
        elif op in (0x8e,): n = 2  # +imm16 handled below
        elif op in (0x8a, 0x8b): n = 3  # reg + imm16 = 4 bytes
        elif op == 0x90: n = 1
        elif op in (0x83,0x84,0x85,0x86,0x87,0x88,0x89): n = 3
        else: n = 2
        if op in (0x8a, 0x8b):
            ops = code[pc+1:pc+4]; size = 4
        elif op == 0x8e:
            ops = code[pc+1:pc+3]; size = 3
        elif op == 0x90:
            ops = code[pc+1:pc+2]; size = 2
        else:
            ops = code[pc+1:pc+1+n]; size = 1 + n
        out.append((pc, name, ops))
        pc += size
    return out
