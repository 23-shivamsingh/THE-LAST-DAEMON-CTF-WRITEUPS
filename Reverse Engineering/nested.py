#!/usr/bin/env python3
"""Solver for nested-VM guards (code = 7e fe; nested program in the data section)."""
import sys, subprocess, re
sys.path.insert(0, 'work')
from vmdis import load
from vmexec import E, const, all_solutions, pick_best, charset_score

def parse_nested(data):
    checks = []
    pc = 0
    while pc < len(data):
        op = data[pc]
        if op == 0x00: pc += 1; continue
        if op == 0xff: break
        if op == 0x01:
            checks.append(('len', data[pc+1])); pc += 2
        elif op == 0x02:
            checks.append(('xor', data[pc+1], data[pc+2], data[pc+3])); pc += 4
        elif op == 0x03:
            checks.append(('add', data[pc+1], data[pc+2], data[pc+3])); pc += 4
        elif op == 0x04:
            checks.append(('rot', data[pc+1], data[pc+2], data[pc+3], data[pc+4])); pc += 5
        elif op == 0x05:
            checks.append(('pair', data[pc+1], data[pc+2], data[pc+3], data[pc+4], data[pc+5])); pc += 6
        elif op == 0x06:
            checks.append(('diff', data[pc+1], data[pc+2], data[pc+3], data[pc+4])); pc += 5
        else:
            raise ValueError('bad nested op %02x at %d' % (op, pc))
    return checks

def solve_nested(path):
    v, f, code, data, raw = load(path)
    checks = parse_nested(data)
    L = next((c[1] for c in checks if c[0] == 'len'), None)
    cons = []
    for c in checks:
        if c[0] == 'xor': _, i, k, vv = c; cons.append((E('eq', E('xor', E('in', i), const(k)), const(vv)), 1))
        elif c[0] == 'add': _, i, k, vv = c; cons.append((E('eq', E('add', E('in', i), const(k)), const(vv)), 1))
        elif c[0] == 'rot': _, i, r, k, vv = c; cons.append((E('eq', E('xor', E('rol', E('in', i), const(r)), const(k)), const(vv)), 1))
        elif c[0] == 'diff': _, i1, i2, k, vv = c; cons.append((E('eq', E('xor', E('xor', E('in', i1), E('in', i2)), const(k)), const(vv)), 1))
    # pair checks: k1*in[i1] + k2*in[i2] == v where k1=data[pc+3], k2=data[pc+4]
    for c in checks:
        if c[0] == 'pair':
            _, i1, i2, k1, k2, vv = c
            cons.append((E('eq', E('add', E('mul', const(k1), E('in', i1)), E('mul', const(k2), E('in', i2))), const(vv)), 1))
    sols = all_solutions(cons, const(1))
    best = pick_best(sols, L or 0)
    return best, checks

if __name__ == '__main__':
    print(solve_nested(sys.argv[1])[0])
