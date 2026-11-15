#!/usr/bin/env python3
"""Symbolic execution for the VMC1 stack VM. Finds an input that reaches HALT with
nonzero TOS (accept), avoiding DECOY paths. Solves byte constraints by bounded search."""
import sys, itertools
sys.path.insert(0, 'work')
from vmdis import load, OPS

G = 0x9e3779b97f4a7c15
C1 = 0xbf58476d1ce4e5b9
C2 = 0x94d049bb133111eb
M64 = (1 << 64) - 1

def decrypt_code(code, token_hex):
    t = bytes.fromhex(token_hex)
    tlo = int.from_bytes(t[:8], 'little')
    thi = int.from_bytes(t[8:], 'little')
    out = bytearray(code)
    for i in range(len(out)):
        s = ((i >> 3) + G + thi) & M64
        t1 = ((s ^ (s >> 30)) * C1) & M64
        rax = ((t1 ^ (t1 >> 27)) * C2) & M64
        rdi = ((tlo ^ rax ^ (rax >> 31)) + G) & M64
        u = ((rdi ^ (rdi >> 30)) * C1) & M64
        u = ((u ^ (u >> 27)) * C2) & M64
        u = u ^ (u >> 31)
        out[i] ^= (u >> ((i & 7) * 8)) & 0xff
    return bytes(out)

def translate_ops(code, table):
    return bytes(table[b] for b in code)

def opcode_map(code, table):
    """Walk instructions, translating only opcode bytes through the inverse table.
    Returns dict pc -> translated opcode.""" 
    m = {}
    pc = 0
    while pc < len(code):
        top = table[code[pc]]
        m[pc] = top
        n = OPS.get(top, ('?', 0))[1]
        pc += 1 + n
    return m

def rol(x, r): r &= 7; return ((x << r) | (x >> (-r & 7))) & 0xff
def ror(x, r): r &= 7; return ((x >> r) | (x << (-r & 7))) & 0xff

class E:
    __slots__ = ('op','a','b')
    def __init__(s, op, a=None, b=None): s.op, s.a, s.b = op, a, b
    def __repr__(s):
        if s.op in ('c','in'): return '%s%d' % (s.op, s.a)
        if s.op in ('rol','ror'): return '%s(%s,%s)' % (s.op, s.a, s.b if isinstance(s.b,E) else s.b)
        return '(%s %s %s)' % (s.op, s.a, s.b)

def const(v): return E('c', v & 0xff)
def is_c(e, v=None): return e.op == 'c' and (v is None or e.a == (v & 0xff))

DATA = b''
def evale(e, inp):
    if e.op == 'c': return e.a
    if e.op == 'in': return inp[e.a]
    if e.op == 'load':
        a = evale(e.a, inp)
        return DATA[a] if a < len(DATA) else 0
    a = evale(e.a, inp)
    if e.op == 'not': return 1 if a == 0 else 0
    b = evale(e.b, inp)
    return {'add': lambda: (a+b)&0xff, 'sub': lambda: (a-b)&0xff, 'xor': lambda: a^b,
            'mul': lambda: (a*b)&0xff, 'eq': lambda: int(a==b), 'lt': lambda: int(a<b),
            'land': lambda: int(a!=0 and b!=0), 'lor': lambda: int(a!=0 or b!=0),
            'rol': lambda: rol(a,b), 'ror': lambda: ror(a,b)}[e.op]()

def freevars(e, s=None):
    s = set() if s is None else s
    if e is None: return s
    if e.op == 'in': s.add(e.a)
    if e.op not in ('c','in','plen'):
        freevars(e.a, s)
        if isinstance(e.b, E): freevars(e.b, s)
    return s

def subst_plen(e, L):
    if e is None or e.op == 'c' or e.op == 'in': return e
    if e.op == 'plen': return const(L)
    return E(e.op, subst_plen(e.a, L), subst_plen(e.b, L) if isinstance(e.b, E) else e.b)

import struct as _struct
def mode_of(raw): return _struct.unpack_from('<H', raw, 6)[0]

def solve_guard(path, inlen_hint=32, maxsteps=20000, verbose=False, token=None):
    global DATA
    ver, flags, code, data, raw = load(path)
    mode = mode_of(raw)
    if mode & 0x10:
        code = decrypt_code(code, token)
    opmap = opcode_map(code, data) if mode & 0x8 else None
    DATA = data
    initmem = frozenset((i, const(b)) for i, b in enumerate(data)) if data else frozenset()
    results = []
    def run():
        start = (0, (), initmem, (), (), ())  # pc, stack, mem, decoy, constraints, callstack
        work = [start]
        seen = set()
        while work:
            pc, stack, mem, decoy, cons, cs = work.pop()
            steps = 0
            stack = list(stack); mem = dict(mem); cs = list(cs)
            while steps < maxsteps:
                steps += 1
                key = (pc, len(stack), decoy)
                if pc < 0 or pc >= len(code): break
                op = opmap[pc] if opmap is not None else code[pc]
                name, n = OPS.get(op, ('BAD', 0))
                ops = code[pc+1:pc+1+n]
                imm = ops[0] if n == 1 else (ops[0] | (ops[1] << 8) if n == 2 else None)
                npc = pc + 1 + n
                if name == 'NOP': pc = npc; continue
                if name == 'PUSH8' or name == 'PUSH16': stack.append(const(imm)); pc = npc; continue
                if name == 'PLEN': stack.append(E('plen')); pc = npc; continue
                if name == 'PIN': stack.append(E('in', imm)); pc = npc; continue
                if name == 'PINI':
                    ix = stack.pop()
                    if is_c(ix): stack.append(E('in', ix.a))
                    else: stack.append(E('ini', ix))
                    pc = npc; continue
                if name in ('ADD','SUB','XOR','MUL','EQ','LT','LAND','LOR'):
                    b = stack.pop(); a = stack.pop()
                    m = {'ADD':'add','SUB':'sub','XOR':'xor','MUL':'mul','EQ':'eq','LT':'lt','LAND':'land','LOR':'lor'}[name]
                    stack.append(E(m, a, b)); pc = npc; continue
                if name in ('ROL','ROR'): stack.append(E(name.lower(), stack.pop(), const(imm))); pc = npc; continue
                if name == 'NOT': stack.append(E('not', stack.pop())); pc = npc; continue
                if name == 'DUP': stack.append(stack[-1]); pc = npc; continue
                if name == 'SWAP': stack[-1], stack[-2] = stack[-2], stack[-1]; pc = npc; continue
                if name == 'DROP': stack.pop(); pc = npc; continue
                if name == 'JMP': pc = imm; continue
                if name in ('JZ','JNZ'):
                    v = stack.pop()
                    if is_c(v):
                        take = (v.a == 0) if name == 'JZ' else (v.a != 0)
                        pc = imm if take else npc; continue
                    # fork: (target, extra constraint that v==0 / v!=0)
                    if name == 'JZ':
                        work.append((imm, tuple(stack), frozenset(mem.items()), decoy, cons + ((v, 0),), tuple(cs)))
                        work.append((npc, tuple(stack), frozenset(mem.items()), decoy, cons + ((v, 1),), tuple(cs)))
                    else:
                        work.append((imm, tuple(stack), frozenset(mem.items()), decoy, cons + ((v, 1),), tuple(cs)))
                        work.append((npc, tuple(stack), frozenset(mem.items()), decoy, cons + ((v, 0),), tuple(cs)))
                    break
                if name == 'LOAD':
                    a = stack.pop()
                    if is_c(a): stack.append(mem.get(a.a, const(0)))
                    else: stack.append(E('load', a))
                    pc = npc; continue
                if name == 'STORE':
                    a = stack.pop(); v = stack.pop()
                    if is_c(a): mem[a.a] = v
                    pc = npc; continue
                if name == 'DECOY': decoy = 1; pc = npc; continue
                if name == 'HALT':
                    if stack and not decoy:
                        results.append((stack[-1], cons, list(mem.items())))
                    break
                if name == 'CALL':
                    cs.append(npc); pc = imm; continue
                if name == 'RET':
                    if cs: pc = cs.pop(); continue
                    # RET with empty callstack = HALT-equivalent in stack VM (0xfe path)
                    if stack and not decoy:
                        results.append((stack[-1], cons, list(mem.items())))
                    break
                if name == 'PERIPH':
                    stack.append(mem.get(imm, const(DATA[imm]) if imm < len(DATA) else const(0)))
                    pc = npc; continue
                if name == 'CODEBYTE':
                    stack.append(const(code[imm]) if imm < len(code) else const(0))
                    pc = npc; continue
                if name in ('NESTED',):
                    raise NotImplementedError(name)
                break
        return
    run()
    return ver, flags, code, data, results

def expr_inputs(e):
    return sorted(freevars(e))

def solve_expr(expr, inlen):
    """find input bytes making expr != 0; returns dict of assignments or None"""
    fv = expr_inputs(expr)
    if not fv:
        return {} if evale(expr, {}) != 0 else None
    if len(fv) > 3: return None
    for combo in itertools.product(range(256), repeat=len(fv)):
        inp = dict(zip(fv, combo))
        try:
            if evale(expr, inp) != 0: return inp
        except Exception:
            return None
    return None

def solve_constraints(cons, tos):
    terms = [(e, w) for e, w in list(cons) + [(tos, 1)]]
    order = sorted(range(len(terms)), key=lambda i: len(freevars(terms[i][0])) or 99)
    terms = [terms[i] for i in order]
    def backtrack(i, assign):
        if i == len(terms): return assign
        e, want = terms[i]
        fv = sorted(freevars(e))
        need = [v for v in fv if v not in assign]
        if not need:
            try: v = evale(e, assign)
            except Exception: return None
            if ((v == 0) if want == 0 else (v != 0)): return backtrack(i + 1, assign)
            return None
        if len(need) > 3: return None
        for combo in itertools.product(range(256), repeat=len(need)):
            a2 = dict(assign); a2.update(zip(need, combo))
            try: v = evale(e, a2)
            except Exception: continue
            if ((v == 0) if want == 0 else (v != 0)):
                r = backtrack(i + 1, a2)
                if r is not None: return r
        return None
    return backtrack(0, {})

def answer_from(path, maxlen=33, token=None):
    ver, flags, code, data, results = solve_guard(path, token=token)
    for tos, cons, mem in results:
        for L in range(1, maxlen):
            cons2 = [(subst_plen(e, L), w) for e, w in cons]
            tos2 = subst_plen(tos, L)
            sol = solve_constraints(cons2, tos2)
            if sol is not None:
                if sol and max(sol) >= L:  # referenced beyond declared length
                    continue
                return bytes(sol.get(i, 0) for i in range(L)), ver, flags, len(results)
    return None, ver, flags, len(results)

if __name__ == '__main__':
    path = sys.argv[1]
    ans, ver, flags, npaths = answer_from(path)
    print('accept paths:', npaths)
    print('answer:', ans)

# ---------------- register VM ----------------
def solve_guard_reg(path, maxsteps=20000, token=None):
    global DATA
    ver, flags, code, data, raw = load(path)
    mode = mode_of(raw)
    if mode & 0x10:
        code = decrypt_code(code, token)
    opmap = opcode_map(code, data) if mode & 0x8 else None
    DATA = data
    initmem = frozenset((i, const(b)) for i, b in enumerate(data)) if data else frozenset()
    results = []
    R0 = tuple(const(0) for _ in range(8))
    work = [(0, R0, initmem, (), ())]
    while work:
        pc, regs, mem, cs, cons = work.pop()
        regs = list(regs); mem = dict(mem); cs = list(cs)
        steps = 0
        while steps < maxsteps:
            steps += 1
            if pc < 0 or pc >= len(code): break
            op = opmap[pc] if opmap is not None else code[pc]
            def b(i): return code[pc+i]
            if op in (0x83,0x84,0x85,0x86,0x87,0x88,0x89):
                rd, r1, r2 = b(1), b(2), b(3)
                m = {0x83:'add',0x84:'sub',0x85:'xor',0x86:'mul',0x88:'eq',0x89:'lt'}[op] if op != 0x87 else None
                if op == 0x87:
                    regs[rd] = E('rol', regs[r1], regs[r2])
                else:
                    regs[rd] = E(m, regs[r1], regs[r2])
                pc += 4; continue
            if op == 0x80: regs[b(1)] = const(b(2)); pc += 3; continue
            if op == 0x81: regs[b(1)] = E('in', b(2)); pc += 3; continue
            if op == 0x82: regs[b(1)] = E('plen'); pc += 2; continue
            if op == 0x91: regs[b(1)] = regs[b(2)]; pc += 3; continue
            if op == 0x92:
                ix = regs[b(2)]
                regs[b(1)] = E('in', ix.a) if is_c(ix) else E('ini', ix)
                pc += 3; continue
            if op == 0x8c:
                a = regs[b(2)]
                regs[b(1)] = mem.get(a.a, const(0)) if is_c(a) else E('load', a)
                pc += 3; continue
            if op == 0x8d:
                a = regs[b(2)]
                if is_c(a): mem[a.a] = regs[b(1)]
                pc += 3; continue
            if op in (0x8a, 0x8b):
                v = regs[b(1)]; imm = b(2) | (b(3) << 8)
                if is_c(v):
                    take = (v.a == 0) if op == 0x8a else (v.a != 0)
                    pc = imm if take else pc + 4; continue
                if op == 0x8a:
                    work.append((imm, tuple(regs), frozenset(mem.items()), tuple(cs), cons + ((v, 0),)))
                    work.append((pc + 4, tuple(regs), frozenset(mem.items()), tuple(cs), cons + ((v, 1),)))
                else:
                    work.append((imm, tuple(regs), frozenset(mem.items()), tuple(cs), cons + ((v, 1),)))
                    work.append((pc + 4, tuple(regs), frozenset(mem.items()), tuple(cs), cons + ((v, 0),)))
                break
            if op == 0x8e:
                imm = b(1) | (b(2) << 8); cs.append(pc + 3); pc = imm; continue
            if op == 0x8f:
                if cs: pc = cs.pop(); continue
                break
            if op == 0x90:
                if not cs:
                    results.append((regs[b(1)], cons, list(mem.items())))
                break
            break
    return ver, flags, code, data, results

def answer_from_reg(path, maxlen=33, token=None):
    ver, flags, code, data, results = solve_guard_reg(path, token=token)
    for tos, cons, mem in results:
        for L in range(1, maxlen):
            cons2 = [(subst_plen(e, L), w) for e, w in cons]
            tos2 = subst_plen(tos, L)
            sol = solve_constraints(cons2, tos2)
            if sol is not None:
                if sol and max(sol) >= L: continue
                return bytes(sol.get(i, 0) for i in range(L)), ver, flags, len(results)
    return None, ver, flags, len(results)

def all_solutions(cons, tos, cap=6000):
    terms = [(e, w) for e, w in list(cons) + [(tos, 1)]]
    order = sorted(range(len(terms)), key=lambda i: len(freevars(terms[i][0])) or 99)
    terms = [terms[i] for i in order]
    out = []
    def backtrack(i, assign):
        if len(out) >= cap: return
        if i == len(terms): out.append(dict(assign)); return
        e, want = terms[i]
        fv = sorted(freevars(e))
        need = [v for v in fv if v not in assign]
        if not need:
            try: v = evale(e, assign)
            except Exception: return
            if ((v == 0) if want == 0 else (v != 0)): backtrack(i + 1, assign)
            return
        if len(need) > 3: return
        for combo in itertools.product(range(256), repeat=len(need)):
            a2 = dict(assign); a2.update(zip(need, combo))
            try: v = evale(e, a2)
            except Exception: continue
            if ((v == 0) if want == 0 else (v != 0)):
                backtrack(i + 1, a2)
                if len(out) >= cap: return
    backtrack(0, {})
    return out

def charset_score(bs):
    return sum(1 for b in bs if (0x61 <= b <= 0x7a) or (0x30 <= b <= 0x39))

def pick_best(sols, L):
    cands = []
    for sol in sols:
        if sol and max(sol) >= L: continue
        cands.append(bytes(sol.get(i, 0) for i in range(L)))
    if not cands: return None
    cands.sort(key=charset_score, reverse=True)
    return cands[0]
