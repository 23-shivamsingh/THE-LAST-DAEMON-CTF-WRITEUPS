#!/usr/bin/env python3
"""Constant extractor v2 - simulates main()'s immediate/memory setup writes.
Works on both template variants (SALT_INIT copies and movabs immediates)."""
import struct, subprocess, re, sys, os

def load(path):
    data = open(path, 'rb').read()
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    entsize, num = struct.unpack_from('<HH', data, 0x36)
    segs = []
    for i in range(num):
        off = e_phoff + i * entsize
        if struct.unpack_from('<I', data, off)[0] == 1:
            p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from('<QQQQQ', data, off + 8)
            segs.append((p_vaddr, p_offset, p_filesz))
    return data, segs

def rd(data, segs, vaddr, size):
    for v, o, s in segs:
        if v <= vaddr and vaddr + size <= v + s:
            return data[o + vaddr - v: o + vaddr - v + size]
    raise ValueError(f'vaddr {vaddr:#x} unmapped')

def cstr(data, segs, vaddr):
    for v, o, s in segs:
        if v <= vaddr < v + s:
            st = o + vaddr - v
            return data[st:data.index(b'\x00', st)].decode()
    return None

STRIPPED_MAP = {0x406228: 'stage_id', 0x406224: 'mode_id', 0x406270: 'salt',
                0x406260: 'msalt', 0x406240: 'target_ct', 0x406230: 'target_len',
                0x4061a0: 'flag_ct', 0x406160: 'flag_hash', 0x406118: 'prev_hash_hex',
                0x406110: 'base_token', 0x406108: 'b64alpha', 0x4060e0: 'milestone_hashes',
                0x4060c8: 'decoy', 0x4060c0: 'teaser', 0x406220: 'magic4', 0x406180: 'flag_len'}

def symmap(path):
    out = subprocess.run(['nm', path], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        m = re.match(r'([0-9a-f]+) [a-zA-Z] (\S+)', line)
        if m: d[int(m.group(1), 16)] = m.group(2)
    if not any(v == 'stage_id' for v in d.values()):
        # stripped binary: template layout is identical (verified against layer31)
        d.update(STRIPPED_MAP)
    return d

def extract(path):
    data, segs = load(path)
    addr2name = symmap(path)
    dis = subprocess.run(['objdump', '-d', '-M', 'intel', path, '--disassemble=main'],
                         capture_output=True, text=True).stdout
    if '\tmov' not in dis and ' mov' not in dis:
        # stripped: main address is loaded into rdi by _start
        ent = subprocess.run(['readelf', '-h', path], capture_output=True, text=True).stdout
        ea = int(re.search(r'Entry point address:\s+0x([0-9a-f]+)', ent).group(1), 16)
        st = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn', path,
                             '--start-address=%#x' % ea, '--stop-address=%#x' % (ea + 0x40)],
                            capture_output=True, text=True).stdout
        ma = int(re.search(r'mov\s+rdi,0x([0-9a-f]+)', st).group(1), 16)
        dis = subprocess.run(['objdump', '-d', '-M', 'intel', path,
                              '--start-address=%#x' % ma, '--stop-address=%#x' % (ma + 0x200)],
                             capture_output=True, text=True).stdout
    writes = {}  # vaddr -> int (up to 8 bytes)
    widths = {}
    regs = {}
    xmm0 = b'\x00' * 16
    for line in dis.splitlines():
        m = re.match(r'\s+[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*(\S.*)', line)
        if not m: continue
        ins = m.group(1)
        m2 = re.match(r'movdqa\s+xmm0,XMMWORD PTR \[rip\+0x[0-9a-f]+\]\s+# ([0-9a-f]+)', ins)
        if m2: xmm0 = rd(data, segs, int(m2.group(1), 16), 16); continue
        m2 = re.match(r'movdqu\s+xmm0,XMMWORD PTR \[rip\+0x[0-9a-f]+\]\s+# ([0-9a-f]+)', ins)
        if m2: xmm0 = rd(data, segs, int(m2.group(1), 16), 16); continue
        m2 = re.match(r'movq\s+xmm0,QWORD PTR \[rip\+0x[0-9a-f]+\]\s+# ([0-9a-f]+)', ins)
        if m2: xmm0 = rd(data, segs, int(m2.group(1), 16), 8) + b'\x00' * 8; continue
        m2 = re.match(r'movhps\s+xmm0,QWORD PTR \[rip\+0x[0-9a-f]+\]\s+# ([0-9a-f]+)', ins)
        if m2: xmm0 = xmm0[:8] + rd(data, segs, int(m2.group(1), 16), 8); continue
        if re.match(r'pxor\s+xmm0,xmm0', ins): xmm0 = b'\x00' * 16; continue
        m2 = re.match(r'mov(?:aps|ups|dqu)\s+XMMWORD PTR \[rip\+0x[0-9a-f]+\],xmm0\s+# ([0-9a-f]+)', ins)
        if m2:
            a = int(m2.group(1), 16)
            writes[a] = struct.unpack('<Q', xmm0[:8])[0]; widths[a] = 8
            writes[a + 8] = struct.unpack('<Q', xmm0[8:])[0]; widths[a + 8] = 8
            continue
        m2 = re.match(r'movq\s+QWORD PTR \[rip\+0x[0-9a-f]+\],xmm0\s+# ([0-9a-f]+)', ins)
        if m2:
            a = int(m2.group(1), 16)
            writes[a] = struct.unpack('<Q', xmm0[:8])[0]; widths[a] = 8
            continue
        m2 = re.match(r'movabs\s+([er][a-z0-9]+),(0x[0-9a-f]+)', ins)
        if m2: regs[m2.group(1)] = int(m2.group(2), 16); continue
        m2 = re.match(r'mov\s+([er][a-z0-9]+),(0x[0-9a-f]+|\d+)(\s|$)', ins)
        if m2:
            v = int(m2.group(2), 0); regs[m2.group(1)] = v
            if m2.group(1).startswith('e') and len(m2.group(1)) == 3: regs['r' + m2.group(1)[1:]] = v
            continue
        m2 = re.match(r'mov\s+([er][a-z0-9]+),QWORD PTR \[rip\+0x[0-9a-f]+\]\s+# ([0-9a-f]+)', ins)
        if m2: regs[m2.group(1)] = struct.unpack('<Q', rd(data, segs, int(m2.group(2), 16), 8))[0]; continue
        m2 = re.match(r'mov\s+([er][a-z0-9]+),DWORD PTR \[rip\+0x[0-9a-f]+\]\s+# ([0-9a-f]+)', ins)
        if m2: regs[m2.group(1)] = struct.unpack('<I', rd(data, segs, int(m2.group(2), 16), 4))[0]; continue
        m2 = re.match(r'mov\s+QWORD PTR \[rip\+0x[0-9a-f]+\],([er][a-z0-9]+)\s+# ([0-9a-f]+)', ins)
        if m2 and m2.group(1) in regs:
            writes[int(m2.group(2), 16)] = regs[m2.group(1)] & 0xffffffffffffffff; widths[int(m2.group(2), 16)] = 8; continue
        m2 = re.match(r'mov\s+DWORD PTR \[rip\+0x[0-9a-f]+\],([er][a-z0-9]+)\s+# ([0-9a-f]+)', ins)
        if m2 and m2.group(1) in regs:
            writes[int(m2.group(2), 16)] = regs[m2.group(1)] & 0xffffffff; widths[int(m2.group(2), 16)] = 4; continue
        m2 = re.match(r'mov\s+QWORD PTR \[rip\+0x[0-9a-f]+\],(0x[0-9a-f]+|\d+)\s+# ([0-9a-f]+)', ins)
        if m2: writes[int(m2.group(2), 16)] = int(m2.group(1), 0); widths[int(m2.group(2), 16)] = 8; continue
        m2 = re.match(r'mov\s+DWORD PTR \[rip\+0x[0-9a-f]+\],(0x[0-9a-f]+|\d+)\s+# ([0-9a-f]+)', ins)
        if m2: writes[int(m2.group(2), 16)] = int(m2.group(1), 0); widths[int(m2.group(2), 16)] = 4; continue
    def name_of(want):
        for a, n in addr2name.items():
            if n == want: return a
        return None
    def getbytes(name, size):
        base = name_of(name)
        if base is None: return None
        out = bytearray(size)
        covered = [False] * size
        for a, v in writes.items():
            if base <= a < base + size:
                w = widths.get(a, 8)
                tmp = struct.pack('<Q', v & 0xffffffffffffffff)
                n = min(w, size - (a - base))
                out[a - base:a - base + n] = tmp[:n]
                for j in range(n): covered[a - base + j] = True
        return bytes(out) if all(covered) else None
    def getint(name):
        base = name_of(name)
        return writes.get(base) if base is not None else None
    def getstr(name):
        base = name_of(name)
        if base is None: return None
        ptr = writes.get(base)
        if ptr is None: return None
        return cstr(data, segs, ptr)
    c = dict(stage_id=getint('stage_id'), mode_id=getint('mode_id'),
             target_len=getint('target_len'), flag_len=getint('flag_len'),
             salt=getbytes('salt', 16), msalt=getbytes('msalt', 16),
             target_ct=getbytes('target_ct', 32), magic4=getbytes('magic4', 4),
             flag_ct=getbytes('flag_ct', 128), flag_hash=getbytes('flag_hash', 32),
             prev_hash_hex=getstr('prev_hash_hex'), base_token=getstr('base_token'),
             b64alpha=getstr('b64alpha'), decoy=getstr('decoy'), teaser=getstr('teaser'))
    if c['target_len'] is None and name_of('target_ct') is not None:
        base = name_of('target_ct')
        covered = [False] * 32
        for a, v in writes.items():
            if base <= a < base + 32:
                for j in range(min(widths.get(a, 8), 32 - (a - base))): covered[a - base + j] = True
        n = 0
        while n < 32 and covered[n]: n += 1
        c['target_len'] = n or None
    if c['flag_len'] is None and name_of('flag_ct') is not None:
        base = name_of('flag_ct')
        covered = [False] * 128
        for a, v in writes.items():
            if base <= a < base + 128:
                for j in range(min(widths.get(a, 8), 128 - (a - base))): covered[a - base + j] = True
        n = 0
        while n < 128 and covered[n]: n += 1
        c['flag_len'] = n or None
    mh = None
    marr = re.search(r'mov\s+rdx,QWORD PTR \[rax\*8\+(0x[0-9a-f]+)\]', dis)
    if marr:
        mh = int(marr.group(1), 16)
    if mh is None:
        mh = name_of('milestone_hashes')
    if mh is not None:
        # in .data: 5 pointers (reduced) - or built in main (full template: array at 0x407120)
        try:
            c['milestone_hashes'] = [cstr(data, segs, struct.unpack('<Q', rd(data, segs, mh + 8 * i, 8))[0]) for i in range(5)]
        except Exception:
            c['milestone_hashes'] = None
    else:
        c['milestone_hashes'] = None
    return c

if __name__ == '__main__':
    base = sys.argv[1] if len(sys.argv) > 1 else '.'
    for n in [int(x) for x in sys.argv[2:]] or range(1, 51):
        p = os.path.join(base, f'layer{n:02d}')
        try:
            c = extract(p)
            print(f'layer{n:02d}: stage={c["stage_id"]} mode={c["mode_id"]} tlen={c["target_len"]} '
                  f'flen={c["flag_len"]} salt={c["salt"].hex() if c["salt"] else None} '
                  f'msalt={c["msalt"].hex() if c["msalt"] else None}')
            print(f'   target={c["target_ct"].hex() if c["target_ct"] else None}')
            print(f'   magic={c["magic4"].hex() if c["magic4"] else None} prevhash={c["prev_hash_hex"]} base={c["base_token"]} b64={c["b64alpha"]}')
            print(f'   milestones={c["milestone_hashes"]}')
        except Exception as e:
            print(f'layer{n:02d}: FAIL {e!r}')
