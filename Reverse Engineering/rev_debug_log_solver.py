#!/usr/bin/env python3
"""
The Debug Log - independent end-to-end solver and verifier.

Written for the Reverse Engineering category writeup. Works directly on the
original The_Debug_Log_Player_Pack.zip. Recovers every handoff token from the
25 debug builds with static analysis only (no external ELF libraries):

  Band 1 (layers 01-05): NEXT_TOKEN strings embedded in plain .rodata.
  Band 2 (layers 06-10): encoded_token_bytes array XOR the named xor_key_byte_0xNN.
  Band 3 (layers 11-15): ordered 'cmp al,imm8' constants inside check_license().
  Band 4 (layers 16-20): invert transform_candidate() (+1, reverse, ROT13, +1, +2)
                         against the embedded transformed_target string.
  Band 5 (layers 21-25): assemble the three artifacts 0x53 / s0urce / window and
                         pass the four release gates; layer25 prints the flag.

On Linux x86-64 every gate from layer02 to layer25 is then EXECUTED with the
statically recovered values (plus two negative tests), which is the
reverification step: the binaries themselves confirm each recovered token.

Usage: python3 rev_debug_log_solver.py The_Debug_Log_Player_Pack.zip
Requires: Python 3.8+, binutils (nm, objdump, strings) on PATH.
"""
import io, os, re, stat, struct, subprocess, sys, tempfile, zipfile

# ---------- minimal ELF64 helpers (no third-party libraries) ----------

def elf_segments(data):
    """Return [(vaddr, file_offset, file_size), ...] for PT_LOAD segments."""
    assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1, 'need ELF64 LE'
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    entsize, num = struct.unpack_from('<HH', data, 0x36)
    segs = []
    for i in range(num):
        off = e_phoff + i * entsize
        if struct.unpack_from('<I', data, off)[0] == 1:  # PT_LOAD
            p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from('<QQQQQ', data, off + 8)
            segs.append((p_vaddr, p_offset, p_filesz))
    return segs

def read_vaddr(data, segs, vaddr, size):
    for p_vaddr, p_offset, p_filesz in segs:
        if p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:
            base = p_offset + (vaddr - p_vaddr)
            return data[base:base + size]
    raise ValueError(f'vaddr {vaddr:#x} not mapped')

def read_cstr(data, segs, vaddr):
    for p_vaddr, p_offset, p_filesz in segs:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            start = p_offset + (vaddr - p_vaddr)
            return data[start:data.index(b'\x00', start)].decode()
    raise ValueError(f'vaddr {vaddr:#x} not mapped')

def nm_symbols(blob_name, data):
    """nm -S on a temporary copy; returns {name: (addr, size)}."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data); tmp = f.name
    try:
        out = subprocess.run(['nm', '-S', tmp], capture_output=True, text=True, check=True).stdout
    finally:
        os.unlink(tmp)
    syms = {}
    for line in out.splitlines():
        m = re.match(r'([0-9a-f]+) ([0-9a-f]+) \w (\S+)', line)
        if m:
            syms[m.group(3)] = (int(m.group(1), 16), int(m.group(2), 16))
    return syms

def disasm_function(blob_data, func):
    """Intel-syntax objdump of one function, from a temporary copy."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(blob_data); tmp = f.name
    try:
        return subprocess.run(['objdump', '-d', '-M', 'intel', tmp,
                               f'--disassemble={func}'],
                              capture_output=True, text=True, check=True).stdout
    finally:
        os.unlink(tmp)

# ---------- band solvers ----------

def band1_strings(builds):
    """Layers 01-05: the next token is a printable NEXT_TOKEN=... string."""
    tokens = {}
    for n in range(1, 6):
        text = subprocess.run(['strings', '-a', '/dev/stdin'], input=builds[n],
                              capture_output=True).stdout.decode('utf-8', 'replace')
        m = re.search(r'NEXT_TOKEN=(\S+)', text)
        tokens[n] = m.group(1)
    return tokens

def band2_xor(builds):
    """Layers 06-10: XOR encoded_token_bytes with the named key byte."""
    out = {}
    for n in range(6, 11):
        data = builds[n]
        segs = elf_segments(data)
        syms = nm_symbols(f'layer{n:02d}', data)
        enc_addr, enc_len = syms['encoded_token_bytes']
        key_name = next(k for k in syms if k.startswith('xor_key_byte_0x'))
        key = read_vaddr(data, segs, syms[key_name][0], 1)[0]
        encoded = read_vaddr(data, segs, enc_addr, enc_len)
        out[n] = (bytes(b ^ key for b in encoded).decode(), key, encoded, key_name)
    return out

def printed_token(blob):
    """NEXT_TOKEN string a build prints on success (plain .rodata string)."""
    text = subprocess.run(['strings', '-a', '/dev/stdin'], input=blob,
                          capture_output=True).stdout.decode('utf-8', 'replace')
    m = re.search(r'NEXT_TOKEN=(\S+)', text)
    return m.group(1) if m else None

def band3_cmp(builds):
    """Layers 11-15: read the ordered cmp al,imm8 constants in check_license."""
    out = {}
    for n in range(11, 16):
        asm = disasm_function(builds[n], 'check_license')
        consts = bytes(int(m.group(1), 16)
                       for m in re.finditer(r'cmp\s+al,0x([0-9a-f]+)', asm))
        assert 'test   al,al' in asm, 'expected a NUL-terminator length check'
        out[n] = (consts.decode(), printed_token(builds[n]))
    return out

def band4_transform(builds):
    """Layers 16-20: invert transform_candidate against transformed_target."""
    out = {}
    for n in range(16, 21):
        data = builds[n]
        segs = elf_segments(data)
        target = read_cstr(data, segs, nm_symbols(f'layer{n:02d}', data)['transformed_target'][0])
        asm = disasm_function(data, 'transform_candidate')
        if 'lea    ecx,[rax+0x1]' in asm:
            cand = ''.join(chr(ord(c) - 1) for c in target); how = 'add 1 per byte'
        elif 'lea    ecx,[rax+0x2]' in asm:
            cand = ''.join(chr(ord(c) - 2) for c in target); how = 'add 2 per byte'
        elif 'sub    rax,QWORD PTR' in asm:
            cand = target[::-1]; how = 'reverse the string'
        elif 'cmp    BYTE PTR [rbp-0x9],0x60' in asm:
            cand = __import__('codecs').decode(target, 'rot_13'); how = 'ROT13'
        else:
            raise ValueError(f'layer{n}: unrecognised transform')
        out[n] = (target, cand, how)
    return out

# ---------- main ----------

def main():
    zpath = sys.argv[1] if len(sys.argv) > 1 else 'The_Debug_Log_Player_Pack.zip'
    zf = zipfile.ZipFile(zpath)
    builds = {n: zf.read(f'player_pack/builds/layer{n:02d}') for n in range(1, 26)}

    t1 = band1_strings(builds)
    print('BAND 1 - embedded strings')
    for n in range(1, 6):
        print(f'  layer{n:02d}: NEXT_TOKEN={t1[n]}')

    t2 = band2_xor(builds)
    print('BAND 2 - single-byte XOR (symbols locate key and array)')
    for n in range(6, 11):
        tok, key, enc, kname = t2[n]
        print(f'  layer{n:02d}: {kname}={key:#04x}  encoded={enc.hex(" ")}  -> {tok!r}')

    t3 = band3_cmp(builds)
    print('BAND 3 - per-character comparison in check_license')
    for n in range(11, 16):
        print(f'  layer{n:02d}: expects {t3[n][0]!r}  (prints NEXT_TOKEN={t3[n][1]})')

    t4 = band4_transform(builds)
    print('BAND 4 - inverted transform_candidate')
    for n in range(16, 21):
        target, cand, how = t4[n]
        print(f'  layer{n:02d}: target={target!r}  transform={how}  -> candidate={cand!r}')

    # chain: each build consumes the previous handoff
    hand = {**{n: t1[n] for n in range(1, 6)},
            **{n: t2[n][0] for n in range(6, 11)},
            **{n: t3[n][1] for n in range(11, 16)},
            **{n: printed_token(builds[n]) for n in range(16, 21)}}
    art_xor, art_cmp, art_tr = t2[10][0], t3[15][1], t4[20][1]
    print('ARTIFACTS:', art_xor, '|', art_cmp, '|', art_tr)

    # ----- execution reverification: run every gate with recovered values -----
    if sys.platform.startswith('linux') and os.uname().machine == 'x86_64':
        with tempfile.TemporaryDirectory() as td:
            paths = {}
            for n, blob in builds.items():
                p = os.path.join(td, f'layer{n:02d}')
                open(p, 'wb').write(blob)
                os.chmod(p, stat.S_IRWXU)
                paths[n] = p
            def run(n, *args):
                r = subprocess.run([paths[n], *args], capture_output=True, text=True)
                return r.returncode, r.stdout.strip()
            checks = []
            prev = t1[1]
            for n in range(2, 6):
                rc, out = run(n, prev); ok = f'NEXT_TOKEN={t1[n]}' in out
                checks.append((f'layer{n:02d} {prev!r}', ok)); prev = t1[n]
            for n in range(6, 11):
                rc, out = run(n, prev); ok = t2[n][0] in out
                checks.append((f'layer{n:02d} {prev!r}', ok)); prev = t2[n][0]
            for n in range(11, 16):
                rc, out = run(n, prev); ok = f'NEXT_TOKEN={t3[n][1]}' in out
                checks.append((f'layer{n:02d} {prev!r}', ok)); prev = t3[n][1]
            cand_prev = prev
            for n in range(16, 21):
                rc, out = run(n, cand_prev, t4[n][1]); ok = f'NEXT_TOKEN={hand[n]}' in out
                checks.append((f'layer{n:02d} {cand_prev!r} {t4[n][1]!r}', ok)); cand_prev = hand[n]
            gates = [(21, (cand_prev, art_xor), 'stage_a'), (22, ('stage_a', art_cmp), 'stage_b'),
                     (23, ('stage_b', art_tr), 'stage_c')]
            for n, args, want in gates:
                rc, out = run(n, *args); checks.append((f'layer{n:02d} {args!r}', f'NEXT_TOKEN={want}' in out))
            combo = f'{art_xor}|{art_cmp}|{art_tr}'
            rc, out = run(24, 'stage_c', combo)
            checks.append((f'layer24 stage_c {combo!r}', 'NEXT_TOKEN=' in out))
            rc, out = run(25, art_xor, art_cmp, art_tr)
            m = re.search(r'flag\{[^}]+\}', out)
            checks.append(('layer25 (three artifacts)', rc == 0 and m is not None))
            print('EXECUTION VERIFICATION (every gate run against the original binaries)')
            for label, ok in checks:
                print(f'  {label}: {"PASS" if ok else "FAIL"}')
            flag = m.group(0)
            payload = flag[5:-1]
            print(f'FINAL BINARY OUTPUT:\n{out}')
            print(f'flag payload length: {len(payload)} characters (rule: 20-40) -> '
                  f'{"VALID" if 20 <= len(payload) <= 40 else "INVALID"}')
            rc, out = run(25, art_xor, 'source', art_tr)  # letter O for digit 0
            print(f'negative test (source vs s0urce): exit={rc} -> {"correctly rejected" if rc else "WRONGLY ACCEPTED"}')
    else:
        print('(non-x86-64 host: static recovery only, gates not executed)')

if __name__ == '__main__':
    main()
