#!/usr/bin/env python3
"""Runtime Echo chain walker: static deobf-variant decode + genuine execution verify."""
import subprocess, re, json, hashlib, os, sys

ORIG = os.path.abspath('original')
SITES = json.load(open('work/pulse_stage_sites.json'))

def ror8(x, r):
    r &= 7
    return ((x >> r) | (x << ((-r) & 7))) & 0xff

def rev8(x):
    x = ((x >> 4) | (x << 4)) & 0xff
    x = (((x >> 2) & 0x33) | ((x << 2) & 0xcc)) & 0xff
    x = (((x >> 1) & 0x55) | ((x << 1) & 0xaa)) & 0xff
    return x

def decode(sig, blob, ln, k):
    k &= 0xff
    out = bytearray(ln)
    for i in range(ln):
        b = blob[i]
        if sig == 'f7cde243':        out[i] = b ^ ((13*i + k) & 0xff)
        elif sig == 'a6ae99b3':      out[i] = (b - (7*i + k)) & 0xff
        elif sig == '7e32be5e':      out[i] = ror8(b ^ ((11*i + k) & 0xff), ((k + i) % 7) + 1)
        elif sig == 'a932fddb':      out[ln-1-i] = b ^ ((5*i + k) & 0xff)
        elif sig == '80e8c45a':
            prev = k if i == 0 else out[i-1]
            out[i] = (b ^ prev ^ (3*i)) & 0xff
        elif sig == '291258b2':      out[i] = (ror8(b, 4) - (9*i + k)) & 0xff
        elif sig == 'd93eee87':      out[i] = (((b - (17*i + k)) & 0xff) * 0xcd) & 0xff
        elif sig == 'e7be4d9a':      out[ln-1-i] = rev8(((k + 19*i) ^ b) & 0xff)
        elif sig == '763d4228':
            prev = k if i == 0 else out[i-1]
            out[i] = (b - (k + prev + 3*i)) & 0xff
        elif sig == '0c7b70ca':      out[i] = ((b - 3*i*i - 0x11) ^ k) & 0xff
        else: raise ValueError(sig)
    return bytes(out)

_rodata_cache = {}
def rodata(f):
    if f in _rodata_cache: return _rodata_cache[f]
    txt = subprocess.run(['objdump','-s','-j','.rodata',f],capture_output=True,text=True).stdout
    m = {}
    for l in txt.splitlines():
        mm = re.match(r'\s+([0-9a-f]+)\s+([0-9a-f ]{8,35}?)\s\s', l)
        if mm:
            addr = int(mm.group(1), 16)
            hexs = mm.group(2).replace(' ', '')
            for j in range(0, len(hexs), 2):
                m[addr + j//2] = int(hexs[j:j+2], 16)
    _rodata_cache[f] = m
    return m

def stage_sites(n):
    cands = [s for s in SITES[str(n)] if 6 <= s['ln'] <= 24]
    cands.sort(key=lambda s: int(s['blob'], 16))
    return cands

def solve_stage(n):
    f = os.path.join(ORIG, 'bin', 'pulse%02d' % n)
    rd = rodata(f)
    cands = stage_sites(n)
    if not cands: raise RuntimeError('no sites for stage %d' % n)
    seen = set(); uniq = []
    for s in cands:
        if s['blob'] in seen: continue
        seen.add(s['blob']); uniq.append(s)
    res = []
    for s in uniq[:2]:
        blobaddr = int(s['blob'], 16)
        blob = bytes(rd[blobaddr + j] for j in range(s['ln']))
        res.append((s, decode(s['sig'], blob, s['ln'], s['key'])))
    return res  # [(site, answer)], second entry is the decoy decode

def run_stage(n, prev, answer, mem_table=None):
    f = os.path.join(ORIG, 'bin', 'pulse%02d' % n)
    env = dict(os.environ)
    if mem_table: env['PULSE_MEMORY_TABLE'] = mem_table
    p = subprocess.run([f, prev, answer], capture_output=True, text=True, cwd=ORIG, env=env, timeout=20)
    return p.stdout + p.stderr

if __name__ == '__main__':
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    os.makedirs('logs', exist_ok=True)
    state_file = 'work/chain_state.json'
    state = json.load(open(state_file)) if os.path.exists(state_file) else {}
    prev = state.get('prev', 'GENESIS')
    mem7 = state.get('mem7')
    for n in range(lo, hi + 1):
        if n < lo: continue
        s_and_a = solve_stage(n)
        site, ans = s_and_a[0]
        ans_s = ans.decode('latin1')
        out = run_stage(n, prev, ans_s, mem7 if 26 <= n <= 30 else None)
        ok = 'UNLOCKED:' in out
        if not ok and len(s_and_a) > 1:
            site, ans = s_and_a[1]
            ans_s = ans.decode('latin1')
            out = run_stage(n, prev, ans_s, mem7 if 26 <= n <= 30 else None)
            ok = 'UNLOCKED:' in out
        log = ['stage %d' % n, 'variant %s key=%#x blob=%s len=%d' % (site['sig'], site['key'], site['blob'], site['ln']),
               'prev: %s' % prev, 'answer: %s' % ans_s, '', '$ ./bin/pulse%02d %s %s' % (n, prev, ans_s), out]
        open('logs/stage%02d.log' % n, 'w').write('\n'.join(log))
        if not ok:
            print('STAGE %d FAILED' % n); print(out); sys.exit(1)
        tok = re.search(r'UNLOCKED:\s*(\S+)', out).group(1)
        if n in (10, 20, 30, 40):
            want = dict((int(l.split()[0]), l.split()[1]) for l in open(os.path.join(ORIG,'checkpoints.sha256')) if l.strip())[n]
            got = hashlib.sha256(tok.encode()).hexdigest()
            print('stage %d checkpoint sha256: %s' % (n, 'MATCH' if got == want else 'MISMATCH got=' + got))
        if n == 7: mem7 = tok
        print('stage %02d OK answer=%s token=%s' % (n, ans_s, tok))
        prev = tok
        state = {'prev': prev, 'mem7': mem7, 'last': n}
        json.dump(state, open(state_file, 'w'))
    print('chain complete through stage', hi)
