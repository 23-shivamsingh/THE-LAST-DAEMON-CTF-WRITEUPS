#!/usr/bin/env python3
"""Binary Labyrinth independent solver - extraction via extract2, transforms reversed from objdump."""
import sys, os, json, hashlib, subprocess, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract2 import extract

BASE = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()  # directory containing layer01..layer50
HEX = '0123456789abcdef'
ALPHA = 'abcdefghijklmnopqrstuvwxyz0123456789'
AL = set(ALPHA.encode())
sha = lambda b: hashlib.sha256(b.encode() if isinstance(b, str) else b).hexdigest()
rol = lambda b, n: n == 0 and b or (((b << n) | (b >> (8 - n))) & 0xff)
ror = lambda b, n: n == 0 and b or (((b >> n) | (b << (8 - n))) & 0xff)

_cache = {}
def C(n):
    if n not in _cache:
        _cache[n] = extract(os.path.join(BASE, 'layer%02d' % n))
    return _cache[n]

def maskbyte(prev, i, stage, msalt):
    return (ord(prev[(stage + i) % len(prev)]) + msalt[i % 16] + 11 * i + 7 * stage) & 0xff

def rhs(prev, stage, msalt, target, tlen):
    return bytes(target[i] ^ maskbyte(prev, i, stage, msalt) for i in range(tlen))


DELTA = 0x9e3779b9
M32 = 0xffffffff

def tea_dec(block, k):
    v0, v1 = struct.unpack('<2I', block)
    s = (DELTA * 32) & M32
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + k[2]) & M32 ^ ((v0 >> 5) + k[3]) & M32 ^ (v0 + s) & M32))) & M32
        v0 = (v0 - ((((v1 << 4) + k[0]) & M32 ^ ((v1 >> 5) + k[1]) & M32 ^ (v1 + s) & M32))) & M32
        s = (s - DELTA) & M32
    return struct.pack('<2I', v0, v1)

def xtea_dec(block, k):
    v0, v1 = struct.unpack('<2I', block)
    s = (DELTA * 32) & M32
    for _ in range(32):
        v1 = (v1 - (((((v0 << 4) ^ (v0 >> 5)) + v0) & M32 ^ (s + k[(s >> 11) & 3]) & M32))) & M32
        s = (s - DELTA) & M32
        v0 = (v0 - (((((v1 << 4) ^ (v1 >> 5)) + v1) & M32 ^ (s + k[s & 3]) & M32))) & M32
    return struct.pack('<2I', v0, v1)

def feistel_dec(block, k):
    L, R = struct.unpack('<2I', block)
    for r in range(4, 0, -1):
        prevR = L
        L = (R ^ (((k[r - 1] ^ prevR) * 0x45d9f3b & M32) + ((prevR << r) & M32) & M32)) & M32
        R = prevR
    return struct.pack('<2I', L, R)

def rc4(key, n):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % 16]) & 0xff
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = []
    for _ in range(n):
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xff])
    return bytes(out)

def b64dec_custom(s16, alpha):
    rev = {alpha[i]: i for i in range(64)}
    out = bytearray()
    for g in range(0, 16, 4):
        q = [rev[c] for c in s16[g:g + 4]]
        w = (q[0] << 18) | (q[1] << 12) | (q[2] << 6) | q[3]
        out += bytes([(w >> 16) & 255, (w >> 8) & 255, w & 255])
    return bytes(out)

def inv_mode(mode, r, salt, D):
    """Invert transform: given r (target^mask), recover pw bytes."""
    tlen = len(r)
    if mode == 1: return r
    if mode == 2: return r[::-1]
    if mode == 3: return bytes((r[i] - salt[i % 16]) & 0xff for i in range(tlen))
    if mode == 4: return bytes(r[i] ^ salt[i % 16] for i in range(tlen))
    if mode == 5: return bytes(ror(r[i], 4) for i in range(tlen))
    if mode == 6: return bytes(ror(r[i], salt[i % 16] & 7) for i in range(tlen))
    if mode == 7:
        out = []
        for i in range(tlen):
            prevp = out[i - 1] if i else 0
            out.append(r[i] ^ salt[i % 16] ^ prevp)
        return bytes(out)
    if mode == 8:
        out = []; t = salt[0]
        for i in range(tlen):
            b = (r[i] - salt[i % 16] - t) & 0xff
            out.append(b); t = b ^ salt[i % 16]
        return bytes(out)
    if mode == 9:
        P = [0, 5, 10, 3, 8, 1, 6, 11, 4, 9, 2, 7]
        out = bytearray(12)
        for i in range(12): out[i] = r[P[i]]  # out[i]=T[p[i]] guess; verify by exec
        return bytes(out)
    if mode == 10:
        return bytes((r[i] - salt[i % 16]) & 0xff if i % 2 == 0 else (r[i] + salt[i % 16]) & 0xff for i in range(tlen))
    if mode == 11:
        return bytes(ord(ALPHA[(ALPHA.index(chr(r[i])) - salt[i % 16] % 36) % 36]) for i in range(tlen))
    if mode == 15:
        return bytes(ord(ALPHA[(29 * (ALPHA.index(chr(r[i])) - salt[i % 16] % 36)) % 36]) for i in range(tlen))
    if mode == 12: return bytes(r[i] ^ salt[i % 16] ^ 0xa5 for i in range(tlen))
    if mode == 13:
        tab = D.get('hex_table') or b'0123456789abcdef'
        rev = {tab[i]: i for i in range(16)}
        return bytes((((rev[r[2 * i]] << 4) | rev[r[2 * i + 1]]) ^ salt[i % 16]) & 0xff for i in range(tlen // 2))
    if mode == 14: return bytes(ror(r[i] ^ salt[i % 16], 3) for i in range(tlen))
    if mode == 16:
        return bytes(ord(ALPHA[(ALPHA.index(chr(r[i])) - (salt[i % 16] + i) % 36) % 36]) for i in range(tlen))
    if mode == 17: return bytes(((r[i] - i * i - 7) & 0xff) ^ salt[i % 16] for i in range(tlen))
    if mode == 18:
        out = []; t = salt[0]
        for i in range(tlen):
            b = (r[i] - t - salt[i % 16]) & 0xff
            out.append(b); t = (33 * t + b) & 0xff
        return bytes(out)
    if mode == 19:
        out = []
        for i in range(tlen):
            k = i % 3
            if k == 0: out.append(r[i] ^ salt[i % 16])
            elif k == 1: out.append((r[i] - salt[i % 16]) & 0xff)
            else: out.append(ror(r[i], salt[i % 16] & 7))
        return bytes(out)
    if mode == 20:
        return bytes(ror(r[i], salt[(i + 1) & 0xf] & 7) ^ salt[i % 16] for i in range(tlen))
    if mode == 26:
        out = []
        for i in range(tlen):
            m = salt[i % 16] | 1
            inv = pow(m, -1, 256)
            out.append(((r[i] - salt[(i + 3) & 0xf]) & 0xff) * inv & 0xff)
        return bytes(out)
    if mode == 35:
        return bytes(r[i] ^ salt[i] for i in range(12))
    if mode == 41:
        k = struct.unpack('<4I', salt)
        return tea_dec(r[0:8], k) + tea_dec(r[8:16], k)
    if mode == 42:
        k = struct.unpack('<4I', salt)
        return xtea_dec(r[0:8], k) + xtea_dec(r[8:16], k)
    if mode == 43:
        ks = rc4(salt, tlen)
        return bytes(r[i] ^ ks[i] for i in range(tlen))
    if mode == 44:
        k = struct.unpack('<4I', salt)
        return feistel_dec(r[0:8], k) + feistel_dec(r[8:16], k)
    if mode == 45:
        return b64dec_custom(r[:16], D['b64alpha'].encode() if isinstance(D['b64alpha'], str) else D['b64alpha'])
    raise ValueError('mode %d not implemented' % mode)

def token(stage, pw):
    return sha(pw.decode() + ':%02d' % stage)[:16]

def solve_known_prev(n, prev):
    D = C(n)
    if D.get('mode_id') == 13 and 'hex_table' not in D:
        D['hex_table'] = open(os.path.join(BASE, 'layer%02d' % n), 'rb').read()[0x4770:0x4780]
    r = rhs(prev, D['stage_id'], D['msalt'], D['target_ct'], D['target_len'])
    return inv_mode(D['mode_id'], r, D['salt'], D)

if __name__ == '__main__':
    prev = C(1)['base_token']
    print('base:', prev)
    solved = {}
    for n in range(1, 21):
        D = C(n)
        pw = solve_known_prev(n, prev)
        ok = all(b in AL for b in pw)
        solved[n] = pw
        print('stage %2d mode %2d pw=%s %s' % (n, D['mode_id'], pw.decode('latin1'), 'charset-ok' if ok else 'CHARSET-FAIL'))
        prev = token(n, pw)
    json.dump({str(k): v.decode('latin1') for k, v in solved.items()}, open('passwords_recovered.json', 'w'))
    print('token20:', prev)
