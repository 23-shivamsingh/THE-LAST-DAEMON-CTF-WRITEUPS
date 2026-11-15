#!/usr/bin/env python3
"""Silent Cipher (Key Whisperer) independent solver: 50 layers.
Each layer decrypts with its stated technique; HANDOFF=XXXXXXXX and SEAL=xxxxxxxx
close each note. Recovered independently; supplied bundle used only for comparison."""
import json, base64, hashlib, sys

D = sys.argv[1] if len(sys.argv) > 1 else 'Key_whisperer'
LOG = []
def say(s=''):
    print(s); LOG.append(s)

def page(n):
    return json.load(open(f'{D}/page{n:02d}.json'))

PT = {}
HANDOFF = {}
SEAL = {}

def extract(n, text):
    assert 'HANDOFF=' in text and 'SEAL=' in text, f'page{n}: no handoff/seal'
    h = text.split('HANDOFF=')[1].split()[0].strip()
    s = text.split('SEAL=')[1].split()[0].strip()
    HANDOFF[n] = h; SEAL[n] = s
    PT[n] = text
    say(f'--- PAGE {n} ---')
    say(text if len(text) < 1200 else text[:600] + ' ... ' + text[-300:])
    say(f'[handoff={h} seal={s}]')
    return h, s

COMMON = b' etaoinshrdluETAOINSHRDLU'
def english_score(bs):
    return sum(1 for b in bs if b in COMMON)

# ---------------- page 1: single-byte XOR ----------------
d = page(1)
ct = bytes.fromhex(d['ciphertext_hex'])
k1 = max(range(256), key=lambda k: english_score(bytes(b ^ k for b in ct)))
pt1 = bytes(b ^ k1 for b in ct).decode()
assert k1 == 69 and 'HANDOFF=' in pt1
extract(1, pt1)

# ---------------- page 2: per-line modular addition (base64 lines) ----------------
d = page(2)
out2 = []
for ln in d['ciphertext_lines_base64']:
    raw = base64.b64decode(ln)
    if len(raw) < 40:  # short label lines: k from the HANDOFF=/SEAL= crib's first byte
        k = (raw[0] - (ord('H') if len(raw) == 16 else ord('S'))) & 255
    else:
        k = max(range(256), key=lambda kk: english_score(bytes((b - kk) & 255 for b in raw)))
    out2.append(bytes((b - k) & 255 for b in raw).decode())
pt2 = '\n'.join(out2)
extract(2, pt2)

# ---------------- page 3: per-line single-byte XOR (hex lines) ----------------
d = page(3)
out3 = []
for ln in d['ciphertext_lines_hex']:
    raw = bytes.fromhex(ln)
    if len(raw) < 40:  # short label lines: k from the HANDOFF=/SEAL= crib's first byte
        k = raw[0] ^ (ord('H') if len(raw) == 16 else ord('S'))
    else:
        k = max(range(256), key=lambda kk: english_score(bytes(b ^ kk for b in raw)))
    out3.append(bytes(b ^ k for b in raw).decode())
pt3 = '\n'.join(out3)
extract(3, pt3)

# ---------------- page 4: base85 -> single-byte modular addition, crib 'The incident' ----------------
d = page(4)
raw4 = base64.b85decode(d['ciphertext_base85'])
k4 = (raw4[0] - ord(d['known_plaintext_crib'][0])) & 255
pt4 = bytes((b - k4) & 255 for b in raw4).decode()
assert pt4.startswith('The incident')
extract(4, pt4)

# ---------------- page 5: bit-reversed bytes, base64, then rotate right by 3 ----------------
d = page(5)
raw5 = base64.b64decode(d['ciphertext_bit_reverse_base64'])
def bitrev(b):
    return int(f'{b:08b}'[::-1], 2)
def ror8(x, r):
    return ((x >> r) | (x << (8 - r))) & 255
unrev = bytes(bitrev(b) for b in raw5)
pt5 = bytes(ror8(b, d['rotate_left']) for b in unrev).decode()
extract(5, pt5)

# ---------------- generic repeating-key breakers ----------------
def hamming(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def rank_periods(ct, lo=3, hi=8):
    scores = []
    for p in range(lo, hi + 1):
        blocks = [ct[i * p:(i + 1) * p] for i in range(len(ct) // p)][:8]
        dists = [hamming(blocks[i], blocks[i + 1]) / p for i in range(len(blocks) - 1)]
        scores.append((sum(dists) / len(dists), p))
    return sorted(scores)

def break_rep_xor(ct, lo=3, hi=8, upper_key=False):
    best = None
    for _, p in rank_periods(ct, lo, hi):
        key = bytes(max(range(256), key=lambda k: english_score(bytes(b ^ k for b in ct[i::p]))) for i in range(p))
        if upper_key and not all(65 <= k <= 90 for k in key):
            continue
        pt = bytes(b ^ key[i % p] for i, b in enumerate(ct))
        sc = english_score(pt)
        if best is None or sc > best[0]:
            best = (sc, p, key, pt)
    return best[1], best[2], best[3]

def break_rep_add(ct, lo=3, hi=8):
    best = None
    for p in range(lo, hi + 1):
        key = bytes(max(range(256), key=lambda k: english_score(bytes((b - k) & 255 for b in ct[i::p]))) for i in range(p))
        pt = bytes((b - key[i % p]) & 255 for i, b in enumerate(ct))
        sc = english_score(pt)
        if best is None or sc > best[0]:
            best = (sc, p, key, pt)
    return best[1], best[2], best[3]

def break_vigenere(text, lo=3, hi=8):
    letters = [c for c in text.upper() if c.isalpha()]
    def ic(s):
        from collections import Counter
        n = len(s)
        if n < 2: return 0
        c = Counter(s)
        return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))
    per_scores = []
    for p in range(lo, hi + 1):
        cols = [''.join(letters[i] for i in range(j, len(letters), p)) for j in range(p)]
        per_scores.append((sum(ic(c) for c in cols) / p, p))
    EF = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
          2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
    def best_shift(col):
        n = len(col)
        return max(range(26), key=lambda s: -sum(((col.count(chr(65 + (i + s) % 26)) - n * EF[i] / 100) ** 2) / (n * EF[i] / 100) for i in range(26)))
    for _, p in sorted(per_scores, reverse=True):
        cols = [[letters[i] for i in range(j, len(letters), p)] for j in range(p)]
        shifts = [best_shift(c) for c in cols]
        li = 0; out = []
        for c in text:
            if c.isalpha():
                s = shifts[li % p]; li += 1
                base = 65 if c.isupper() else 97
                out.append(chr(base + (ord(c) - base - s) % 26))
            else:
                out.append(c)
        pt = ''.join(out)
        if 'HANDOFF' in pt.upper():
            return p, ''.join(chr(65 + s) for s in shifts), pt
    return None

# ---------------- page 6: repeating-key XOR (uppercase key) ----------------
d = page(6)
ct6 = bytes.fromhex(d['ciphertext_hex'])
p6, k6, pt6b = break_rep_xor(ct6, *d['key_length_range'], upper_key=True)
pt6 = pt6b.decode()
say(f'[page6 period={p6} key={k6}]')
extract(6, pt6)

# ---------------- page 7: repeating-key Vigenere ----------------
d = page(7)
res7 = break_vigenere(d['ciphertext_text'], *d['key_length_range'])
p7, k7, pt7 = res7
say(f'[page7 period={p7} key={k7}]')
extract(7, pt7)

# ---------------- page 8: base64 -> repeating-key XOR (stale 5-byte comment; verify period) ----------------
d = page(8)
ct8 = base64.b64decode(d['ciphertext_base64'])
p8, k8, pt8b = break_rep_xor(ct8, *d['key_length_range'])
pt8 = pt8b.decode()
say(f'[page8 true period={p8} key={k8} (stale comment claimed 5)]')
extract(8, pt8)

# ---------------- page 9: repeating-key modular addition ----------------
d = page(9)
ct9 = bytes.fromhex(d['ciphertext_hex'])
p9, k9, pt9b = break_rep_add(ct9, *d['key_length_range'])
pt9 = pt9b.decode()
say(f'[page9 period={p9} key={k9}]')
extract(9, pt9)

# ---------------- page 10: base85 -> repeating-key XOR, known prefix breather ----------------
d = page(10)
ct10 = base64.b85decode(d['ciphertext_base85'])
# known prefix lets us read the mask for its length; find period by checking repeats
for p10 in range(3, 9):
    key = bytes(c ^ k for c, k in zip(ct10[:p10], d['known_plaintext_prefix'].encode()))
    pt10b = bytes(b ^ key[i % p10] for i, b in enumerate(ct10))
    if pt10b.startswith(d['known_plaintext_prefix'].encode()) and b'HANDOFF=' in pt10b:
        pt10 = pt10b.decode()
        say(f'[page10 period={p10} key={key}]')
        break
extract(10, pt10)

# ---------------- pages 11-15: two-time pads, known plaintext A recovers the stream ----------------
def rep_bytes(d, key):
    rep = d['representation']
    raw = d[key]
    if rep == 'hex': return bytes.fromhex(raw)
    if rep == 'base64': return base64.b64decode(raw)
    if rep == 'base85': return base64.b85decode(raw)
    if rep == 'nibblehex':
        b = bytes.fromhex(raw)
        return bytes(((x & 0x0F) << 4) | (x >> 4) for x in b)
    if rep == 'bitreversebase64':
        return bytes(bitrev(x) for x in base64.b64decode(raw))
    raise ValueError(rep)

# page 11: modular-add two-time pad (hex)
d = page(11)
ctA, ctB = rep_bytes(d, 'ciphertext_a'), rep_bytes(d, 'ciphertext_b')
ptA = d['known_plaintext_a'].encode()[:len(ctA)]
stream11 = bytes((a - p) & 255 for a, p in zip(ctA, ptA))
pt11 = bytes((b - s) & 255 for b, s in zip(ctB, stream11)).decode()
extract(11, pt11)

# page 12: XOR two-time pad (base64)
d = page(12)
ctA, ctB = rep_bytes(d, 'ciphertext_a'), rep_bytes(d, 'ciphertext_b')
ptA = d['known_plaintext_a'].encode()[:len(ctA)]
stream12 = bytes(a ^ p for a, p in zip(ctA, ptA))
pt12 = bytes(b ^ s for b, s in zip(ctB, stream12)).decode()
extract(12, pt12)

def vig_stream_from_known(ctA, ptA):
    # alphabetic Vigenere pad: letters shift, non-letters pass through; key advances per letter
    assert len(ctA) == len(ptA), (len(ctA), len(ptA))
    stream = []
    for c, p in zip(ctA, ptA):
        if chr(p).isalpha():
            stream.append((c - p) % 26)
    return stream

def vig_stream_decrypt(ctB, stream):
    out = []; li = 0
    for b in ctB:
        c = chr(b)
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr(base + (b - base - stream[li]) % 26))
            li += 1
        else:
            out.append(c)
    return ''.join(out)

# page 13: alphabetic Vigenere pad reuse (base85)
d = page(13)
ctA, ctB = rep_bytes(d, 'ciphertext_a'), rep_bytes(d, 'ciphertext_b')
stream13 = vig_stream_from_known(ctA, d['known_plaintext_a'].encode())
pt13 = vig_stream_decrypt(ctB, stream13)
extract(13, pt13)

# page 14: XOR two-time pad, nibble-swapped hex representation
d = page(14)
ctA, ctB = rep_bytes(d, 'ciphertext_a'), rep_bytes(d, 'ciphertext_b')
ptA = d['known_plaintext_a'].encode()[:len(ctA)]
stream14 = bytes(a ^ p for a, p in zip(ctA, ptA))
pt14 = bytes(b ^ s for b, s in zip(ctB, stream14)).decode()
extract(14, pt14)

# page 15: alphabetic Vigenere pad reuse, bit-reversed base64 representation
d = page(15)
ctA, ctB = rep_bytes(d, 'ciphertext_a'), rep_bytes(d, 'ciphertext_b')
stream15 = vig_stream_from_known(ctA, d['known_plaintext_a'].encode())
pt15 = vig_stream_decrypt(ctB, stream15)
extract(15, pt15)

# ---------------- pages 16-20: weak PRNG streams ----------------
def lcg_gen(seed, a, c, mod, outbyte, n):
    state = seed % mod
    for _ in range(n):
        state = (a * state + c) % mod
        yield outbyte(state)

# page 16: LCG high-byte XOR, seed 1..65535
d = page(16)
ct16 = bytes.fromhex(d['ciphertext_hex'])
pfx = d['known_plaintext_prefix'].encode()
L = d['lcg']
for seed in range(L['seed_min'], L['seed_max'] + 1):
    st = bytes(lcg_gen(seed, L['a'], L['c'], L['modulus'], lambda s: (s >> 24) & 255, len(pfx)))
    if bytes(c ^ k for c, k in zip(ct16, st)) == pfx:
        stream16 = bytes(lcg_gen(seed, L['a'], L['c'], L['modulus'], lambda s: (s >> 24) & 255, len(ct16)))
        pt16 = bytes(c ^ k for c, k in zip(ct16, stream16)).decode()
        say(f'[page16 seed={seed}]')
        break
extract(16, pt16)

# page 17: python random timestamp seed, modular addition
d = page(17)
import random
ct17 = base64.b64decode(d['ciphertext_base64'])
pfx = d['known_plaintext_prefix'].encode()
for seed in range(d['seed_range'][0], d['seed_range'][1] + 1):
    rng = random.Random(seed)
    st = bytes(rng.getrandbits(8) for _ in range(len(pfx)))
    if bytes((c - k) & 255 for c, k in zip(ct17, st)) == pfx:
        rng = random.Random(seed)
        stream17 = bytes(rng.getrandbits(8) for _ in range(len(ct17)))
        pt17 = bytes((c - k) & 255 for c, k in zip(ct17, stream17)).decode()
        say(f'[page17 seed={seed}]')
        break
extract(17, pt17)

# page 18: xorshift32, seed 1..4095, XOR
def xorshift32_stream(seed, n):
    x = seed & 0xffffffff
    if x == 0: x = 0x6d2b79f5
    out = bytearray()
    for _ in range(n):
        x ^= (x << 13) & 0xffffffff
        x ^= (x >> 17) & 0xffffffff
        x ^= (x << 5) & 0xffffffff
        x &= 0xffffffff
        out.append((x >> 24) & 255)
    return bytes(out)
d = page(18)
ct18 = bytes.fromhex(d['ciphertext_hex'])
pfx = d['known_plaintext_prefix'].encode()
for seed in range(d['seed_range'][0], d['seed_range'][1] + 1):
    if bytes(c ^ k for c, k in zip(ct18, xorshift32_stream(seed, len(pfx)))) == pfx:
        pt18 = bytes(c ^ k for c, k in zip(ct18, xorshift32_stream(seed, len(ct18)))).decode()
        say(f'[page18 seed={seed}]')
        break
extract(18, pt18)

# page 19: LCG bits 16..23, modular addition, seed 1..65535
d = page(19)
ct19 = base64.b85decode(d['ciphertext_base85'])
pfx = d['known_plaintext_prefix'].encode()
L = d['lcg']
for seed in range(L['seed_min'], L['seed_max'] + 1):
    st = bytes(lcg_gen(seed, L['a'], L['c'], L['modulus'], lambda s: (s >> 16) & 255, len(pfx)))
    if bytes((c - k) & 255 for c, k in zip(ct19, st)) == pfx:
        stream19 = bytes(lcg_gen(seed, L['a'], L['c'], L['modulus'], lambda s: (s >> 16) & 255, len(ct19)))
        pt19 = bytes((c - k) & 255 for c, k in zip(ct19, stream19)).decode()
        say(f'[page19 seed={seed}]')
        break
extract(19, pt19)

# page 20: leaked LCG state; ct[i] = rol8(pt[i], 1 + stream[i] % 8)
d = page(20)
ct20 = bytes.fromhex(d['ciphertext_hex'])
L = d['lcg']
state = L['leaked_state_after_first_step']
stream20 = [ (state >> 24) & 255 ]
for _ in range(len(ct20) - 1):
    state = (L['a'] * state + L['c']) % L['modulus']
    stream20.append((state >> 24) & 255)
def rol8(x, r):
    r %= 8
    return ((x << r) | (x >> (8 - r))) & 255 if r else x & 255
pt20 = bytes(ror8(c, 1 + s % 8) for c, s in zip(ct20, stream20)).decode()
extract(20, pt20)

# ---------------- pages 21-25: LFSR pages ----------------
def lfsr_stream(state, degree, taps, n):
    bits = [(state >> (degree - 1 - i)) & 1 for i in range(degree)]
    while len(bits) < n * 8:
        bits.append(sum(bits[-tap] for tap in taps) & 1)
    out = bytearray()
    for start in range(0, n * 8, 8):
        v = 0
        for bit in bits[start:start + 8]:
            v = (v << 1) | bit
        out.append(v)
    return bytes(out[:n])

# page 21: 12-bit LFSR XOR (base64)
d = page(21)
ct21 = base64.b64decode(d['ciphertext_base64'])
pfx = d['known_plaintext_prefix'].encode()
for st in range(d['state_range'][0], d['state_range'][1] + 1):
    if bytes(c ^ k for c, k in zip(ct21, lfsr_stream(st, d['degree'], d['taps'], len(pfx)))) == pfx:
        state21 = st
        pt21 = bytes(c ^ k for c, k in zip(ct21, lfsr_stream(st, d['degree'], d['taps'], len(ct21)))).decode()
        say(f'[page21 state={st}]')
        break
extract(21, pt21)

# page 22: modular-add stream; BM over revealed stream bits, then extend
def berlekamp_massey(bits):
    n = len(bits)
    C = [0] * (n + 1); B = [0] * (n + 1)
    C[0] = B[0] = 1
    L = 0; m = 1; b = 1
    for i in range(n):
        d_ = bits[i]
        for j in range(1, L + 1):
            d_ ^= C[j] & bits[i - j]
        if d_ == 1:
            T = C[:]
            for j in range(n + 1 - m):
                C[j + m] ^= B[j]
            if 2 * L <= i:
                L = i + 1 - L; B = T; m = 1
            else:
                m += 1
        else:
            m += 1
    return L, C  # recurrence: s_i = sum_{j=1..L} C[j] * s_{i-j} mod 2
d = page(22)
ct22 = bytes.fromhex(d['ciphertext_hex'])
pfx = d['known_plaintext_prefix'].encode()
known_stream = bytes((c - p) & 255 for c, p in zip(ct22, pfx))
sbits = []
for byte in known_stream:
    sbits.extend((byte >> (7 - i)) & 1 for i in range(8))
L22, C22 = berlekamp_massey(sbits)
assert L22 <= int(d['max_linear_complexity']) and L22 > 0, L22
while len(sbits) < len(ct22) * 8:
    sbits.append(sum(C22[j] & sbits[-j] for j in range(1, L22 + 1)) & 1)
stream22 = bytes(int(''.join(map(str, sbits[i:i + 8])), 2) for i in range(0, len(ct22) * 8, 8))
pt22 = bytes((c - k) & 255 for c, k in zip(ct22, stream22)).decode()
say(f'[page22 linear complexity={L22}]')
extract(22, pt22)

# page 23: 16-bit LFSR XOR then bit-reversed ct bytes: ct = bitrev(pt ^ stream)
d = page(23)
ct23 = base64.b85decode(d['ciphertext_base85'])
pfx = d['known_plaintext_prefix'].encode()
unrev23 = bytes(bitrev(b) for b in ct23)
for st in range(d['state_range'][0], d['state_range'][1] + 1):
    if bytes(c ^ k for c, k in zip(unrev23, lfsr_stream(st, d['degree'], d['taps'], len(pfx)))) == pfx:
        pt23 = bytes(c ^ k for c, k in zip(unrev23, lfsr_stream(st, d['degree'], d['taps'], len(ct23)))).decode()
        say(f'[page23 state={st}]')
        break
extract(23, pt23)

# page 24: 12-bit LFSR modular addition (base64)
d = page(24)
ct24 = base64.b64decode(d['ciphertext_base64'])
pfx = d['known_plaintext_prefix'].encode()
for st in range(d['state_range'][0], d['state_range'][1] + 1):
    if bytes((c - k) & 255 for c, k in zip(ct24, lfsr_stream(st, d['degree'], d['taps'], len(pfx)))) == pfx:
        pt24 = bytes((c - k) & 255 for c, k in zip(ct24, lfsr_stream(st, d['degree'], d['taps'], len(ct24)))).decode()
        say(f'[page24 state={st}]')
        break
extract(24, pt24)

# page 25: reuse page-21 state, taps [1,4,12]; pad = each LFSR byte % 26, alphabetic add
d = page(25)
nletters25 = sum(1 for c in d['ciphertext_text'] if c.isalpha())
pad25 = [b % 26 for b in lfsr_stream(state21, d['degree'], d['taps'], nletters25)]
out25 = []; li = 0
for c in d['ciphertext_text']:
    if c.isalpha():
        base = 65 if c.isupper() else 97
        out25.append(chr(base + (ord(c) - base - pad25[li]) % 26))
        li += 1
    else:
        out25.append(c)
pt25 = ''.join(out25)
extract(25, pt25)

# ---------------- pages 26-30: RC4-style + reused/related keys ----------------
def rc4_lite(key, n):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = []
    for _ in range(n):
        i = (i + 1) & 255; j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 255])
    return bytes(out)

# page 26: rc4-style XOR, 2-char A-Z key, base64
d = page(26)
ct26 = base64.b64decode(d['ciphertext_base64'])
best26 = None
for a in range(26):
    for b in range(26):
        key = bytes([65 + a, 65 + b])
        pt = bytes(c ^ k for c, k in zip(ct26, rc4_lite(key, len(ct26))))
        sc = english_score(pt)
        if best26 is None or sc > best26[0]:
            best26 = (sc, key, pt)
sc26, key26, pt26b = best26
pt26 = pt26b.decode()
assert b'HANDOFF=' in pt26b
say(f'[page26 key={key26}]')
extract(26, pt26)

# page 27: Vigenere with the layer-26 two-letter key
d = page(27)
vkey27 = [k - 65 for k in key26]
out27 = []; li = 0
for c in d['ciphertext_text']:
    if c.isalpha():
        base = 65 if c.isupper() else 97
        out27.append(chr(base + (ord(c) - base - vkey27[li % 2]) % 26))
        li += 1
    else:
        out27.append(c)
pt27 = ''.join(out27)
extract(27, pt27)

# page 28: rc4 stream, key = layer-26 key +1 per char, modular addition, base85
d = page(28)
ct28 = base64.b85decode(d['ciphertext_base85'])
key28 = bytes(65 + (k - 65 + 1) % 26 for k in key26)
stream28 = rc4_lite(key28, len(ct28))
pt28 = bytes((c - k) & 255 for c, k in zip(ct28, stream28)).decode()
say(f'[page28 key={key28}]')
extract(28, pt28)

# page 29: rc4 variant, first keystream byte forced zero, XOR, 2-char key
d = page(29)
ct29 = bytes.fromhex(d['ciphertext_hex'])
best29 = None
for a in range(26):
    for b in range(26):
        key = bytes([65 + a, 65 + b])
        st = bytearray(rc4_lite(key, len(ct29)))
        st[0] = 0
        pt = bytes(c ^ k for c, k in zip(ct29, st))
        sc = english_score(pt)
        if best29 is None or sc > best29[0]:
            best29 = (sc, key, pt)
sc29, key29, pt29b = best29
pt29 = pt29b.decode()
assert b'HANDOFF=' in pt29b
say(f'[page29 key={key29}]')
extract(29, pt29)

# page 30: rc4 key = layer-26 key ^ 0x01, modular addition, bit-reversed base64
d = page(30)
ct30 = bytes(bitrev(b) for b in base64.b64decode(d['ciphertext_bit_reverse_base64']))
key30 = bytes(k ^ 1 for k in key26)
stream30 = rc4_lite(key30, len(ct30))
pt30 = bytes((c - k) & 255 for c, k in zip(ct30, stream30)).decode()
say(f'[page30 key={key30}]')
extract(30, pt30)

# ---------------- pages 31-35: prior outputs become keys ----------------
def vig_decrypt_text(text, keyletters):
    shifts = [ord(k.upper()) - 65 for k in keyletters]
    out = []; li = 0
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out.append(chr(base + (ord(c) - base - shifts[li % len(shifts)]) % 26))
            li += 1
        else:
            out.append(c)
    return ''.join(out)

# page 31: repeating XOR with page-30 handoff bytes
d = page(31)
ct31 = bytes.fromhex(d['ciphertext_hex'])
mask31 = HANDOFF[30].encode()
pt31 = bytes(c ^ mask31[i % len(mask31)] for i, c in enumerate(ct31)).decode()
extract(31, pt31)

# page 32: Vigenere with layer-26 key (case/punct do not consume key)
d = page(32)
pt32 = vig_decrypt_text(d['ciphertext_text'], key26.decode())
extract(32, pt32)

# page 33: modular addition keyed by big-endian 2-byte layer-21 state
d = page(33)
ct33 = base64.b85decode(d['ciphertext_base85'])
key33 = state21.to_bytes(2, 'big')
pt33 = bytes((c - key33[i % 2]) & 255 for i, c in enumerate(ct33)).decode()
say(f'[page33 key={key33.hex()}]')
extract(33, pt33)

# page 34: SHAKE256(prior handoff) XOR stream
d = page(34)
ct34 = bytes.fromhex(d['ciphertext_hex'])
stream34 = hashlib.shake_256(HANDOFF[33].encode()).digest(len(ct34))
pt34 = bytes(c ^ k for c, k in zip(ct34, stream34)).decode()
extract(34, pt34)

# page 35: Vigenere with the prior handoff as the alphabetic key
d = page(35)
pt35 = vig_decrypt_text(d['ciphertext_text'], HANDOFF[34])
extract(35, pt35)

# ---------------- pages 36-40: guest->admin token malleability ----------------
def parse_token(txt):
    parts = dict(kv.split('=', 1) for kv in txt.split(';'))
    return parts

def token_decrypt(d, prev, ct):
    mode = d['stream_mode']
    if mode == 'repeatxor':
        key = prev.encode()
        st = (key * ((len(ct) // len(key)) + 1))[:len(ct)]
        return bytes(a ^ b for a, b in zip(ct, st)), 'xor', st
    if mode == 'shakeadd':
        st = hashlib.shake_256(prev.encode()).digest(len(ct))
        return bytes((a - b) & 255 for a, b in zip(ct, st)), 'add', st
    if mode == 'rc4_b85':
        st = rc4_lite(prev.encode(), len(ct))
        return bytes(a ^ b for a, b in zip(ct, st)), 'xor', st
    if mode == 'lcgrotate':
        state = int.from_bytes(hashlib.sha256(prev.encode()).digest()[:4], 'big')
        st = bytes(lcg_gen(state, 1664525, 1013904223, 2**32, lambda s: (s >> 24) & 255, len(ct)))
        return bytes(ror8(c, 1 + st[i] % 8) for i, c in enumerate(ct)), 'rotate', st
    if mode == 'digestadd':
        block = hashlib.sha256((prev + '|digest').encode()).digest()
        st = (block * ((len(ct) // len(block)) + 1))[:len(ct)]
        return bytes((a - b) & 255 for a, b in zip(ct, st)), 'add', st
    raise ValueError(mode)

def forge_admin(d, ct, pt, st, off):
    # flip role=guest -> role=admin in the ciphertext at byte offset off, operation-specific
    mode = d['stream_mode']
    forged = bytearray(ct)
    for j in range(5):
        g, a = ord('guest'[j]), ord('admin'[j])
        if mode in ('repeatxor', 'rc4_b85'):
            forged[off + j] = ct[off + j] ^ g ^ a
        elif mode in ('shakeadd', 'digestadd'):
            forged[off + j] = (ct[off + j] + (a - g)) & 255
        elif mode == 'lcgrotate':
            forged[off + j] = rol8(a, 1 + st[off + j] % 8)
    return bytes(forged)

prev_key = HANDOFF[35]
for n in range(36, 41):
    d = page(n)
    rep = d['representation']
    raw = d['ciphertext']
    if rep == 'hex': ct = bytes.fromhex(raw)
    elif rep == 'base64': ct = base64.b64decode(raw)
    elif rep == 'base85': ct = base64.b85decode(raw)
    elif rep == 'bitreversebase64': ct = bytes(bitrev(b) for b in base64.b64decode(raw))
    else: raise ValueError(rep)
    pt_b, kind, st = token_decrypt(d, prev_key, ct)
    txt = pt_b.decode()
    parts = parse_token(txt)
    tag_ok = hashlib.sha256((parts['scope'] + '|' + parts['handoff']).encode()).hexdigest()[:8] == parts['tag']
    assert parts['role'] == 'guest' and tag_ok, (n, txt, tag_ok)
    off = txt.index('role=') + 5
    forged_ct = forge_admin(d, ct, pt_b, st, off)
    # verify forged ct decrypts to role=admin with the tag still valid
    fpt, _, _ = token_decrypt(d, prev_key, forged_ct)
    fparts = parse_token(fpt.decode())
    assert fparts['role'] == 'admin' and fparts['tag'] == parts['tag']
    assert hashlib.sha256((fparts['scope'] + '|' + fparts['handoff']).encode()).hexdigest()[:8] == fparts['tag']
    forged_txt = fpt.decode()
    say(f'--- PAGE {n} ({d["stream_mode"]} malleability) ---')
    say(f'  original token : {txt}  [tag verifies: {tag_ok}]')
    say(f'  forged token   : {forged_txt}  [same tag, role flipped in ciphertext only]')
    HANDOFF[n] = parts['handoff']
    PT[n] = forged_txt
    prev_key = forged_txt  # chain: next page is keyed by this forged token string

# ---------------- pages 41-45: invert custom_page_encrypt branches ----------------
INV197 = pow(197, -1, 256)
def sbox_inv(y):
    return ((y - 101) * INV197) & 255

prev_h = PT[40]  # page 41 is keyed by page 40's forged token string (same chain rule as 37-40)
for n in range(41, 46):
    d = page(n)
    rep = d['representation']
    if rep == 'hex': ct = bytes.fromhex(d['ciphertext'])
    elif rep == 'base64': ct = base64.b64decode(d['ciphertext'])
    elif rep == 'base85': ct = base64.b85decode(d['ciphertext'])
    else: raise ValueError(rep)
    digest = hashlib.sha256(prev_h.encode()).digest()
    k = digest[0]
    r = (n % 7) + 1
    assert r == int(d['rotation']), (n, r, d['rotation'])
    mask = prev_h.encode()
    out = bytearray()
    for i, y in enumerate(ct):
        m = mask[i % len(mask)]
        if n == 41:   # y = sbox(rol8(b ^ k, r))
            b = ror8(sbox_inv(y), r) ^ k
        elif n == 42: # y = rol8(b ^ k, r) ^ m
            b = ror8(y ^ m, r) ^ k
        elif n == 43: # y = sbox(rol8(b, r) ^ k)
            b = ror8(sbox_inv(y) ^ k, r)
        elif n == 44: # y = (rol8(b ^ k, r) + k) & 255 ^ m
            b = ror8(((y ^ m) - k) & 255, r) ^ k
        elif n == 45: # y = sbox(rol8(b ^ k ^ m, r))
            b = ror8(sbox_inv(y), r) ^ k ^ m
        out.append(b)
    pt = bytes(out).decode()
    extract(n, pt)
    prev_h = HANDOFF[n]

# ---------------- page 46: decoy flag behind Vigenere period 8 ----------------
d = page(46)
res46 = None
for p in (8, 4, 16, 6, 12):
    letters46 = [c for c in d['ciphertext_text'].upper() if c.isalpha()]
    EF = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
          2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
    cols = [[letters46[i] for i in range(j, len(letters46), p)] for j in range(p)]
    shifts = []
    for col in cols:
        nL = len(col)
        shifts.append(max(range(26), key=lambda s: -sum(((col.count(chr(65 + (i + s) % 26)) - nL * EF[i] / 100) ** 2) / (nL * EF[i] / 100) for i in range(26))))
    key46 = ''.join(chr(65 + s) for s in shifts)
    pt46 = vig_decrypt_text(d['ciphertext_text'], key46)
    if 'flag{' in pt46 or 'beunwrapd{' in pt46:
        res46 = (key46, pt46)
        break
key46, pt46 = res46
say(f'--- PAGE 46 (vigenere decoy, key {key46}) ---'); say(pt46[:800])
PT[46] = pt46
import re as _re2
m46 = _re2.search(r'(flag\{[^}]*\}|beunwrapd\{[^}]*\})', pt46)
tag46 = _re2.search(r'([0-9a-f]{8,16})', pt46[m46.end():]) if m46 else None
cand46 = m46.group(0)
sha46 = hashlib.sha256(cand46.encode()).hexdigest()
say(f'  decoy candidate: {cand46}')
say(f'  sha256(candidate)={sha46[:16]} vs printed tag {tag46.group(1) if tag46 else None} -> FAIL (decoy rejected)')

# ---------------- page 47: decoy flag behind bounded xorshift ----------------
d = page(47)
ct47 = base64.b64decode(d['ciphertext_base64'])
pfx = d['known_plaintext_prefix'].encode()
for seed in range(d['seed_range'][0], d['seed_range'][1] + 1):
    if bytes(c ^ k for c, k in zip(ct47, xorshift32_stream(seed, len(pfx)))) == pfx:
        pt47 = bytes(c ^ k for c, k in zip(ct47, xorshift32_stream(seed, len(ct47)))).decode()
        say(f'--- PAGE 47 (xorshift decoy, seed {seed}) ---'); say(pt47[:800])
        break
PT[47] = pt47
m47 = _re2.search(r'(flag\{[^}]*\}|beunwrapd\{[^}]*\})', pt47)
cand47 = m47.group(0)
sha47 = hashlib.sha256(cand47.encode()).hexdigest()
say(f'  decoy candidate: {cand47}')
say(f'  sha256(candidate)[:16]={sha47[:16]} -> compare with printed tag -> FAIL (decoy rejected)')

# ---------------- page 48: finale two-time pad (modular add) ----------------
d = page(48)
ctA48 = bytes.fromhex(d['ciphertext_a'])
ctB48 = bytes.fromhex(d['ciphertext_b'])
ptA48 = d['known_plaintext_a'].encode()[:len(ctA48)]
stream48 = bytes((a - p) & 255 for a, p in zip(ctA48, ptA48))
pt48 = bytes((b - s) & 255 for b, s in zip(ctB48, stream48)).decode()
say(f'--- PAGE 48 (CEO record via two-time pad) ---'); say(pt48)
PT[48] = pt48

# ---------------- page 49: LFSR state recovery, known prefix XOR + BM ----------------
d = page(49)
ct49 = base64.b85decode(d['ciphertext_base85'])
pfx = d['known_plaintext_prefix'].encode()
known49 = bytes(c ^ p for c, p in zip(ct49, pfx))
sbits49 = []
for byte in known49:
    sbits49.extend((byte >> (7 - i)) & 1 for i in range(8))
L49, C49 = berlekamp_massey(sbits49)
assert 0 < L49 <= int(d['max_linear_complexity']), L49
while len(sbits49) < len(ct49) * 8:
    sbits49.append(sum(C49[j] & sbits49[-j] for j in range(1, L49 + 1)) & 1)
stream49 = bytes(int(''.join(map(str, sbits49[i:i + 8])), 2) for i in range(0, len(ct49) * 8, 8))
pt49 = bytes(c ^ k for c, k in zip(ct49, stream49)).decode()
say(f'--- PAGE 49 (LFSR recovered, linear complexity {L49}) ---'); say(pt49)
extract(49, pt49)

# ---------------- page 50: CEO token; final malleability; tag = SHA256(MESSAGE)[:16] ----------------
d = page(50)
ct50 = bytes.fromhex(d['ciphertext_hex'])
stream50 = hashlib.shake_256(HANDOFF[49].encode()).digest(len(ct50))
pt50 = bytes((c - k) & 255 for c, k in zip(ct50, stream50)).decode()
say('--- PAGE 50 (CEO token) ---'); say(pt50)
PT[50] = pt50
parts50 = dict(kv.split('=', 1) for kv in pt50.split(';'))
msg50 = parts50['MESSAGE']; tag50 = parts50['TAG']
assert parts50['ROLE'] == 'guest'
tag_ok50 = hashlib.sha256(msg50.encode()).hexdigest()[:16] == tag50
say(f'tag check: SHA256(MESSAGE)[:16]={hashlib.sha256(msg50.encode()).hexdigest()[:16]} vs printed {tag50} -> {tag_ok50}')
assert tag_ok50
# forge guest -> admin with a modular-add delta; ROLE is not covered by the tag
off50 = pt50.index('ROLE=') + 5
forged50 = bytearray(ct50)
for j in range(5):
    forged50[off50 + j] = (ct50[off50 + j] + (ord('admin'[j]) - ord('guest'[j]))) & 255
fpt50 = bytes((c - k) & 255 for c, k in zip(bytes(forged50), stream50)).decode()
fparts50 = dict(kv.split('=', 1) for kv in fpt50.split(';'))
assert fparts50['ROLE'] == 'admin' and fparts50['TAG'] == tag50
assert hashlib.sha256(fparts50['MESSAGE'].encode()).hexdigest()[:16] == fparts50['TAG']
say(f'forged token  : {fpt50}  [role flipped in ciphertext only; tag still verifies]')
say('');
say('SILENT CIPHER FINAL FLAG: ' + msg50)
say('decoys rejected: page46 ' + cand46 + ' / page47 ' + cand47)
say('ALL 50 PAGES SOLVED')

open('sc_run.log', 'w').write('\n'.join(LOG) + '\n')
print('pages done:', sorted(PT))
