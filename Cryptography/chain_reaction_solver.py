#!/usr/bin/env python3
"""Chain Reaction: independent layer solver (self-contained layers).

Chain convention status: the originals reference a ../README.md that is NOT in the
player ZIP, so the chain-gate formula and chain KDF are an honest gap. Every layer
solved here uses only the layer's own JSON data and its own verifier (envelope
prefixes, oracle transcripts, known pairs, checkpoint digest prefixes).
"""
import json, hashlib, hmac, base64, re, os, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else 'player'
LAY = os.path.join(BASE, 'layers')
LOG = []
TOKENS = {}

def say(s=''):
    print(s); LOG.append(s)

def layer(n):
    return json.load(open(os.path.join(LAY, 'layer_%03d.json' % n)))

def record(n, mode, token, note=''):
    TOKENS[n] = token
    say(f'--- LAYER {n} ({mode}) ---')
    say(f'  token = {token}')
    if note: say(f'  {note}')
    assert re.fullmatch(r'[0-9a-f]{32}', token) or token.startswith('flag{'), token

# ---------- affine_hex ----------
def solve_affine(n):
    d = layer(n)['data']
    alpha = d['alphabet']; a, b = d['a'], d['b']
    ai = pow(a, -1, 16)
    tok = ''.join(alpha[(ai * (alpha.index(c) - b)) % 16] for c in d['ciphertext'])
    record(n, 'affine_hex', tok, f'D(y)=a^-1*(y-b) mod 16, a={a}, b={b}, a^-1={ai}')

# ---------- base32_shift ----------
def solve_base32(n):
    d = layer(n)['data']
    alpha, sh = d['alphabet'], d['shift']
    body = ''.join(alpha[(alpha.index(c) - sh) % 32] for c in d['ciphertext'] if c != '=')
    body += '=' * ((8 - len(body) % 8) % 8)
    tok = base64.b32decode(body).decode()
    record(n, 'base32_shift', tok, f'undo alphabet shift {sh}, then base32 decode')

# ---------- base85_shift (ROT47 then ASCII85) ----------
def rot47(t):
    return ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in t)

def solve_base85(n):
    d = layer(n)['data']
    tok = base64.a85decode(rot47(d['ciphertext_rot47'])).decode()
    record(n, 'base85_shift', tok, 'undo ROT47, then ASCII85 decode')

# ---------- ecb_oracle / ecb_oracle_prefix ----------
def solve_ecb_oracle(n):
    d = layer(n)['data']
    tok = ''
    for row in d['samples']:
        idx = row['candidate_blocks'].index(row['target_block'])
        tok += chr(idx)
    record(n, layer(n)['mode'], tok,
           f"byte-at-a-time: each row's target block matched against 256 candidate blocks; index = recovered byte")

# ---------- padding_oracle / error_leak / padding_error ----------
def solve_padding_oracle(n):
    d = layer(n)['data']
    ct = bytes.fromhex(d['ciphertext']); iv = bytes.fromhex(d['iv'])
    blocks = [iv] + [ct[i:i+16] for i in range(0, len(ct), 16)]
    inter = {}
    for row in d['oracle_responses']:
        key = (row['block_index'], row['byte_position'])
        vec = row['responses_for_guesses_0_to_255']
        assert vec.count('1') == 1, (n, key, vec.count('1'))
        inter[key] = vec.index('1')
    pt = b''
    nblocks = len(blocks) - 1
    for bi in range(nblocks):
        I = bytes(inter[(bi, pos)] for pos in range(16))
        pt += bytes(a ^ b for a, b in zip(I, blocks[bi]))
    # strip PKCS7
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    m = re.search(rb'[0-9a-f]{32}', pt)
    assert m, pt
    record(n, layer(n)['mode'], m.group().decode(),
           f'pre-recorded valid/invalid vectors -> intermediate bytes -> XOR with previous block; pt={pt[:60]!r}')

# ---------- MITM family: E_k(x) = (197*(x^k)+101) mod 256, double encryption ----------
def E(x, k): return (197 * (x ^ k) + 101) % 256
def D(y, k): return ((pow(197, -1, 256) * (y - 101)) % 256) ^ k

def solve_mitm(n):
    d = layer(n)['data']
    p = bytes.fromhex(d['known_plaintext']); c = bytes.fromhex(d['known_ciphertext'])
    t = bytes.fromhex(d['target_ciphertext'])
    # per-byte independent MITM on first byte pair to find (k1, k2) - but keys are per-byte?
    # try single-byte keys shared across the message first
    fwd = {}
    for k1 in range(256):
        fwd.setdefault(E(p[0], k1), []).append(k1)
    pairs = []
    for k2 in range(256):
        mid = D(c[0], k2)
        if mid in fwd:
            for k1 in fwd[mid]:
                if all(E(E(pb, k1), k2) == cb for pb, cb in zip(p, c)):
                    pairs.append((k1, k2))
    assert pairs, 'no key pair'
    k1, k2 = pairs[0]
    pt = bytes(D(D(cb, k2), k1) for cb in t)
    m = re.search(rb'[0-9a-f]{32}', pt)
    assert m, pt
    record(n, layer(n)['mode'], m.group().decode(),
           f'MITM: midpoint table over 256 k1 values x reverse-encrypted known pair; k1={k1}, k2={k2}')

# ---------- rsa_small_e ----------
def icbrt(x):
    lo, hi = 0, 1 << ((x.bit_length() // 3) + 2)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** 3 < x: lo = mid + 1
        else: hi = mid
    return lo if lo ** 3 == x else None

def solve_rsa(n):
    d = layer(n)['data']
    c = int(d['c'], 16) if isinstance(d['c'], str) else d['c']
    m = icbrt(c)
    assert m is not None
    pt = m.to_bytes(d['message_bytes'], 'big')
    tok = pt.decode()
    record(n, 'rsa_small_e', tok, 'm^3 < n so exact integer cube root; no padding')

# ---------- timing ----------
def solve_timing(n):
    d = layer(n)['data']
    ct = bytes.fromhex(d['ciphertext'])
    ts = d['candidate_keys_0_to_255_timing_ns']
    k = ts.index(min(ts))
    pt = bytes(b ^ k for b in ct)
    record(n, 'timing', pt.decode(), f'min-timing candidate key = 0x{k:02x}')

# ---------- cache_trace ----------
def solve_cache(n):
    d = layer(n)['data']
    ct = bytes.fromhex(d['ciphertext'])
    hi = d['victim_way_high_nibble']
    # way leak fixes the high nibble; set leak did not determine the low nibble in our data
    # (advertised set nibble 0x0 was wrong), so brute-force the 16 low nibbles and keep the
    # candidate that yields a 32-char hex token.
    for lo in range(16):
        k = (hi << 4) | lo
        pt = bytes(b ^ k for b in ct)
        if re.fullmatch(rb'[0-9a-f]{32}', pt):
            record(n, 'cache_trace', pt.decode(),
                   f'high nibble 0x{hi:x} from way leak; low nibble 0x{lo:x} brute-forced (hex-shape check) -> key 0x{k:02x}')
            return
    raise AssertionError('no low-nibble candidate gives a hex token')

# ---------- fast_hash_kdf (unsalted SHA-256(password)) ----------
def solve_fast_hash(n):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    d = layer(n)['data']
    iv = bytes.fromhex(d['iv']); ct = bytes.fromhex(d['ciphertext'])
    words = open(os.path.join(BASE, 'wordlist.txt')).read().split()
    for w in words:
        k = hashlib.sha256(w.encode()).digest()
        try:
            pt = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct), 16)
        except Exception:
            continue
        m = re.search(rb'[0-9a-f]{32}', pt)
        if m and all(32 <= c < 127 for c in pt):
            record(n, 'fast_hash_kdf', m.group().decode(),
                   f'dictionary hit: password={w!r}, key=SHA-256(password) unsalted; pt={pt[:60]!r}')
            return
    raise AssertionError('no password hit')

# ---------- salt_reuse ----------
def solve_salt_reuse(n):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    d = layer(n)['data']
    iv = bytes.fromhex(d['iv_reused'])
    c1 = bytes.fromhex(d['ciphertext_known_plaintext'])
    c2 = bytes.fromhex(d['ciphertext_target'])
    words = open(os.path.join(BASE, 'wordlist.txt')).read().split()
    for w in words:
        k = hashlib.sha256(w.encode()).digest()
        try:
            p1 = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c1), 16)
        except Exception:
            continue
        if all(32 <= c < 127 for c in p1):
            p2 = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c2), 16)
            m = re.search(rb'[0-9a-f]{32}', p2)
            assert m, p2
            record(n, 'salt_reuse', m.group().decode(),
                   f'password={w!r} (same unsalted SHA-256 key reused); known msg={p1[:50]!r}; target={p2[:60]!r}')
            return
    raise AssertionError('no password hit')

# ---------- timestamp_key ----------
def solve_timestamp(n):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    d = layer(n)['data']
    iv = bytes.fromhex(d['iv']); ct = bytes.fromhex(d['ciphertext'])
    hdr = d['known_header'].encode()
    for ts in range(d['search_low'], d['search_high'] + 1):
        for kn, k in [('sha256(str)16', hashlib.sha256(str(ts).encode()).digest()[:16]),
                      ('sha256(str)32', hashlib.sha256(str(ts).encode()).digest()),
                      ('md5(str)', hashlib.md5(str(ts).encode()).digest()),
                      ('sha1(str)16', hashlib.sha1(str(ts).encode()).digest()[:16])]:
            try:
                pt = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct), 16)
            except Exception:
                continue
            if pt.startswith(hdr):
                m = re.search(rb'[0-9a-f]{32}', pt)
                assert m, pt
                record(n, 'timestamp_key', m.group().decode(),
                       f'timestamp={ts}, key={kn}; pt={pt[:60]!r}')
                return
    raise AssertionError('no timestamp hit')

# ---------- weak_prng ----------
def solve_weak_prng(n):
    import random
    d = layer(n)['data']
    ct = bytes.fromhex(d['ciphertext']); nonce = bytes.fromhex(d['nonce'])
    hdr = d['known_header'].encode()
    for seed in range(d['seed_low'], d['seed_high'] + 1):
        r = random.Random(seed)
        ks = r.randbytes(len(ct))
        pt = bytes(a ^ b for a, b in zip(ct, ks))
        if pt.startswith(hdr):
            m = re.search(rb'[0-9a-f]{32}', pt)
            assert m, pt
            record(n, 'weak_prng', m.group().decode(), f'seed={seed}, python-random keystream XOR')
            return
    raise AssertionError('no seed hit')

# ---------- gcm_forgery (GHASH subkey from same-nonce pair) ----------
GF_POLY = 0xE1000000000000000000000000000000

def gf_mul(x, y):
    z = 0; v = x
    for i in range(128):
        if (y >> (127 - i)) & 1: z ^= v
        v = (v >> 1) ^ (GF_POLY if v & 1 else 0)
    return z

def gf_pow(x, e):
    r = 1 << 127  # 1 in GF(2^128) with this bit ordering? use standard: 1 = 0x80..? careful
    # use square-and-multiply with integer 1 represented as 2^127? For GHASH field, identity is integer 1<<127? No: identity is integer with only MSB set? Test below.
    b = x
    r = None
    while e:
        if e & 1:
            r = b if r is None else gf_mul(r, b)
        b = gf_mul(b, b)
        e >>= 1
    return r

def gf_inv(x):
    return gf_pow(x, (1 << 128) - 2)

def solve_gcm_forgery(n):
    d = layer(n)['data']
    c1 = int(d['known_ciphertext_1'], 16); t1 = int(d['known_tag_1'], 16)
    c2 = int(d['known_ciphertext_2'], 16); t2 = int(d['known_tag_2'], 16)
    # single 128-bit block messages, empty AAD:
    # T = GHASH(C, len) ^ E(J0); GHASH = ((C * H) ^ lenblock) * H ; len same both -> cancels:
    # T1 ^ T2 = (C1 ^ C2) * H^2   (because ((C1*H)^L)*H ^ ((C2*H)^L)*H = (C1^C2)*H^2)
    dc = c1 ^ c2; dt = t1 ^ t2
    H2 = gf_mul(dt, gf_inv(dc))
    # H = sqrt(H2): in GF(2^128), square root is x^(2^127)
    H = gf_pow(H2, 1 << 127)
    assert gf_mul(H, H) == H2
    lenblock = 128  # 128 bits -> len block integer = 128 (aadtbits=0 || cbits=128)
    EJ0 = t1 ^ gf_mul(gf_mul(c1, H) ^ lenblock, H)
    assert EJ0 == (t2 ^ gf_mul(gf_mul(c2, H) ^ lenblock, H))
    cf = int(d['forgery_target_ciphertext'], 16)
    tag = gf_mul(gf_mul(cf, H) ^ lenblock, H) ^ EJ0
    taghex = '%032x' % tag
    chk = hashlib.sha256(bytes.fromhex(taghex)).hexdigest()[:16]
    ok = chk == d['forgery_tag_check_sha256_prefix']
    assert ok, 'forged-tag digest mismatch'
    record(n, 'gcm_forgery', taghex,
           'GHASH subkey H recovered from same-nonce pair (H^2 = dT/dC in GF(2^128), H = (H^2)^(2^127)); forged tag VERIFIED: sha256(tag bytes) prefix matches the layer check')

# ---------- reuse cascade: keystream = ct_known XOR known previous token ----------
def solve_reuse(n, prev):
    d = layer(n)['data']
    c1 = bytes.fromhex(d['ciphertext_known_plaintext']); c2 = bytes.fromhex(d['ciphertext_target'])
    ks = bytes(a ^ b for a, b in zip(c1, prev.encode()))
    pt = bytes(a ^ b for a, b in zip(c2, ks))
    m = re.fullmatch(rb'[0-9a-f]{32}', pt)
    assert m, pt
    record(n, layer(n)['mode'], m.group().decode(),
           f'reused-stream cancellation with the verified previous token (L{n-1}) as known plaintext')

SOLVERS = {
    'affine_hex': solve_affine,
    'base32_shift': solve_base32,
    'base85_shift': solve_base85,
    'ecb_oracle': solve_ecb_oracle,
    'ecb_oracle_prefix': solve_ecb_oracle,
    'padding_oracle': solve_padding_oracle,
    'error_leak': solve_padding_oracle,
    'padding_error': solve_padding_oracle,
    'mitm': solve_mitm,
    'mitm_des2': solve_mitm,
    'tmto': solve_mitm,
    'rsa_small_e': solve_rsa,
    'timing': solve_timing,
    'cache_trace': solve_cache,
    'fast_hash_kdf': solve_fast_hash,
    'salt_reuse': solve_salt_reuse,
    'timestamp_key': solve_timestamp,
    'weak_prng': solve_weak_prng,
    'gcm_forgery': solve_gcm_forgery,
}

# reuse layers whose previous token is recovered by a self-contained layer
REUSE_CASCADE = {33: 32, 34: 33, 88: 87, 93: 92}

def main():
    only = set(int(x) for x in os.environ.get('ONLY', '').split(',') if x)
    for n in range(1, 101):
        d = layer(n)
        m = d['mode']
        if m in SOLVERS and (not only or n in only):
            try:
                SOLVERS[m](n)
            except Exception as e:
                say(f'--- LAYER {n} ({m}) FAILED: {e!r}')
    # cascade: reuse layers keyed by tokens recovered above (two passes for chains)
    for _ in range(2):
        for n, prevn in sorted(REUSE_CASCADE.items()):
            if n not in TOKENS and prevn in TOKENS and (not only or n in only):
                try:
                    solve_reuse(n, TOKENS[prevn])
                except Exception as e:
                    say(f'--- LAYER {n} (reuse) FAILED: {e!r}')
    say()
    say('tokens recovered: %d -> %s' % (len(TOKENS), sorted(TOKENS)))
    json.dump(TOKENS, open('cr_tokens.json', 'w'), indent=1)
    open('cr_run.log', 'w').write('\n'.join(LOG) + '\n')

if __name__ == '__main__':
    main()
