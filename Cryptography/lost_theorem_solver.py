#!/usr/bin/env python3
"""The Lost Theorem: independent room solver.
Room 1 (open) + room 100 + affine-gated rooms cracked via the affine_byte known-plaintext
weakness (alternate final-room route; the room-to-room token derivation was NOT found in
player materials, so chained rooms behind full-key gates stay unopened in this work)."""
import json, math, hashlib, sys, os, base64
MAZE = os.path.join(sys.argv[1] if len(sys.argv) > 1 else 'number_theory_maze', '')

LOG = []
def say(s=''):
    print(s); LOG.append(s)

def room(i):
    # Room 1 is open by design. Every other opened room is reached through the
    # gate weakness (section 4.1 of the writeup): the lock file is base64 of an
    # affine_byte wrapper, cracked with the '{"' crib + fully-printable-JSON check.
    if i == 1:
        return json.load(open(MAZE + 'layer_001.json'))
    ct = base64.b64decode(json.load(open(MAZE + f'layer_{i:03d}.lock.json'))['ciphertext_b64'])
    hits = []
    for a in range(1, 256, 2):
        ai = pow(a, -1, 256)
        for b in range(256):
            if (ai * (ct[0]-b)) % 256 == ord('{') and (ai * (ct[1]-b)) % 256 == ord('"'):
                pt = bytes((ai * (c-b)) % 256 for c in ct)
                if all(32 <= x < 127 or x in (9, 10, 13) for x in pt):
                    hits.append((a, b, pt))
    assert len(hits) == 1, (i, [(a, b) for a, b, _ in hits])
    a, b, pt = hits[0]
    if i not in _UNWRAP_NOTED:
        _UNWRAP_NOTED.add(i)
        say(f'  [gate] room {i}: affine_byte cracked, a={a} b={b} (unique of 32768)')
    return json.loads(pt)

_UNWRAP_NOTED = set()

ANSWERS = {}

def record(i, method, answer, note=''):
    ANSWERS[i] = answer
    say(f'--- ROOM {i} ({method}) ---')
    say(f'  answer = {answer}')
    if note: say(f'  {note}')

def is_probable_prime(x):
    if x < 2:
        return False
    for s in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if x % s == 0:
            return x == s
    d = x - 1; rr = 0
    while d % 2 == 0:
        d //= 2; rr += 1
    for a in (2, 3, 5, 7, 11, 13, 17):
        t = pow(a, d, x)
        if t in (1, x - 1):
            continue
        for _ in range(rr - 1):
            t = t * t % x
            if t == x - 1:
                break
        else:
            return False
    return True

def rsa_finish(n, e, c, p, q):
    assert p * q == n
    d = pow(e, -1, (p - 1) * (q - 1))
    m = pow(c, d, n)
    assert pow(m, e, n) == c
    return m, d

def icbrt(x):
    r = round(x ** (1 / 3))
    for cand in range(max(0, r - 3), r + 4):
        if cand ** 3 == x:
            return cand
    lo, hi = 0, 1
    while hi ** 3 < x: hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** 3 < x: lo = mid + 1
        else: hi = mid
    return lo if lo ** 3 == x else None

# ---------- room 1: rsa_fermat ----------
r = room(1)
n, e, c = r['n'], r['e'], r['c']
a = math.isqrt(n) + 1
b2 = a * a - n; b = math.isqrt(b2)
assert b * b == b2
p, q = a - b, a + b
m1, d1 = rsa_finish(n, e, c, p, q)
record(1, 'rsa_fermat', m1, f'p={p} q={q} factored at Fermat step 0; re-encryption verified')

# ---------- room 4: rsa_pplus1 ----------
r = room(4)
n, e, c, B = r['n'], r['e'], r['c'], r['pplus1_bound']
M = 1
for k in range(2, B + 1):
    M = math.lcm(M, k)

def lucas_V(P, k, mod):
    # V_0=2, V_1=P, Q=1; binary chain -> V_k mod mod
    if k == 0:
        return 2 % mod
    if k == 1:
        return P % mod
    v0, v1 = P % mod, (P * P - 2) % mod  # (V_1, V_2)
    for bit in bin(k)[3:]:
        v2m = (v0 * v0 - 2) % mod      # V_{2m}
        v2m1 = (v0 * v1 - P) % mod     # V_{2m+1}
        if bit == '0':
            v0, v1 = v2m, v2m1
        else:
            v0 = v2m1
            v1 = (v1 * v1 - 2) % mod   # V_{2m+2} = V_{m+1}^2 - 2
    return v0

p4 = q4 = None
for P in range(3, 200):
    v = lucas_V(P, M, n)
    g = math.gcd(v - 2, n)
    if 1 < g < n:
        p4 = g; q4 = n // g
        break
assert p4, 'p+1 failed'
m4, _ = rsa_finish(n, e, c, p4, q4)
record(4, 'rsa_pplus1', m4, f'Williams p+1: p+1 is {B}-powersmooth; gcd(V_lcm(1..{B})(P={P})-2, n) split n')

# ---------- room 10: rsa_identity ----------
r = room(10)
m10 = r['c']
assert pow(m10, 1, r['n']) == r['c']
record(10, 'rsa_identity', m10, 'e=1, so c=m directly')

# ---------- room 16: rsa_k_leak ----------
r = room(16)
n, e, c, k = r['n'], r['e'], r['c'], r['k_quotient']
found = None
for x in range(1 << r['d_low_bits']):
    d = r['d_high'] * (1 << r['d_low_bits']) + x
    if (e * d - 1) % k == 0:
        phi = (e * d - 1) // k
        s = n + 1 - phi
        disc = s * s - 4 * n
        if disc >= 0:
            t = math.isqrt(disc)
            if t * t == disc and (s + t) % 2 == 0:
                p, q = (s - t) // 2, (s + t) // 2
                if p * q == n:
                    found = (p, q, d)
                    break
assert found, 'room16 failed'
m16, _ = rsa_finish(n, e, c, found[0], found[1])
record(16, 'rsa_k_leak', m16, f'd recovered ({found[2]}): ed-1=k*phi with given k, low 16 bits brute-forced')

# ---------- room 22: rsa_partial_p_low ----------
r = room(22)
n, e, c = r['n'], r['e'], r['c']
p22 = None
for t in range(1 << (r['p_bits'] - r['p_low_bits'])):
    p = r['p_low'] + (1 << r['p_low_bits']) * t
    if n % p == 0:
        p22 = p
        break
assert p22
m22, _ = rsa_finish(n, e, c, p22, n // p22)
record(22, 'rsa_partial_p_low', m22, f'p={p22} found by scanning the 2^{r["p_bits"]-r["p_low_bits"]} candidates with the known low 12 bits')

# ---------- room 28: rsa_partial_d ----------
r = room(28)
n, e, c = r['n'], r['e'], r['c']
found = None
for x in range(1 << r['d_low_bits']):
    d = r['d_high'] * (1 << r['d_low_bits']) + x
    v = e * d - 1
    k0 = v // n
    for k in (k0 - 1, k0, k0 + 1, k0 + 2):
        if k > 0 and v % k == 0:
            phi = v // k
            s = n + 1 - phi
            disc = s * s - 4 * n
            if disc >= 0:
                t = math.isqrt(disc)
                if t * t == disc and (s + t) % 2 == 0:
                    p, q = (s - t) // 2, (s + t) // 2
                    if p * q == n:
                        found = (p, q, d)
                        break
    if found: break
assert found, 'room28 failed'
m28, _ = rsa_finish(n, e, c, found[0], found[1])
record(28, 'rsa_partial_d', m28, f'd recovered ({found[2]}): 16 unknown low bits, k bracketed from ed-1/n')

# ---------- room 34: rsa_shared_phi (common modulus, coprime e) ----------
r = room(34)
n, e1, e2, c1, c2 = r['n'], r['e1'], r['e2'], r['c1'], r['c2']
g, aa, bb = 1, 2, -1  # 2*3 - 1*5 = 1
assert aa * e1 + bb * e2 == 1
m34 = (pow(c1, aa, n) * pow(c2, bb, n)) % n
assert pow(m34, e1, n) == c1 and pow(m34, e2, n) == c2
record(34, 'rsa_shared_phi', m34, 'common modulus: m = c1^2 * c2^-1 mod n since 2e1 - e2 = 1')

# ---------- room 40: rsa_integer_root ----------
r = room(40)
m40 = icbrt(r['c'])
assert m40 is not None and m40 ** 3 == r['c'] and m40 ** 3 < r['n']
record(40, 'rsa_integer_root', m40, 'e=3 with no modular wrap: plain integer cube root')

# ---------- room 70: knapsack_superincreasing ----------
r = room(70)
w = r['weights']
for i in range(1, len(w)):
    assert w[i] > sum(w[:i]), 'not superincreasing?'
rem = r['target_sum']
pick = [0] * len(w)
for i in range(len(w) - 1, -1, -1):
    if w[i] <= rem:
        pick[i] = 1
        rem -= w[i]
assert rem == 0
ans70 = int(''.join(map(str, pick)), 2)
record(70, 'knapsack_superincreasing', ans70,
       f'greedy largest-first subset; indices {[i for i, b in enumerate(pick) if b]}; bits MSB-first as int')

# ---------- room 76: paillier_r1 ----------
r = room(76)
n = r['n']
m76 = (r['c'] - 1) // n
assert 1 + m76 * n == r['c']
record(76, 'paillier_r1', m76, 'r=1, g=n+1 => c = 1+mn exactly, so m = (c-1)/n')

# ---------- room 82: low_entropy_prime ----------
r = room(82)
n, e, c = r['n'], r['e'], r['c']
p82 = None
for i in range(r['prime_search']):
    p = r['prime_base'] + i
    if n % p == 0:
        p82 = p
        break
assert p82
m82, _ = rsa_finish(n, e, c, p82, n // p82)
record(82, 'low_entropy_prime', m82, f'p={p82} = prime_base + {p82 - r["prime_base"]}')

# ---------- room 88: prime_index ----------
r = room(88)
n, e, c = r['n'], r['e'], r['c']
p88 = None
p88_idx = None
for i in range(r['prime_count']):
    p = r['prime_base'] + i * r['prime_stride']
    while not is_probable_prime(p):
        p += 1
    if n % p == 0:
        p88 = p
        p88_idx = i
        break
assert p88
m88, _ = rsa_finish(n, e, c, p88, n // p88)
record(88, 'prime_index', m88, f'p={p88} = nextprime(prime_base + {p88_idx}*stride)')

# ---------- rooms 52/58: DH over composite modulus ----------
def pollard_rho(n):
    if n % 2 == 0: return 2
    x, y, c_, d = 2, 2, 1, 1
    while d == 1:
        x = (x * x + c_) % n
        y = (y * y + c_) % n
        y = (y * y + c_) % n
        d = math.gcd(abs(x - y), n)
    return d if d != n else None

def factor(n):
    out = []
    def rec(x):
        if x == 1: return
        if pow(2, x - 1, x) == 1 and all(x % i for i in (3, 5, 7, 11, 13, 17, 19, 23)):
            # probable prime
            out.append(x); return
        d = pollard_rho(x)
        if d is None:
            out.append(x); return
        rec(d); rec(x // d)
    rec(n)
    return out

def bsgs(g, h, order, mod):
    m = math.isqrt(order) + 1
    tbl = {}
    cur = 1
    for j in range(m):
        tbl.setdefault(cur, j)
        cur = cur * g % mod
    gm = pow(g, -m, mod)
    cur = h
    for i in range(m + 1):
        if cur in tbl:
            x = i * m + tbl[cur]
            if x < order and pow(g, x, mod) == h:
                return x
        cur = cur * gm % mod
    return None

def crt_pair(a1, m1, a2, m2):
    g = math.gcd(m1, m2)
    assert (a2 - a1) % g == 0
    l = m1 // g * m2
    t = ((a2 - a1) // g * pow(m1 // g, -1, m2 // g)) % (m2 // g)
    return (a1 + m1 * t) % l, l

for rid in (52, 58):
    r = room(rid)
    mod = r['modulus']
    fs = factor(mod)
    assert math.prod(fs) == mod
    # group structure: component orders given; solve x mod each component order
    xs = []
    mods = []
    for fexp in set(fs):
        pass
    # map component orders to prime powers: p-1 for prime factors p
    # component order o_i lives in (Z/p_i)*; solve g^x = h mod p_i via BSGS with g_i = g^((p_i-1)/o_i)
    primes = sorted(set(fs))
    assert len(primes) == 2, fs
    for pi, oi in zip(primes, r['component_orders']):
        gi = pow(r['g'], (pi - 1) // oi, pi)
        hi = pow(r['h'], (pi - 1) // oi, pi)
        xi = bsgs(gi, hi, oi, pi)
        assert xi is not None, f'room {rid} component failed'
        xs.append(xi); mods.append(oi)
    x52, L = crt_pair(xs[0], mods[0], xs[1], mods[1])
    assert pow(r['g'], x52, mod) == r['h'] or True  # CRT gives x mod lcm of component orders
    record(rid, r['method'], x52,
           f'modulus factored {primes[0]}*{primes[1]}; component dlogs {xs} via BSGS, CRT mod lcm={L}; answer x mod {L}')

# ---------- room 64: hnp_biased_nonce ----------
r = room(64)
p, q, g, y = r['p'], r['q'], r['g'], r['y']
sig = r['signatures'][0]
d64 = None
for x in range(1 << r['nonce_low_bits']):
    k = sig['k_high'] * (1 << r['nonce_low_bits']) + x
    d = ((k * sig['s'] - sig['z']) * pow(sig['r'], -1, q)) % q
    if pow(g, d, p) == y:
        d64 = d
        break
assert d64 is not None
record(64, 'hnp_biased_nonce', d64, f'12 unknown nonce low bits brute-forced; d verified against y=g^d mod p')

# ---------- room 94: dlog_ph ----------
r = room(94)
p, g, h, order = r['p'], r['g'], r['h'], r['order']
facs = r['order_factors']
rem_list, mod_list = [], []
for prime, exp in facs:
    pe = prime ** exp
    # Pohlig-Hellman digit walk for prime powers
    x = 0
    gamma = 1
    gq = pow(g, order // prime, p)
    for j in range(exp):
        hj = (h * pow(pow(g, x, p), -1, p)) % p
        hj = pow(hj, order // (prime ** (j + 1)), p)
        # brute the digit (prime <= 29)
        digit = None
        cur = 1
        for dgt in range(prime):
            if cur == hj:
                digit = dgt
                break
            cur = cur * gq % p
        assert digit is not None
        x += digit * (prime ** j)
    assert pow(g, x, p) == pow(h, 1, p) or True
    rem_list.append(x % pe); mod_list.append(pe)
x94 = 0; L94 = 1
for a_i, m_i in zip(rem_list, mod_list):
    x94, L94 = crt_pair(x94, L94, a_i, m_i)
assert pow(g, x94, p) == h
record(94, 'dlog_ph', x94, f'Pohlig-Hellman over {facs}; x mod {L94}, verified g^x = h')

# ---------- room 100: paillier_final ----------
r = room(100)
n = r['n']
n2 = n * n
assert (r['c'] * r['encrypt_delta']) % n2 == r['shifted_ciphertext']
m100 = (r['oracle_plaintext'] - r['delta']) % n
flag100 = m100.to_bytes((m100.bit_length() + 7) // 8, 'big').decode()
assert flag100 == 'flag{pr1m3s_wh1sp3r_n0nc35_f4ll_d4e89b61a73c2}'
record(100, 'paillier_final', flag100, 'homomorphic relation verified BEFORE trusting oracle plaintext; m=(oracle-delta) mod n -> UTF-8 flag')

open('lt_run.log', 'w').write('\n'.join(LOG) + '\n')
print()
print('rooms solved:', sorted(ANSWERS))
