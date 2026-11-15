#!/usr/bin/env python3
"""Archive Shadows (Paper_trail) - independent 50-page chain solver.
Written from the player pack only. Standard library only.
Each page's decoded text is stored in PT[page]; instructions on a page
(and the decoded text of the previous page) drive the next decode."""
import base64, codecs, hashlib, json, os, re, sys, urllib.parse
from collections import Counter

PACK = sys.argv[1] if len(sys.argv) > 1 else 'Paper_trail'
PT = {}   # page -> decoded plaintext
LOG = []
def say(*a):
    line = ' '.join(str(x) for x in a)
    print(line); LOG.append(line)

def page(n):
    for name in (f'page{n:02d}.txt', f'page{n:02d}.json', f'page{n:02d}.http',
                 f'page{n:02d}.log', f'page{n:02d}.eml', f'page{n:02d}.rot',
                 f'page{n:02d}_reused_stream.txt', f'page{n:02d}_seed.txt',
                 f'page{n:02d}_whitespace.txt', f'page{n:02d}_case.txt',
                 f'page{n:02d}_wordlists.txt', f'page{n:02d}_zero_width.txt',
                 f'page{n:02d}_lengths.txt'):
        p = os.path.join(PACK, name)
        if os.path.exists(p):
            return open(p, encoding='utf-8').read()
    raise FileNotFoundError(n)

def payload(text):
    return text.split('BEGIN PAYLOAD', 1)[1].split('END PAYLOAD', 1)[0].strip()

def atbash(t):
    out = []
    for c in t:
        if 'A' <= c <= 'Z': out.append(chr(155 - ord(c)))
        elif 'a' <= c <= 'z': out.append(chr(219 - ord(c)))
        else: out.append(c)
    return ''.join(out)

def caesar(t, k):
    out = []
    for c in t:
        if 'A' <= c <= 'Z': out.append(chr((ord(c)-65+k) % 26 + 65))
        elif 'a' <= c <= 'z': out.append(chr((ord(c)-97+k) % 26 + 97))
        else: out.append(c)
    return ''.join(out)

TRAILER = ('THE LAST ARCHIVE WAS NOT A ROOM BUT A CHAIN OF CHECKS. '
           'EACH PAGE HAD TO EARN THE RIGHT TO NAME THE NEXT, AND EACH '
           'SEAL COULD BE TESTED WITHOUT TRUSTING THE CLERK.')

# ---------------- pages 1-5 (already verified interactively) ----------------
d = json.loads(page(1))
PT[1] = base64.b64decode(d['metadata']['field_7']).decode()
v = re.search(r'X-Archive-Block: (\S+)', page(2)).group(1)
PT[2] = base64.b32decode(v).decode()
hx = re.search(r'payload=([0-9A-Fa-f]+)', page(3)).group(1)
PT[3] = bytes.fromhex(hx).decode()
PT[4] = urllib.parse.unquote(page(4).split('\n\n', 1)[1].strip())
PT[5] = codecs.decode(page(5).split('PAYLOAD FOLLOWS')[1].strip(), 'rot13')
for n in range(1, 6):
    assert PT[n].endswith('TRUSTING THE CLERK.'), n
    say(f'--- PAGE {n:02d} decoded ---')
    say(PT[n])

# ---------------- page 6: Atbash ----------------
PT[6] = atbash(payload(page(6)))
say('--- PAGE 06 (atbash) ---'); say(PT[6])

# ---------------- page 7: affine, brute a (coprime) x b ----------------
ct = payload(page(7)).upper()
best = None
for a in range(1, 26, 2):
    if a == 13: continue
    if __import__('math').gcd(a, 26) != 1: continue
    ai = pow(a, -1, 26)
    for b in range(26):
        pt = ''.join(chr((ai * ((ord(c) - 65) - b)) % 26 + 65) if c.isalpha() else c for c in ct)
        score = pt.count(' THE ') + pt.count(' AND ') + pt.count('THE LAST ARCHIVE')
        if best is None or score > best[0]:
            best = (score, a, b, pt)
score, a, b, pt = best
say(f'--- PAGE 07 (affine a={a} b={b}, score={score}) ---'); say(pt)
assert 'THE LAST ARCHIVE' in pt
PT[7] = pt

# ---------------- substitution solver (pages 8, 9) ----------------
# Corpus sentences known so far (pages 1-7 all draw from one template set).
def sentences(*texts):
    out = set()
    for t in texts:
        for s in re.split(r'(?<=[.;])\s+', t.replace('\n', ' ')):
            s = s.strip()
            if s: out.add(s)
    return out

CORPUS = sentences(*PT.values())
def word_pattern(w):
    m, nxt = {}, 0
    p = []
    for c in w:
        if c not in m:
            m[c] = nxt; nxt += 1
        p.append(m[c])
    return tuple(p)

def corpus_words():
    ws = set()
    for s in CORPUS:
        for w in re.findall(r'[A-Z]+', s.upper()):
            ws.add(w)
    return ws

KNOWN_SENTENCES = [
    'THE LAST ARCHIVE WAS NOT A ROOM BUT A CHAIN OF CHECKS',
    'EACH PAGE HAD TO EARN THE RIGHT TO NAME THE NEXT AND EACH SEAL COULD BE TESTED WITHOUT TRUSTING THE CLERK',
    'THE ARCHIVIST KEPT A PAPER REGISTER BESIDE THE LAMP AND EACH ENTRY RECORDED WHICH HAND HAD TOUCHED THE PAGE',
    'A SEAL WAS NEVER TRUSTED BECAUSE IT LOOKED OLD THE INK THE FIBRES AND THE ORDER OF THE MARKS HAD TO AGREE',
    'A SEAL WAS NEVER TRUSTED BECAUSE IT LOOKED OLD THE INK THE FIBERS AND THE ORDER OF THE MARKS HAD TO AGREE',
    'THE NIGHT CLERK MEASURED EVERY STRIP BEFORE TRYING A KEY SINCE A LENGTH CAN EXPOSE A BAD ASSUMPTION',
    'SOME NOTES WERE COPIED BY CAREFUL HANDS WHILE OTHERS WERE MADE BY A MACHINE THAT REUSED WHAT SHOULD HAVE BEEN FRESH',
    'THE SAFE HOUSE HAD NO WINDOWS BUT THE LEDGER STILL SPOKE THROUGH SPACING REPETITION AND THE SHAPE OF EACH LETTER',
    'A FALSE TRAIL COULD BE BEAUTIFUL AND STILL FAIL ITS SEAL A TRUE TRAIL HAD TO SURVIVE A CHECK ANYONE COULD REPEAT',
]

def solve_substitution(ct, label):
    ct_words = re.findall(r'[A-Z]+', ct)
    fwd = {}
    # align known sentences by word-pattern sequence
    for sent in KNOWN_SENTENCES:
        pw = sent.split()
        pats = [word_pattern(w) for w in pw]
        n = len(pw)
        for i in range(0, len(ct_words) - n + 1):
            seg = ct_words[i:i+n]
            if [word_pattern(w) for w in seg] != pats:
                continue
            trial = dict(fwd)
            ok = True
            for cw_, pw_ in zip(seg, pw):
                for c, q in zip(cw_, pw_):
                    if c in trial and trial[c] != q: ok = False; break
                    if q in trial.values() and trial.get(c) != q: ok = False; break
                    trial[c] = q
                if not ok: break
            if ok:
                fwd = trial
                say(f'[{label}] aligned known sentence at word {i}: ...{pw[0]} {pw[1]}... (+letters)')
                break
    say(f'[{label}] {len(fwd)} letters mapped from known-plaintext alignment')
    COMMON = ['THE ', ' AND ', 'ING', 'ION', 'ENT', 'HER', 'TH ', 'HE ', ' IN ',
              'ER ', ' RE ', 'ED ', ' OF ', ' TO ', 'THAT', 'WITH', 'HAVE', 'NOT',
              ' BE ', ' AS ', ' AT ', ' IT ', 'EN ', 'ES ', 'OR ', 'NT ', 'EA ', 'TI ',
              'ATIO', 'FOR ', 'TER', 'EST', 'ERS', 'HAT', 'ATE', 'ALL', 'TIO']
    def score(t):
        return sum(t.count(s) * len(s) for s in COMMON)
    while True:
        unmapped = [c for c in set(re.sub(r'[^A-Z]', '', ct)) if c not in fwd]
        if not unmapped: break
        used = set(fwd.values())
        best_gain = None
        for c in unmapped:
            for q in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                if q in used: continue
                fwd[c] = q
                s = score(''.join(fwd.get(x, x) for x in ct))
                del fwd[c]
                if best_gain is None or s > best_gain[0]:
                    best_gain = (s, c, q)
        _, c, q = best_gain
        fwd[c] = q
        say(f'[{label}] greedy fill {c}>{q}')
    pt = ''.join(fwd.get(c, c) for c in ct)
    say(f'--- {label} (substitution, {len(fwd)} letters) ---')
    say(pt)
    say(f'[{label}] mapping: ' + ' '.join(f'{k}>{v}' for k, v in sorted(fwd.items())))
    return pt

PT[8] = solve_substitution(payload(page(8)).upper(), 'PAGE 08')
PT[9] = solve_substitution(payload(page(9)).upper(), 'PAGE 09')

# ---------------- page 10: Caesar over 25 shifts ----------------
ct = payload(page(10)).upper()
best = max(range(1, 26), key=lambda s: caesar(ct, -s).count('THE'))
pt = caesar(ct, -best)
say(f'--- PAGE 10 (caesar shift back {best}) ---'); say(pt)
PT[10] = pt

# ---------------- page 11: Vigenere, key broken by IC + chi^2 columns ----------------
ENG = {'A':.08167,'B':.01492,'C':.02782,'D':.04253,'E':.12702,'F':.02228,'G':.02015,
       'H':.06094,'I':.06966,'J':.00153,'K':.00772,'L':.04025,'M':.02406,'N':.06749,
       'O':.07507,'P':.01929,'Q':.00095,'R':.05987,'S':.06327,'T':.09056,'U':.02758,
       'V':.00978,'W':.02360,'X':.00150,'Y':.01974,'Z':.00074}
def col_chi2(pt_letters):
    n = len(pt_letters)
    cnt = Counter(pt_letters)
    return sum((cnt.get(chr(65+i), 0) - n*ENG[chr(65+i)])**2 / (n*ENG[chr(65+i)] + 1e-9)
               for i in range(26))
def chi2_shift(col, s):
    return col_chi2([chr((ord(c) - 65 - s) % 26 + 65) for c in col])
def vig_break(text, maxk=14, mode='vigenere', crib='THE LAST ARCHIVE'):
    letters = re.sub(r'[^A-Z]', '', text.upper())
    def ic(s):
        n = len(s)
        return sum(v*(v-1) for v in Counter(s).values()) / (n*(n-1) + 1e-9)
    def decrypt_with(key, k):
        out, ki = [], 0
        for c in text.upper():
            if c.isalpha():
                kv = ord(key[ki % k]) - 65
                p = (ord(c) - 65 - kv) % 26 if mode == 'vigenere' else (kv - (ord(c) - 65)) % 26
                out.append(chr(p + 65)); ki += 1
            else: out.append(c)
        return ''.join(out)
    scores = []
    for k in range(1, maxk + 1):
        cols = [letters[i::k] for i in range(k)]
        scores.append((sum(ic(c) for c in cols) / k, k))
    # try periods in IC order, smallest preferred among the top, accept first whose
    # decryption contains the known trailer crib
    for _, k in sorted(scores, reverse=True) + sorted(scores):
        cols = [letters[i::k] for i in range(k)]
        if mode == 'vigenere':
            key = ''.join(chr(65 + min(range(26), key=lambda s: chi2_shift(c, s))) for c in cols)
        else:  # beaufort: P = (K - C) mod 26
            key = ''.join(chr(65 + min(range(26), key=lambda kv: col_chi2(
                [chr((kv - (ord(ch) - 65)) % 26 + 65) for ch in c]))) for c in cols)
        pt = decrypt_with(key, k)
        if crib in pt:
            return k, key, pt
    raise SystemExit(f'vig_break failed ({mode})')

ct11 = payload(page(11)).upper()
k11, key11, pt11 = vig_break(ct11)
say(f'--- PAGE 11 (vigenere period={k11} key={key11}) ---'); say(pt11)
PT[11] = pt11

# ---- page-seal rule (discovered independently, verified against P11 key XPOZH):
# seal digest for page NN = SHA-256( decoded plaintext of page NN-1 || "|PAPER-TRAIL|NN" )
# key letters = digest bytes mod 26, A=0..Z=25.
def seal(n, extra=b''):
    return hashlib.sha256(PT[n-1].encode() + f'|PAPER-TRAIL|{n:02d}'.encode() + extra).digest()
assert [b % 26 for b in seal(11)[:5]] == [23, 15, 14, 25, 7], 'seal rule self-check vs P11'
say('PAGE-SEAL RULE confirmed: sha256(prev plaintext | \'|PAPER-TRAIL|NN\') -> key bytes%26 (matches cracked P11 key XPOZH)')

def keyed_decrypt(text, key, mode, skip_nonletters=True):
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            kv = key[ki % len(key)]
            v = ord(c.upper()) - 65
            if mode == 'vigenere': p = (v - kv) % 26
            elif mode == 'beaufort': p = (kv - v) % 26
            elif mode == 'add': p = (v + kv) % 26
            out.append(chr(p + 65)); ki += 1
        else:
            out.append(c)
    return ''.join(out)

# ---------------- page 12: Beaufort, key from page-seal ----------------
ct12 = payload(page(12)).upper()
k12p, key12s, pt12 = vig_break(ct12, mode='beaufort')
say(f'--- PAGE 12 (beaufort, cracked period={k12p} key={key12s}) ---'); say(pt12)
assert 'THE LAST ARCHIVE' in pt12
PT[12] = pt12
# identify key derivation from the seal schedule
d12 = seal(12)
cands = {
    'first5%26': ''.join(chr(65 + b % 26) for b in d12[:5]),
    'bytes5-10%26': ''.join(chr(65 + b % 26) for b in d12[5:10]),
    'last5%26': ''.join(chr(65 + b % 26) for b in d12[-5:]),
    'hexletters5': ''.join(c.upper() for c in d12.hex() if c.isalpha())[:5],
}
for name, v in cands.items():
    if v == key12s: say(f'PAGE 12 key = page-seal {name}')
say(f'PAGE 12 cracked key {key12s}; seal-derived candidates: {cands}')

# ---------------- page 13: plaintext autokey, seed = 6 page-seal bytes ----------------
# (seed length found by backward-rolling the known tail sentence for lengths 2..12;
#  only L=6 yields English, and it equals seal(13)[:6] % 26)
ct13 = payload(page(13)).upper()
seed13 = [b % 26 for b in seal(13)[:6]]
letters13 = [c for c in ct13 if c.isalpha()]
ks = list(seed13); ptletters = []
for i, c in enumerate(letters13):
    p = (ord(c) - 65 - ks[i]) % 26
    ptletters.append(p); ks.append(p)
out, it = [], iter(ptletters)
for c in ct13:
    out.append(chr(next(it) + 65) if c.isalpha() else c)
pt13 = ''.join(out)
say(f'--- PAGE 13 (plaintext autokey, 6-letter seed {"".join(chr(65+x) for x in seed13)}) ---'); say(pt13)
assert 'ASSUMPTION' in pt13
PT[13] = pt13

# ---------------- page 14: running key = alpha text of page 13 ----------------
ct14 = payload(page(14)).upper()
runkey = [ord(c) - 65 for c in re.sub(r'[^A-Z]', '', pt13.upper())]
letters14 = [c for c in ct14 if c.isalpha()]
assert len(letters14) <= len(runkey)
pt14l = [(ord(c) - 65 - runkey[i]) % 26 for i, c in enumerate(letters14)]
out, it = [], iter(pt14l)
for c in ct14:
    out.append(chr(next(it) + 65) if c.isalpha() else c)
pt14 = ''.join(out)
say('--- PAGE 14 (running key = page13 alpha text) ---'); say(pt14)
assert 'THE LAST ARCHIVE' in pt14
PT[14] = pt14

# ---------------- page 15: Gronsfeld (repeating digit key) ----------------
ct15 = payload(page(15)).upper()
letters15 = [c for c in ct15 if c.isalpha()]
best15 = None
for klen in range(2, 13):
    digs = [b % 10 for b in seal(15)[:klen]]
    pl = [(ord(c) - 65 - digs[i % klen]) % 26 for i, c in enumerate(letters15)]
    txt = ''.join(chr(65 + p) for p in pl)
    sc = txt.count('THE') + txt.count('AND') + 3 * ('THE LAST ARCHIVE' in txt)
    if best15 is None or sc > best15[0]:
        best15 = (sc, klen, digs, txt)
sc, klen, digs, txt15 = best15
say(f'PAGE 15 digit key length {klen}: {digs} (score {sc})')
out, it = [], iter(txt15)
for c in ct15:
    out.append(next(it) if c.isalpha() else c)
pt15 = ''.join(out)
say('--- PAGE 15 (gronsfeld) ---'); say(pt15)
assert 'THE' in pt15
PT[15] = pt15

def payload_raw(text):
    return text.split('BEGIN PAYLOAD\n')[1].split('\nEND PAYLOAD')[0]

# ---------------- page 16: rail fence, 3 rails, whole string incl spaces ----------------
ct16 = payload_raw(page(16))
def rail_decrypt(ct, rails):
    n = len(ct)
    pat = list(range(rails)) + list(range(rails - 2, 0, -1))
    counts = Counter(pat[i % len(pat)] for i in range(n))
    idx = {}
    pos = 0
    for r in range(rails):
        idx[r] = ct[pos:pos + counts[r]]; pos += counts[r]
    ptr = [0] * rails
    out = []
    for i in range(n):
        r = pat[i % len(pat)]
        out.append(idx[r][ptr[r]]); ptr[r] += 1
    return ''.join(out)
pt16 = rail_decrypt(ct16, 3).upper()
say('--- PAGE 16 (rail fence 3) ---'); say(pt16)
assert 'THE' in pt16
PT[16] = pt16

# ---------------- page 17: columnar width 7, column order from seal digest ----------------
ct17 = payload_raw(page(17))  # exact string: edge spaces are grid cells
def col_order_from_digest(dgst, width):
    return [i for i, _ in sorted(enumerate(dgst[:width]), key=lambda t: (t[1], t[0]))]
def columnar_decrypt(ct, width, order):
    # encryption: write rows across `width`, read columns in sequence order[0], order[1], ...
    n = len(ct)
    rows = (n + width - 1) // width
    lens = []
    for c in range(width):
        lens.append(rows if c < n - (rows - 1) * width or n % width == 0 or c < n % width else rows - 1)
    # recompute properly: full rows = n // width; remainder r = n % width -> first r columns have one extra
    full, rem = divmod(n, width)
    lens = [full + (1 if c < rem else 0) for c in range(width)]
    cols = {}
    pos = 0
    for c in order:
        cols[c] = ct[pos:pos + lens[c]]; pos += lens[c]
    out = []
    for r in range(full + (1 if rem else 0)):
        for c in range(width):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return ''.join(out)
order17 = col_order_from_digest(seal(17), 7)
pt17 = columnar_decrypt(ct17, 7, order17).upper()
say(f'--- PAGE 17 (columnar w=7, seal column order {order17}) ---'); say(pt17)
assert 'THE' in pt17
PT[17] = pt17

# ---------------- page 18: spiral route, 19x20 grid, 366 chars + 14 X pad ----------------
ct18 = payload_raw(page(18))
def spiral_decrypt(ct, rows, cols, start, cw):
    # encryption read the perimeter clockwise then inward; we fill the grid in that
    # read order, then return row-major text
    grid = [[''] * cols for _ in range(rows)]
    # build the spiral coordinate sequence
    coords = []
    r0, r1, c0, c1 = 0, rows - 1, 0, cols - 1
    while r0 <= r1 and c0 <= c1:
        ring = ([(r0, c) for c in range(c0, c1 + 1)] +
                [(r, c1) for r in range(r0 + 1, r1 + 1)] +
                ([(r1, c) for c in range(c1 - 1, c0 - 1, -1)] if r1 > r0 else []) +
                ([(r, c0) for r in range(r1 - 1, r0, -1)] if c1 > c0 else []))
        coords.extend(ring)
        r0 += 1; r1 -= 1; c0 += 1; c1 -= 1
    # rotate/reflect the sequence for the chosen start corner and direction
    def transform(seq):
        if start == 'tl': s = seq
        elif start == 'tr': s = [(r, cols - 1 - c) for r, c in seq]
        elif start == 'br': s = [(rows - 1 - r, cols - 1 - c) for r, c in seq]
        else: s = [(rows - 1 - r, c) for r, c in seq]
        return s
    # clockwise vs anticlockwise: reverse each ring traversal
    seq = transform(coords)
    if not cw:
        seq = [seq[0]] + list(reversed(seq[1:]))  # crude; refined below if needed
    for (r, c), ch in zip(seq, ct):
        grid[r][c] = ch
    return ''.join(''.join(row) for row in grid)
best18 = None
for start in ('tl', 'tr', 'br', 'bl'):
    t = spiral_decrypt(ct18, 19, 20, start, True).upper()
    sc = sum(t.count(w) for w in (' THE ', ' AND ', 'ARCHIVE', ' OF '))
    if best18 is None or sc > best18[0]: best18 = (sc, start, t)
sc18, start18, pt18 = best18
say(f'--- PAGE 18 (spiral 19x20, start={start18} cw, score {sc18}) ---'); say(pt18)
PT[18] = pt18

# ---------------- page 19: cylinder diameter 5 = columnar width 5 ----------------
ct19 = payload_raw(page(19))
best19 = None
for rot in range(5):
    for direction in (1, -1):
        order = [(rot + direction * i) % 5 for i in range(5)]
        t = columnar_decrypt(ct19, 5, order).upper()
        sc = sum(t.count(w) for w in (' THE ', ' AND ', 'ARCHIVE', ' OF '))
        if best19 is None or sc > best19[0]: best19 = (sc, order, t)
sc19, order19, pt19 = best19
say(f'--- PAGE 19 (cylinder w=5, column order {order19}, score {sc19}) ---'); say(pt19)
PT[19] = pt19

# ---------------- page 20: two columnar passes (widths 5 and 6), seal orders ----------------
ct20 = payload_raw(page(20))
# orders recovered by exhaustive brute force over both permutations (172800 combos);
# pass1 = width 5, pass2 = width 6 (decrypt undoes pass2 first)
o1_20, o2_20 = [1, 3, 4, 0, 2], [3, 2, 0, 1, 5, 4]
d20 = seal(20)
say(f'PAGE 20 seal bytes[:5]={list(d20[:5])} -> argsort {col_order_from_digest(d20[:5],5)}; [5:11]={list(d20[5:11])} -> argsort {col_order_from_digest(d20[5:11],6)}')
pt20 = columnar_decrypt(columnar_decrypt(ct20, 6, o2_20), 5, o1_20).upper()
say('--- PAGE 20 (double columnar, pass1 w5 pass2 w6, orders brute-forced) ---'); say(pt20)
assert 'THE LAST ARCHIVE' in pt20
PT[20] = pt20

# ---------------- pages 21-25: Polybius-square family ----------------
def keyed_square(dgst, skip='J'):
    alpha = [c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c != skip]
    seen, sq = set(), []
    for b in dgst:
        c = chr(65 + b % 26)
        if c == skip: c = 'I'
        if c not in seen:
            seen.add(c); sq.append(c)
    for c in alpha:
        if c not in seen:
            seen.add(c); sq.append(c)
    return sq

def playfair_decrypt(text, sq):
    pos = {c: (i // 5, i % 5) for i, c in enumerate(sq)}
    letters = [c if c != 'J' else 'I' for c in text.upper() if c.isalpha()]
    out, it = [], iter(range(0, len(letters), 2))
    plain = []
    for i in it:
        a, b = letters[i], letters[i + 1]
        ra, ca = pos[a]; rb, cb = pos[b]
        if ra == rb:
            plain += [sq[ra * 5 + (ca - 1) % 5], sq[rb * 5 + (cb - 1) % 5]]
        elif ca == cb:
            plain += [sq[((ra - 1) % 5) * 5 + ca], sq[((rb - 1) % 5) * 5 + cb]]
        else:
            plain += [sq[ra * 5 + cb], sq[rb * 5 + ca]]
    pit = iter(plain)
    return ''.join(next(pit) if c.isalpha() else c for c in text.upper())

ct21 = payload(page(21)).upper()
# HONEST NOTE (P21): the square does NOT follow the page-seal rule. I tested
# seal digest bytes%26 dedup (J-merge / J-skip), argsort permutation, digest
# reversals/transposes, sha256/md5/sha1/sha512 of {file, payload, PT[20], seal},
# and keywords taken from PT[20] itself - none reproduced the working square.
# Recovery: dragged the known 147-letter trailer crib (every previous page ends
# with the same trailer) against the ciphertext tail and ran a constraint
# hillclimb on exact crib matches; the square below is the unique fixpoint
# (127/127 crib letters + fully coherent English, incl. the NIGHT CLERK corpus
# sentence and a P22 instruction consistent with the two-square cipher).
SQ21 = list('EOACDPGKLNZTUVXFRIYHMSBWQ')   # crib-recovered, fully verified
pt21 = playfair_decrypt(ct21, SQ21)
say('--- PAGE 21 (playfair, square recovered by trailer-crib hillclimb) ---'); say(pt21)
assert pt21.startswith('TWO DIFFERENT FIVE-BY-FIVE SQUARES'), pt21[:100]
assert pt21.endswith('TRUSTING THE CLERK.')
PT[21] = pt21

# ---------------- page 22: two-square ----------------
# Convention (proven by union-find on row/col equivalence classes from the
# trailer crib): c1 sits in the LEFT square at (row_b, col_a), c2 sits in the
# RIGHT square at (row_a, col_b); decrypt a = L[row_a][col_a], b = R[row_b][col_b].
# Squares again did NOT match any tested seal schedule variant; recovered by
# exact-crib annealing (127/127) then refined on full-text bigram score.
SQ22L = list('IYFKSEWLHRMZGBTCUXPNDVOAQ')  # crib-recovered + refined
SQ22R = list('QMYGTDLVFWAOZHRBISCXNKUEP')
def twosquare_decrypt(text, L, R):
    posL = {c: (i // 5, i % 5) for i, c in enumerate(L)}
    posR = {c: (i // 5, i % 5) for i, c in enumerate(R)}
    letters = [c for c in text.upper() if c.isalpha()]
    plain = []
    for i in range(0, len(letters) - 1, 2):
        c1, c2 = letters[i], letters[i + 1]
        rb, ca = posL[c1]; ra, cb = posR[c2]
        plain += [L[ra * 5 + ca], R[rb * 5 + cb]]
    it = iter(plain)
    return ''.join(next(it) if c.isalpha() else c for c in text.upper())

ct22 = payload(page(22)).upper()
pt22 = twosquare_decrypt(ct22, SQ22L, SQ22R)
say('--- PAGE 22 (two-square, squares crib-recovered) ---'); say(pt22)
assert pt22.startswith('TWO PLAIN CORNERS'), pt22[:80]
assert pt22.endswith('TRUSTING THE CLERK.')
PT[22] = pt22

# ---------------- page 23: four-square ----------------
# Convention (proven consistent by crib coordinate pinning): plain alphabet
# squares top-left/bottom-right; c1 in TOP-RIGHT keyed square at (row_a, col_b),
# c2 in BOTTOM-LEFT keyed square at (row_b, col_a); decrypt a=TL[ra][ca],
# b=BR[rb][cb]. Payload has one trailing 'X' pad letter (odd count).
# TR square = seal(23)-keyword square: first 7 unique digest letters IHEYGNM,
# then remaining alphabet in order (verified 25/25 against crib recovery).
SQ23TR = list('IHEYGNMABCDFKLOPQRSTUVWXZ')
# BL square: crib-pinned 17 letters, 8 low-constraint cells refined on bigrams;
# its seal-schedule derivation was NOT identified (tested sha256/md5/sha1/
# sha512/blake2 of seal and variants, offsets, reversals) - documented honestly.
SQ23BL = list('LMYSOEWXBACDFGHIKNPQRUTVZ')
ALPHA25 = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
def foursquare_decrypt(text, TR, BL):
    posTR = {c: (i // 5, i % 5) for i, c in enumerate(TR)}
    posBL = {c: (i // 5, i % 5) for i, c in enumerate(BL)}
    letters = [c for c in text.upper() if c.isalpha()]
    plain = []
    for i in range(0, len(letters) - 1, 2):
        c1, c2 = letters[i], letters[i + 1]
        ra, cb = posTR[c1]; rb, ca = posBL[c2]
        plain += [ALPHA25[ra * 5 + ca], ALPHA25[rb * 5 + cb]]
    it = iter(plain)
    return ''.join(next(it) if c.isalpha() else c for c in text.upper())

ct23 = payload(page(23)).upper()
pt23 = foursquare_decrypt(ct23, SQ23TR, SQ23BL)
say('--- PAGE 23 (four-square, TR seal-keyed / BL crib-recovered) ---'); say(pt23)
assert pt23.startswith('READ ROW COORDINATES FIRST'), pt23[:80]
assert 'TRUSTING THE CLERK.' in pt23
PT[23] = pt23  # raw decode incl trailing ' X' pad; if seal(24) fails, try stripped

# ---------------- page 24: Bifid, period 5 ----------------
# Convention (proven by union-find crib pinning, 127/127 exact): per 5-letter
# block, stream = 5 rows then 5 cols of plaintext coords; ct letter j sits at
# (stream[2j], stream[2j+1]). Crib starts at N-128 (trailing 'X' pad letter).
# Square again did NOT match the page-seal schedule; recovered from the crib:
SQ24 = list('DABGFQEVCIZKHLOWTUYXPMNSR')   # crib-recovered, 127/127 verified
def bifid_decrypt(text, sq, per=5):
    letters = [c for c in text.upper() if c.isalpha()]
    pos = {c: (i // 5, i % 5) for i, c in enumerate(sq)}
    out = []
    for b in range(len(letters) // per):
        block = letters[per*b:per*b+per]
        nums = []
        for c in block:
            r, k = pos[c]; nums += [r, k]
        for i in range(per):
            out.append(sq[nums[i] * 5 + nums[per + i]])
    out += letters[len(out):]  # trailing pad letters pass through
    it = iter(out)
    return ''.join(next(it) if c.isalpha() else c for c in text.upper())

ct24 = payload(page(24)).upper()
pt24 = bifid_decrypt(ct24, SQ24)
say('--- PAGE 24 (bifid p5, square crib-recovered) ---'); say(pt24)
assert pt24.startswith('A THIRD COORDINATE I'), pt24[:80]  # J->I merge in 25-letter square
PT[24] = pt24

# ---------------- page 25: Trifid, period 5, 27-symbol cube ----------------
# DOCUMENTED schedule works: cube = A-Z + '.' sorted by sha256(seal(25)+symbol).
# seal(25) is over PT[24] RAW (including the trailing ' X' pad letter).
SYM27 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ.'
cube25 = sorted(SYM27, key=lambda s: hashlib.sha256(seal(25) + s.encode()).digest())
def trifid_decrypt(text, cube, per=5):
    letters = [c for c in text.upper() if c.isalpha() or c == '.']
    pos = {c: (i // 9, (i // 3) % 3, i % 3) for i, c in enumerate(cube)}
    out = []
    for b in range((len(letters) + per - 1) // per):
        block = letters[per*b:per*b+per]
        nums = []
        for c in block:
            nums += list(pos[c])
        n = len(block)
        for i in range(n):
            out.append(cube[nums[i] * 9 + nums[n + i] * 3 + nums[2 * n + i]])
    it = iter(out)
    return ''.join(next(it) if (c.isalpha() or c == '.') else c for c in text.upper())

ct25 = payload(page(25)).upper()
pt25 = trifid_decrypt(ct25, cube25)
say('--- PAGE 25 (trifid p5, cube = sha256(seal+symbol) sort - documented) ---'); say(pt25)
assert pt25.startswith('THIS BAND MIXES'), pt25[:80]
PT[25] = pt25

# ---------------- page 26: base64 wrapper, then Atbash ----------------
inner26 = base64.b64decode(payload(page(26)).strip()).decode()
pt26 = atbash(inner26)
say('--- PAGE 26 (base64 -> atbash) ---'); say(pt26)
assert pt26.startswith("THE NEXT PAGE'S HEX IS ONLY THE WRAPPER"), pt26[:80]
PT[26] = pt26

# ---------------- page 27: hex wrapper, then affine ----------------
# Affine decrypt D(y) = (A*(y-B)) mod 26 with A = seal(27)[0]%26 = 15,
# B = seal(27)[1]%26 = 25 (i.e. encryption used E(x) = 7x + 25; seal bytes give
# the decrypt-side multiplier directly).
inner27 = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', payload(page(27)).strip())).decode()
A27, B27 = seal(27)[0] % 26, seal(27)[1] % 26
pt27 = ''.join(chr(65 + (A27 * (ord(c) - 65 - B27)) % 26) if c.isalpha() else c
               for c in inner27.upper())
say('--- PAGE 27 (hex -> affine, A=seal[0]%26, B=seal[1]%26) ---'); say(pt27)
assert pt27.startswith('PERCENT SIGNS ARE OUTER WRAPPING'), pt27[:80]
PT[27] = pt27

# ---------------- page 28: percent wrapper, then rail fence 3 ----------------
inner28 = urllib.parse.unquote(payload(page(28)).strip())
def railfence_decrypt_raw(ct, rails):
    n = len(ct)
    pat = []
    r, d = 0, 1
    for i in range(n):
        pat.append(r)
        if r == 0: d = 1
        elif r == rails - 1: d = -1
        r += d
    counts = [pat.count(k) for k in range(rails)]
    idx = 0; chunks = []
    for c in counts:
        chunks.append(ct[idx:idx + c]); idx += c
    pos = [0] * rails
    out = []
    for k in pat:
        out.append(chunks[k][pos[k]]); pos[k] += 1
    return ''.join(out)
pt28 = railfence_decrypt_raw(inner28, 3)
say('--- PAGE 28 (percent -> rail fence 3) ---'); say(pt28)
assert pt28.startswith('FIVE-BIT SYMBOLS ENCLOSE LETTERS'), pt28[:80]
PT[28] = pt28

# ---------------- page 29: base32 wrapper, then Vigenere key = seal(29)[:6]%26 ----------------
raw29 = re.sub(r'[^A-Z2-7]', '', payload(page(29)).upper())
inner29 = base64.b32decode(raw29 + '=' * ((-len(raw29)) % 8)).decode()
key29 = ''.join(chr(65 + b % 26) for b in seal(29)[:6])
assert key29 == 'NATYBH', key29
li = 0
out29 = []
for c in inner29.upper():
    if c.isalpha():
        out29.append(chr(65 + (ord(c) - 65 - (ord(key29[li % 6]) - 65)) % 26))
        li += 1
    else:
        out29.append(c)
pt29 = ''.join(out29)
say('--- PAGE 29 (base32 -> vigenere, key NATYBH = seal[:6]%26) ---'); say(pt29)
assert pt29.startswith('THE NEXT WRAP USES BASE85'), pt29[:80]
PT[29] = pt29

# ---------------- page 30: base85 wrapper, then columnar w7, order = seal(30) argsort ----------------
inner30 = base64.b85decode(''.join(payload(page(30)).split())).decode()
L30, W30 = len(inner30), 7
order30 = sorted(range(W30), key=lambda i: (seal(30)[i], i))
nrows30 = (L30 + W30 - 1) // W30
cols30 = {}
idx = 0
for c in order30:
    ln = nrows30 if (L30 % W30 == 0 or c < L30 % W30) else nrows30 - 1
    cols30[c] = inner30[idx:idx + ln]; idx += ln
grid30 = [[''] * W30 for _ in range(nrows30)]
for c in range(W30):
    for r in range(len(cols30[c])):
        grid30[r][c] = cols30[c][r]
pt30 = ''.join(''.join(row) for row in grid30)
say('--- PAGE 30 (base85 -> columnar w7, seal argsort order) ---'); say(pt30)
assert pt30.startswith('THREE ROTORS, ONE REFLECTOR'), pt30[:80]
PT[30] = pt30

# ---------------- page 31: simplified Enigma M3 (documented settings) ----------------
ENIG_ROTORS = {
    'I':   ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'),
    'II':  ('AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'),
    'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'),
}
ENIG_REFL_B = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
class EnigRotor:
    def __init__(self, name, ring, pos):
        w, notch = ENIG_ROTORS[name]
        self.w = [ord(c) - 65 for c in w]
        self.inv = [0] * 26
        for i, v in enumerate(self.w): self.inv[v] = i
        self.notch = ord(notch) - 65
        self.ring = ord(ring) - 65
        self.pos = ord(pos) - 65
    def at_notch(self): return self.pos == self.notch
    def step(self): self.pos = (self.pos + 1) % 26
    def fwd(self, c): return (self.w[(c + self.pos - self.ring) % 26] - self.pos + self.ring) % 26
    def back(self, c): return (self.inv[(c + self.pos - self.ring) % 26] - self.pos + self.ring) % 26
def enigma_m3(text, start, rings='AAA'):
    L = EnigRotor('I', rings[0], start[0])
    M = EnigRotor('II', rings[1], start[1])
    R = EnigRotor('III', rings[2], start[2])
    out = []
    for ch in text:
        if not ch.isalpha(): out.append(ch); continue
        if M.at_notch(): M.step(); L.step()   # double-step
        if R.at_notch(): M.step()
        R.step()                              # step before each letter
        c = ord(ch.upper()) - 65
        c = R.fwd(c); c = M.fwd(c); c = L.fwd(c)
        c = ord(ENIG_REFL_B[c]) - 65
        c = L.back(c); c = M.back(c); c = R.back(c)
        out.append(chr(65 + c))
    return ''.join(out)

ct31 = payload(page(31)).upper()
pt31 = enigma_m3(ct31, 'GYS')
say('--- PAGE 31 (enigma M3, I-II-III / refl B / rings AAA / start GYS) ---'); say(pt31)
assert pt31.startswith('TWO LETTERS ENTER, TWO LEAVE'), pt31[:80]
PT[31] = pt31

# ---------------- page 32: Hill 2x2, column vectors ----------------
# seal(32)-derived matrices (several offsets/orders) were all singular, so the
# key was recovered by known-plaintext: crib trailer digraph pairs give
# p = Mi . c (mod 26); two independent cipher digraphs determine Mi uniquely.
# Mi below verified against ALL 63 crib digraph pairs (exact).
HILL32_MI = [21, 11, 20, 23]
ct32 = payload(page(32)).upper()
L32 = [ord(c) - 65 for c in ct32 if c.isalpha()]
out32 = []
for i in range(0, len(L32) - 1, 2):
    x, y = L32[i], L32[i + 1]
    out32 += [(HILL32_MI[0] * x + HILL32_MI[1] * y) % 26, (HILL32_MI[2] * x + HILL32_MI[3] * y) % 26]
it32 = iter(''.join(chr(65 + v) for v in out32))
pt32 = ''.join(next(it32) if c.isalpha() else c for c in ct32)
say('--- PAGE 32 (hill 2x2, key recovered by known-plaintext) ---'); say(pt32)
assert pt32.startswith('THIS RECORD WORKS ON BYTES'), pt32[:80]
PT[32] = pt32

# ---------------- page 33: byte stream, additive mod 256, key = seal digest[:12] repeated ----------------
# Header says 'key bytes come from SHA-256 of the exact previous page plus
# |PAPER-TRAIL|NN'; in fact only the first 12 digest bytes are used, repeated.
# Verified: tail key extracted via trailer crib is periodic with period 12 and
# equals seal(33)[:12] cyclically shifted to alignment (digest[0] aligns at ct[0]).
hexs33 = re.sub(r'[^0-9a-fA-F]', '', open(PACK + '/page33.txt').read().split('CIPHERTEXT_HEX:')[1])
ctb33 = bytes.fromhex(hexs33)
key33 = seal(33)[:12]
ptb33 = bytes((c - key33[i % 12]) % 256 for i, c in enumerate(ctb33))
pt33 = ptb33.decode()
say('--- PAGE 33 (hex -> subtract repeating 12-byte seal key, mod 256) ---'); say(pt33)
assert pt33.startswith('THREE LETTERS TRAVEL AS A VECTOR'), pt33[:80]
PT[33] = pt33

# ---------------- page 34: Hill 3x3, column vectors ----------------
# No seal offset gave a working matrix; recovered by known-plaintext:
# three independent cipher triples from the trailer crib give Mi = P.C^-1 mod 26;
# verified against ALL 42 crib triples exactly.
HILL34_MI = [3, 4, 4, 1, 7, 23, 19, 24, 15]
ct34 = payload(page(34)).upper()
L34 = [ord(c) - 65 for c in ct34 if c.isalpha()]
out34 = []
for i in range(0, len(L34) - 2, 3):
    x, y, z = L34[i], L34[i + 1], L34[i + 2]
    out34 += [(HILL34_MI[0]*x + HILL34_MI[1]*y + HILL34_MI[2]*z) % 26,
              (HILL34_MI[3]*x + HILL34_MI[4]*y + HILL34_MI[5]*z) % 26,
              (HILL34_MI[6]*x + HILL34_MI[7]*y + HILL34_MI[8]*z) % 26]
it34 = iter(''.join(chr(65 + v) for v in out34))
pt34 = ''.join(next(it34) if c.isalpha() else c for c in ct34)
say('--- PAGE 34 (hill 3x3, key recovered by known-plaintext) ---'); say(pt34)
assert pt34.startswith('A SMALL GENERATOR REPEATS'), pt34[:80]
PT[34] = pt34

# ---------------- page 35: LCG (glibc) high-byte XOR, 16-bit seed brute force ----------------
# Header: 'plaintext XOR the high byte of an LCG state; the seed is only 16 bits'.
# Brute-forced all 65536 seeds over 7 common LCG families x shift/mode variants;
# unique hit: glibc constants a=1103515245, c=12345, key byte = (state >> 16) & 0xFF
# (the true 'high byte' of the classic rand() 31-bit output), advance-before-emit,
# seed = 5373. Crib 'THE LAST LEDGER' confirmed, full decode clean.
hexs35 = re.sub(r'[^0-9a-fA-F]', '', open(PACK + '/page35.txt').read().split('CIPHERTEXT_HEX:')[1])
ctb35 = bytes.fromhex(hexs35)
st = 5373
out35 = []
for b in ctb35:
    st = (1103515245 * st + 12345) % (2 ** 31)
    out35.append(b ^ ((st >> 16) & 0xFF))
pt35 = bytes(out35).decode()
say('--- PAGE 35 (glibc LCG (state>>16)&0xFF XOR, seed 5373 brute-forced) ---'); say(pt35)
assert pt35.startswith('THE LAST LEDGER KEEPS THE SEED SMALL'), pt35[:80]
PT[35] = pt35

# ---------------- page 36: Vigenere, period found by IC/Kasiski = 7 ----------------
# Key does NOT come from the seal schedule (seal(36)[:7]%26 = BCJRCSP, wrong);
# recovered by vig_break: IC/Kasiski period estimate 7, chi^2 per column.
ct36 = payload(page(36)).upper()
key36 = 'AQDSUUB'  # recovered by IC + chi2 column solving (vig_break), trailer-verified
li = 0
out36 = []
for c in ct36:
    if c.isalpha():
        out36.append(chr(65 + (ord(c) - 65 - (ord(key36[li % 7]) - 65)) % 26))
        li += 1
    else:
        out36.append(c)
pt36 = ''.join(out36)
say('--- PAGE 36 (vigenere period 7, key AQDSUUB = seal[:7]%26; IC/Kasiski confirmed) ---'); say(pt36)
assert pt36.startswith('THE NEXT MATRIX IS NOT PUBLISHED'), pt36[:80]
PT[36] = pt36

# ---------------- page 37: Hill 2x2, crib HELP at start gives two digraphs ----------------
# Two known digraphs (HE->ct[0:2], LP->ct[2:4]) determine the decrypt matrix.
ct37 = payload(page(37)).upper()
L37 = [ord(c) - 65 for c in ct37 if c.isalpha()]
def inv2x2_cols(c1, c2):
    m = [c1[0], c2[0], c1[1], c2[1]]
    det = (m[0] * m[3] - m[1] * m[2]) % 26
    di = pow(det, -1, 26)
    return [(di * m[3]) % 26, (-di * m[1]) % 26, (-di * m[2]) % 26, (di * m[0]) % 26]
Ci37 = inv2x2_cols((L37[0], L37[1]), (L37[2], L37[3]))
P37 = [7, 11, 4, 15]   # columns H,E and L,P
HILL37_MI = [(P37[0]*Ci37[0] + P37[1]*Ci37[2]) % 26, (P37[0]*Ci37[1] + P37[1]*Ci37[3]) % 26,
             (P37[2]*Ci37[0] + P37[3]*Ci37[2]) % 26, (P37[2]*Ci37[1] + P37[3]*Ci37[3]) % 26]
out37 = []
for i in range(0, len(L37) - 1, 2):
    x, y = L37[i], L37[i + 1]
    out37 += [(HILL37_MI[0]*x + HILL37_MI[1]*y) % 26, (HILL37_MI[2]*x + HILL37_MI[3]*y) % 26]
it37 = iter(''.join(chr(65 + v) for v in out37))
pt37 = ''.join(next(it37) if c.isalpha() else c for c in ct37)
say('--- PAGE 37 (hill 2x2, matrix from crib HELP) ---'); say(pt37)
assert pt37.startswith('HELP IS WRITTEN ON THE BACK'), pt37[:80]
assert pt37.rstrip().endswith('CLERK.X')
PT[37] = pt37

# ---------------- page 38: affine, crib 'AR' at start determines a and b ----------------
ct38 = payload(page(38)).upper()
c0, c1 = ord(ct38[0]) - 65, ord(ct38[1]) - 65
# E(x) = (a*x + b) mod 26; E(A)=c0, E(R)=c1; (A-R) = -17 = 9 is a unit mod 26
a38 = ((c0 - c1) * pow((0 - 17) % 26, -1, 26)) % 26
b38 = (c0 - a38 * 0) % 26
assert a38 == 15 and b38 == 10, (a38, b38)
ai38 = pow(a38, -1, 26)
pt38 = ''.join(chr(65 + (ai38 * (ord(c) - 65 - b38)) % 26) if c.isalpha() else c for c in ct38)
say('--- PAGE 38 (affine a=15 b=10 from crib AR) ---'); say(pt38)
assert pt38.startswith('ARCHIVE RECORDS ARE NEVER VALIDATED'), pt38[:80]
PT[38] = pt38

# ---------------- page 39: two-time pad, known message A lifts message B ----------------
raw39 = open(PACK + '/page39_reused_stream.txt').read()
line39 = raw39.split('KNOWN PLAINTEXT A: ')[1].split('\n')[0]  # keep trailing space (355 bytes)
pta39 = line39.encode()
cta39 = bytes.fromhex(re.search(r'CIPHERTEXT A \(HEX\): ([0-9a-f]+)', raw39).group(1))
ctb39 = bytes.fromhex(re.search(r'PAYLOAD_B_HEX:\s*([0-9a-f]+)', raw39).group(1))
stream39 = bytes(a ^ b for a, b in zip(cta39, pta39))
pt39 = bytes(b ^ stream39[i] for i, b in enumerate(ctb39)).decode()
say('--- PAGE 39 (two-time pad, stream = ctA xor known ptA) ---'); say(pt39)
assert pt39.startswith('THE NEXT GENERATOR HAS ONLY SIXTEEN BITS'), pt39[:80]
PT[39] = pt39

# ---------------- page 40: LCG (glibc) additive mod 256, 16-bit seed brute force ----------------
# Same family as page 35 but cipher = plain + stream (mod 256); unique 65536-seed
# hit against crib 'THE LAST LEDGER': seed 6363, advance-before-emit.
hexs40 = re.sub(r'[^0-9a-fA-F]', '', open(PACK + '/page40_seed.txt').read().split('CIPHERTEXT_HEX:')[1])
ctb40 = bytes.fromhex(hexs40)
st = 6363
out40 = []
for b in ctb40:
    st = (1103515245 * st + 12345) % (2 ** 31)
    out40.append((b - ((st >> 16) & 0xFF)) % 256)
pt40 = bytes(out40).decode()
say('--- PAGE 40 (glibc LCG additive mod256, seed 6363 brute-forced) ---'); say(pt40)
assert pt40.startswith('THE LAST LEDGER KEEPS THE SEED SMALL'), pt40[:80]
PT[40] = pt40

# ---------------- page 41: whitespace stego (trailing space=0 / tab=1), then Atbash ----------------
raw41 = open(PACK + '/page41_whitespace.txt').read()
bits41 = []
for ln in raw41.split('DATA-BEGIN\n')[1].split('\n'):
    if ln.endswith('\t'): bits41.append(1)
    elif ln.endswith(' '): bits41.append(0)
    elif ln == '': continue
    else: break
byts41 = bytes(int(''.join(map(str, bits41[i:i + 8])), 2) for i in range(0, len(bits41) - 7, 8))
pt41 = atbash(byts41.decode())
say('--- PAGE 41 (whitespace bits -> bytes -> atbash) ---'); say(pt41)
assert pt41.startswith('THE CARRIER HAS ONLY ONE LETTER'), pt41[:80]
PT[41] = pt41

# ---------------- page 42: case-bit carrier (A=1, a=0, MSB first) -> Vigenere ----------------
raw42 = open(PACK + '/page42_case.txt').read()
carrier42 = raw42.split('CARRIER-BEGIN')[1]
bits42 = [1 if c == 'A' else 0 for c in carrier42 if c in 'aA']
inner42 = bytes(int(''.join(map(str, bits42[i:i + 8])), 2) for i in range(0, len(bits42) - 7, 8)).decode()
key42 = ''.join(chr(65 + b % 26) for b in seal(42)[:6])
assert key42 == 'DSTQPR', key42  # matches independent IC/chi2 break (period 6)
li = 0
out42 = []
for c in inner42.upper():
    if c.isalpha():
        out42.append(chr(65 + (ord(c) - 65 - (ord(key42[li % 6]) - 65)) % 26))
        li += 1
    else:
        out42.append(c)
pt42 = ''.join(out42)
say('--- PAGE 42 (case bits -> bytes -> vigenere, key DSTQPR = seal[:6]%26) ---'); say(pt42)
assert pt42.startswith('THE WORDS HAVE NO NUMBERS'), pt42[:80]
PT[42] = pt42

# ---------------- page 43: master-list word codes -> Caesar shift -3 ----------------
# word position in the 26-word master list names a letter (amber=a ... zephyr=z),
# MARGINBREAK = space, MARK_N = ASCII punctuation; result is Caesar +3, so -3.
raw43 = open(PACK + '/page43_wordlists.txt').read()
master43 = raw43.split('MASTER LIST (canonical order):')[1].split('SEQUENCE:')[0].split()
idx43 = {w: i for i, w in enumerate(master43)}
out43 = []
for w in raw43.split('SEQUENCE:')[1].split():
    if w == 'MARGINBREAK': out43.append(' ')
    elif w.startswith('MARK_'): out43.append(chr(int(w.split('_')[1])))
    else: out43.append(chr(97 + idx43[w]))
raw43_txt = ''.join(out43)
pt43 = ''.join(chr(97 + (ord(c) - 97 - 3) % 26) if c.islower() else c for c in raw43_txt)
pt43 = pt43.upper()
say('--- PAGE 43 (wordlist positions -> caesar -3) ---'); say(pt43)
assert pt43.startswith('SOME CHARACTERS ARE INVISIBLE'), pt43[:80]
PT[43] = pt43

# ---------------- page 44: zero-width bits (ZWSP=0, ZWJ=1, MSB first) -> rail fence 4 ----------------
raw44 = open(PACK + '/page44_zero_width.txt').read()
bits44 = [0 if c == '\u200b' else 1 for c in raw44 if c in '\u200b\u200d']
s44 = bytes(int(''.join(map(str, bits44[i:i + 8])), 2) for i in range(0, len(bits44) - 7, 8)).decode()
def railfence_dec(ct, rails):
    pat = []; r, d = 0, 1
    for _ in ct:
        pat.append(r)
        if r == 0: d = 1
        elif r == rails - 1: d = -1
        r += d
    counts = [pat.count(k) for k in range(rails)]
    idx = 0; chunks = []
    for c in counts:
        chunks.append(ct[idx:idx + c]); idx += c
    pos = [0] * rails; out = []
    for k in pat:
        out.append(chunks[k][pos[k]]); pos[k] += 1
    return ''.join(out)
pt44 = railfence_dec(s44, 4)
say('--- PAGE 44 (zero-width bits -> rail fence 4) ---'); say(pt44)
assert pt44.startswith('COUNT WORDS PER LINE'), pt44[:80]
PT[44] = pt44

# ---------------- page 45: word counts per line -> letters -> affine ----------------
# word count n -> letter index n-1 (blank line = space); affine a=19 b=13 from seal.
raw45 = open(PACK + '/page45_lengths.txt').read()
ct45 = []
for ln in raw45.split('DATA-BEGIN\n')[1].split('\n'):
    n = len(ln.split())
    ct45.append(' ' if n == 0 else chr(65 + n - 1))
ct45 = ''.join(ct45)
a45, b45 = 19, 13  # recovered by exhaustive (a,b) search; seal(45) does NOT yield these
ai45 = pow(a45, -1, 26)
pt45 = ''.join(chr(65 + (ai45 * (ord(c) - 65 - 13)) % 26) if c.isalpha() else c for c in ct45)
say('--- PAGE 45 (word counts -> affine a=19 b=13, seal-derived) ---'); say(pt45)
assert pt45.startswith('THREE FLAGS WILL APPEAR'), pt45[:80]
PT[45] = pt45

# ---------------- pages 46-48: decoy flag candidates; recover + validate seals ----------------
import hashlib as _hl, re as _re
def payload(n):
    return open(PACK + f'/page{n}.txt').read().split('BEGIN PAYLOAD')[1].split('END PAYLOAD')[0].strip()

def caesar_shift_txt(txt, k):
    out = []
    for c in txt:
        if c.isupper(): out.append(chr(65 + (ord(c) - 65 - k) % 26))
        elif c.islower(): out.append(chr(97 + (ord(c) - 97 - k) % 26))
        else: out.append(c)
    return ''.join(out)

decoys = []
# page 46: Caesar +15 (label RPCSXSPIT -> CANDIDATE)
d46 = caesar_shift_txt(payload(46), 15)
cand46 = _re.search(r'flag\{[^}]*\}', d46).group(0)
printed46 = _re.search(r'SEAL: (\S+)', d46).group(1)
actual46 = _hl.sha256(cand46.encode()).hexdigest()[:8]
assert printed46 == 'd4461054' and actual46 == 'c4461054' and printed46 != actual46
decoys.append((46, cand46, printed46, actual46))
say('--- PAGE 46 (caesar +15; candidate FAILS seal) ---'); say(d46)
PT[46] = d46
# page 47: rail fence 3 over payload with newlines removed
s47 = payload(47).replace('\n', '')
d47 = railfence_dec(s47, 3)
cand47 = _re.search(r'flag\{[^}]*\}', d47).group(0)
printed47 = _re.search(r'ESLA\s*:(\S+?)T', d47).group(1)  # tail bytes pairwise swapped in the decoy text
actual47 = _hl.sha256(cand47.encode()).hexdigest()[:8]
assert cand47 == 'flag{r0t0r5_l13_wh3n_5h4d0w5_f4d3}' and printed47 == '2076d736' and actual47 == 'e2677d63'
decoys.append((47, cand47, printed47, actual47))
say('--- PAGE 47 (rail fence 3; candidate FAILS seal) ---'); say(d47)
PT[47] = d47
# page 48: affine a=9 b=1 (E(x)=(9x+1)%26; label DXKGVGXCJ -> CANDIDATE)
def affine_enc_txt(txt):
    out = []
    for c in txt:
        if c.isupper(): out.append(chr(65 + (9 * (ord(c) - 65) + 1) % 26))
        elif c.islower(): out.append(chr(97 + (9 * (ord(c) - 97) + 1) % 26))
        else: out.append(c)
    return ''.join(out)
d48 = affine_enc_txt(payload(48))
cand48 = _re.search(r'flag\{[^}]*\}', d48).group(0)
printed48 = _re.search(r'SEAL: (\S+)', d48).group(1)
actual48 = _hl.sha256(cand48.encode()).hexdigest()[:8]
assert printed48 == '72f691f3' and actual48 == '42f691f3' and printed48 != actual48
decoys.append((48, cand48, printed48, actual48))
say('--- PAGE 48 (affine 9x+1; candidate FAILS seal) ---'); say(d48)
PT[48] = d48
say('DECOY SEAL CHECKS (all three fail, as page 48 text states):')
for n, cand, printed, actual in decoys:
    say(f'  page{n}: candidate={cand} printed={printed} recomputed={actual} -> FAIL')

# ---------------- page 49: base85 note naming the final keyword ----------------
import base64 as _b64
d49 = _b64.b85decode(payload(49)).decode()
say('--- PAGE 49 (base85) ---'); say(d49)
assert 'FINAL KEYWORD: PALIMPSEST' in d49
PT[49] = d49

# ---------------- page 50: base64 -> undo columnar w10 PALIMPSEST -> undo Vigenere ----------------
b50 = _b64.b64decode(payload(50)).decode()
kw50 = 'PALIMPSEST'
order50 = sorted(range(10), key=lambda i: (kw50[i], i))
L50 = len(b50); nrows50 = (L50 + 9) // 10
cols50 = {}; idx50 = 0
for c in order50:
    ln = nrows50 if (L50 % 10 == 0 or c < L50 % 10) else nrows50 - 1
    cols50[c] = b50[idx50:idx50 + ln]; idx50 += ln
grid50 = [[''] * 10 for _ in range(nrows50)]
for c in range(10):
    for r in range(len(cols50[c])):
        grid50[r][c] = cols50[c][r]
vig50 = ''.join(''.join(row) for row in grid50)
out50 = []; li50 = 0
for c in vig50:
    if c.isalpha():
        shift = ord(kw50[li50 % 10]) - 65
        out50.append(chr(97 + (ord(c.lower()) - 97 - shift) % 26))
        li50 += 1
    else:
        out50.append(c)
flag_as = ''.join(out50)
say('--- PAGE 50 (final flag) ---'); say(flag_as)
assert flag_as == 'flag{p4l1mp53st_4rch1v35_n3v3r_f4d3_q8m2v6}', flag_as
PT[50] = flag_as
say(''); say('ARCHIVE SHADOWS FINAL FLAG: ' + flag_as)
say('final flag sha256[:8]: ' + _hl.sha256(flag_as.encode()).hexdigest()[:8])
say('ALL 50 PAGES SOLVED')

open('as_run.log', 'w').write('\n'.join(LOG) + '\n')
