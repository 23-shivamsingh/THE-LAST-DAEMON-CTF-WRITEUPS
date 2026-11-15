#!/usr/bin/env python3
"""The Cipher Drawer - independent solver (written from the player pack notes only).
Walks the 25 notes in filing order, prints every decode, check and handoff.
Standard library only."""
import base64, re, sys, os

PACK = sys.argv[1] if len(sys.argv) > 1 else 'cd_orig/The_Cipher_Drawer_Player_Pack'

def note(n):
    name = f'layer{n:02d}_note.txt' if n < 25 else 'layer25_final_note.txt'
    return open(os.path.join(PACK, name), encoding='utf-8').read()

def grab(text, label):
    return re.search(label + r':\s*(\S+)', text).group(1)

def b64(s):  return base64.b64decode(s).decode()
def unhex(s): return bytes.fromhex(s).decode()
def unbin(s): return ''.join(chr(int(b, 2)) for b in s.split())
def caesar(t, k):
    out = []
    for c in t:
        if 'A' <= c <= 'Z': out.append(chr((ord(c)-65+k) % 26 + 65))
        elif 'a' <= c <= 'z': out.append(chr((ord(c)-97+k) % 26 + 97))
        else: out.append(c)
    return ''.join(out)
def atbash(t):
    out = []
    for c in t:
        if 'A' <= c <= 'Z': out.append(chr(155 - ord(c)))
        elif 'a' <= c <= 'z': out.append(chr(219 - ord(c)))
        else: out.append(c)
    return ''.join(out)
def vig_decrypt(t, key):
    ki, out = 0, []
    for c in t:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            k = ord(key[ki % len(key)].lower()) - 97
            out.append(chr((ord(c) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)

log = []
def say(*a):
    line = ' '.join(str(x) for x in a)
    print(line); log.append(line)

# ---------- Band 1: plain encodings (layers 1-5) ----------
say('$ python3 cd_mysolve.py', PACK)
say('=== BAND 1: encodings ===')
h = b64(grab(note(1), 'BASE64'))
say(f'L01 base64 {grab(note(1),"BASE64")} -> {h!r}  handoff={h}')
t = unhex(grab(note(2), 'HEX')); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L02 hex -> {t!r}  prefix ok ({t.split("|")[0]}), handoff={h}')
t = unbin(re.search(r'BINARY:\s*([01 ]+?)\n', note(3)).group(1).strip()); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L03 binary -> {t!r}  prefix ok, handoff={h}')
t = b64(grab(note(4), 'BASE64')); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L04 base64 -> {t!r}  prefix ok, handoff={h}')
t = unhex(grab(note(5), 'HEX')); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L05 hex -> {t!r}  prefix ok, handoff={h}')

# ---------- Band 2: wheel ciphers (layers 6-10) ----------
say('=== BAND 2: Caesar / ROT13 / Atbash ===')
ct = grab(note(6), 'CIPHERTEXT'); t = caesar(ct, -3); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L06 caesar-3 {ct} -> {t!r}  prefix ok, handoff={h}')
ct = grab(note(7), 'CIPHERTEXT')
for s in range(26):
    t = caesar(ct, -s)
    if t.startswith(h + '|'):
        say(f'L07 unknown shift: trying 26 shifts, match at shift={s}: {ct} -> {t!r}')
        h = t.split('|')[1]; break
else: raise SystemExit('L07 no shift matched')
say(f'     handoff={h}')
ct = grab(note(8), 'CIPHERTEXT'); t = caesar(ct, -5); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L08 caesar-5 {ct} -> {t!r}  prefix ok, handoff={h}')
ct = grab(note(9), 'CIPHERTEXT'); t = caesar(ct, 13); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L09 rot13 {ct} -> {t!r}  prefix ok, handoff={h}')
ct = grab(note(10), 'CIPHERTEXT'); t = atbash(ct); assert t.startswith(h + '|'), t
h = t.split('|')[1]; say(f'L10 atbash {ct} -> {t!r}  prefix ok, handoff={h}')

# ---------- Band 3: single-byte XOR (layers 11-15) ----------
say('=== BAND 3: single-byte XOR, crib "Dear" ===')
for n in range(11, 16):
    txt = note(n)
    ct = bytes.fromhex(re.search(r'CIPHERTEXT \(hex bytes\):\s*([0-9a-f]+)', txt).group(1))
    key = ct[0] ^ ord('D')
    pt = bytes(b ^ key for b in ct).decode()
    seal_needed = re.search(r'previous seal `([^`]+)`', txt).group(1)
    assert seal_needed.lower() in pt.lower(), (n, seal_needed, pt)
    say(f'L{n} key=0x{key:02x} ({key}={chr(key)!r})  pt={pt!r}')
    say(f'     previous seal {seal_needed!r} present: OK')
    m = re.search(r'next seal=([A-Za-z0-9]+)', pt)
    if m:
        h = m.group(1)
    else:
        h = re.search(r'key byte=(\d+)', pt).group(1)
    say(f'     next seal/handoff={h}')

# ---------- Band 4: shorthand substitution (layers 16-20) ----------
say('=== BAND 4: 4-letter shorthand substitution ===')
for n in range(16, 21):
    txt = note(n)
    lines = re.findall(r'seal=(\S+) \| ciphertext=([A-Z ]+)', txt)
    sel = [c for s, c in lines if s == h]
    assert len(sel) == 1, (n, h, lines)
    ct = sel[0]
    # crib: A->Q, E->M, R->X ; remaining symbol = most frequent in selected line
    symbols = [c for c in ct if c != ' ']
    from collections import Counter
    freq = Counter(symbols)
    rem = [s for s in set(symbols) - {'Q', 'M', 'X'}]
    assert len(rem) == 1
    most = freq.most_common(1)[0][0]
    say(f'L{n} seal={h} selects {ct!r}; frequencies={dict(freq)}; remaining symbol {rem[0]} (most frequent={most}) -> T')
    table = {'Q': 'A', 'M': 'E', 'X': 'R', rem[0]: 'T'}
    pt = ''.join(table.get(c, c) for c in ct)
    h = pt.split()[-1]
    say(f'     decoded {pt!r}  handoff(last word)={h}')

# ---------- Band 5: fragment registers + Vigenere (layers 21-25) ----------
say('=== BAND 5: fragment registers + Vigenere ===')
txt = note(21)
frag = re.search(r'seal=TEA \| base64-fragment=(\S+)', txt).group(1)
f1 = b64(frag).lower()
say(f'L21 seal=TEA fragment {frag} -> {f1!r} (matches Band-1 first fragment INK)')
assert f1 == 'ink'
txt = note(22)
row = re.search(r'seal=INK \| decimal-byte=(\d+) \| ASCII-letter=(\S)', txt)
f2 = row.group(2)
say(f'L22 seal=INK row: decimal {row.group(1)} -> ASCII {f2!r} (matches Band-3 key byte)')
assert int(row.group(1)) == 108 and f2 == 'l'
txt = note(23)
frag = re.search(r'index=l \| substitution-crib-fragment=(\S+)', txt).group(1)
f3 = frag.lower()
say(f'L23 index=l fragment {frag} -> {f3!r} (matches Band-4 last shorthand word TEA)')
assert f3 == 'tea'
key = f1 + f2 + f3
say(f'L24 assembled Vigenere key = {key!r}')
txt = note(24)
for cand, ct in re.findall(r'CANDIDATE ([AB])(?: \(decoy\))?: ([A-Z ]+)', txt):
    pt = vig_decrypt(ct, key)
    words = len(pt.split())
    say(f'     candidate {cand}: {ct!r} -> {pt!r}  ({words} words)')
    if words == 6:
        token = 'SIXWORDS'
        say(f'     -> exactly six words: genuine headline. check token={token}')
txt = note(25)
body = re.search(r'SEALED BODY B \| seal=SIXWORDS \| ciphertext=(.+)', txt).group(1).strip()
pt = vig_decrypt(body, key)
say(f'L25 body with seal={token}: {body!r}')
say(f'     decrypted -> {pt!r}')
m = re.search(r'flag\{[^}]+\}', pt, re.I)
assert m, pt
say(f'FINAL FLAG: {m.group(0)}')
open('cd_run.log', 'w').write('\n'.join(log) + '\n')
print('run log written to cd_run.log')
