#!/usr/bin/env python3
"""My own solver for 'The Unredacted Record' (UNWRAPD CASE FILE), 150 layers.
Wrapper spec from evidence/shared/wrap_protocol.txt (re-implemented):
  M = 'UNWRAPD-WRAP-v1|' + '|'.join(input tokens) + '|' + salt ; K = SHA256(M)
  keystream = SHA256(K || salt || uint32be(counter)) blocks; plaintext = ct XOR keystream.
Verification is mine too: decoy layers are selected by SHA-256 of the raw candidate ciphertext
against evidence/shared/decoy_hash_ledger.csv (+ observed_at cross-check); every 15th layer is
verified against pausepoints.csv (SHA-256 of the recovered token); a wrong token breaks the next
layer's decryption. Extraction uses my own parsers per carrier format."""
import base64, csv, email, gzip, hashlib, json, plistlib, re, sqlite3, struct, tarfile, zipfile, io
from pathlib import Path
from xml.etree import ElementTree as ET
from PIL import Image

PLAYER = Path('/tmp/f7/orig/PLAYER')

def find_envelope(data):
    text = data.decode('utf-8', 'ignore') if isinstance(data, bytes) else data
    dec = json.JSONDecoder()
    for m in re.finditer(r'\{', text):
        try: v, _ = dec.raw_decode(text[m.start():])
        except ValueError: continue
        if isinstance(v, dict):
            if isinstance(v.get('candidates'), list) and v['candidates']: return v['candidates']
            if isinstance(v.get('candidate'), dict): return [v['candidate']]
    return None

def b64_marker(data):
    t = data.decode('latin1', 'ignore') if isinstance(data, bytes) else data
    m = re.search(r'UNWRAPD[-_]RECORDS[-_]B64[:=]([A-Za-z0-9+/=]+)', t)
    if m: return find_envelope(base64.b64decode(m.group(1)))
    return None

# ---------- genuine binary-format parsers (my own) ----------
def parse_fat12(path):
    d = path.read_bytes()
    bps = struct.unpack('<H', d[11:13])[0]; spc = d[13]
    nfats = d[16]; rootn = struct.unpack('<H', d[17:19])[0]
    spf = struct.unpack('<H', d[22:24])[0]
    root_off = (1 + nfats * spf) * bps
    data_off = root_off + rootn * 32
    fat = d[bps:bps + spf * bps]
    def chain(c0):
        out = []; c = c0
        while 2 <= c < 0xFF8:
            out.append(c)
            i = c + c // 2
            v = fat[i] | (fat[i+1] << 8)
            c = (v >> 4) if (c & 1) else (v & 0xFFF)
        return out
    def read_file(c0, size):
        b = b''.join(d[data_off + (c-2)*spc*bps : data_off + (c-1)*spc*bps] for c in chain(c0))
        return b[:size]
    found = []
    for i in range(rootn):
        e = d[root_off + i*32 : root_off + (i+1)*32]
        if e[0] == 0x00: break
        if e[0] == 0xE5:  # deleted entry
            name = e[1:11].decode('ascii', 'replace'); ext = e[8:11].decode('ascii','replace')
            c0 = struct.unpack('<H', e[26:28])[0]; size = struct.unpack('<I', e[28:32])[0]
            found.append((name, read_file(c0, size)))
    return found

def parse_jpeg_comments(path):
    d = path.read_bytes(); assert d[:2] == b'\xff\xd8'
    i = 2; coms = []
    while i + 4 <= len(d):
        if d[i] != 0xFF: break
        m = d[i+1]
        if m in (0xD8, 0xD9): i += 2; continue
        if m == 0xDA: break
        ln = struct.unpack('>H', d[i+2:i+4])[0]
        if m == 0xFE: coms.append(d[i+4:i+2+ln])
        i += 2 + ln
    return coms

def parse_pcap_payloads(path):
    d = path.read_bytes()
    magic = struct.unpack('<I', d[:4])[0]; assert magic == 0xa1b2c3d4
    off = 24; streams = {}; udp = []
    while off + 16 <= len(d):
        _, _, incl, _ = struct.unpack('<IIII', d[off:off+16]); p = d[off+16:off+16+incl]; off += 16 + incl
        if len(p) < 14 or p[12:14] != b'\x08\x00': continue
        ihl = (p[14] & 0x0f) * 4; proto = p[14+9]
        src = '.'.join(map(str, p[14+12:14+16])); dst = '.'.join(map(str, p[14+16:14+20]))
        if proto == 6:
            sport, dport, seq = struct.unpack('>HHI', p[14+ihl:14+ihl+8])
            doff = (p[14+ihl+12] >> 4) * 4
            pay = p[14+ihl+doff:]
            if pay: streams.setdefault((src, sport, dst, dport), []).append((seq, pay))
        elif proto == 17:
            ulen = struct.unpack('>H', p[14+ihl+4:14+ihl+6])[0]
            udp.append(p[14+ihl+8:14+ihl+ulen])
    out = [b''.join(pay for _, pay in sorted(v)) for v in streams.values()]
    out += udp
    return out

def png_lsb(path):
    im = Image.open(path).convert('RGB')
    px = list(im.getdata())
    bits = [c & 1 for p in px for c in p]
    packed = bytes(sum(bits[i+j] << (7-j) for j in range(8)) for i in range(0, len(bits)-7, 8))
    n = int.from_bytes(packed[:4], 'big')
    assert 0 < n <= len(packed) - 4, n
    return packed[4:4+n]

def csv_rows(path):
    lines = [l for l in path.read_text().splitlines() if not l.startswith('#')]
    return [dict(rid=r.get('record_id') or r.get('rid'), salt=r['salt'], ciphertext=r['ciphertext'],
                 observed_at=r.get('observed_at')) for r in csv.DictReader(lines)]

# ---------- candidate extraction per format ----------
def extract(layer):
    n = layer['layer']; kind = layer['format']; f = PLAYER / layer['artifact']
    if kind == 'fat12':
        for name, content in parse_fat12(f):
            r = find_envelope(content)
            if r: return r
        raise ValueError('fat12: no envelope in deleted entries')
    if kind == 'png': return find_envelope(png_lsb(f))
    if kind == 'jpg':
        for c in parse_jpeg_comments(f):
            r = find_envelope(c) or b64_marker(c)
            if r: return r
        raise ValueError('jpg: no envelope in COM segments')
    if kind == 'zip':
        with zipfile.ZipFile(f) as z:
            assert z.testzip() is None
            for name in z.namelist():
                r = find_envelope(z.read(name)) or b64_marker(z.read(name))
                if r: return r
        c = find_envelope(z.comment)
        if c: return c
        raise ValueError('zip: no envelope')
    if kind == 'tar':
        with tarfile.open(f) as t:
            for m in t.getmembers():
                if m.isfile():
                    b = t.extractfile(m).read()
                    r = find_envelope(b) or b64_marker(b)
                    if r: return r
        raise ValueError('tar: no envelope')
    if kind == 'gzip': return find_envelope(gzip.decompress(f.read_bytes())) or b64_marker(gzip.decompress(f.read_bytes()))
    if kind == 'sqlite':
        con = sqlite3.connect(f)
        rows = con.execute('SELECT rid, salt, ciphertext, observed_at FROM candidate_records').fetchall()
        con.close()
        return [dict(zip(('rid','salt','ciphertext','observed_at'), r)) for r in rows]
    if kind == 'plist': return plistlib.loads(f.read_bytes())['Candidates']
    if kind == 'jsonl':
        return [r for l in f.read_text().splitlines() if (r := json.loads(l)).get('event') == 'candidate_record']
    if kind in ('eventxml', 'xml'):
        root = ET.fromstring(f.read_bytes())
        return [dict(rid=e.findtext('./System/EventRecordID'),
                     **{fd.get('Name').lower(): fd.text for fd in e.findall('./EventData/Data')})
                for e in root.findall('.//Event')]
    if kind == 'registry_reg':
        return [dict(rid=rid, salt=salt, ciphertext=ct) for rid, salt, ct in
                re.findall(r'"Blob_(ev-[^" ]+)"="([0-9a-f]+)\|([0-9a-f]+)"', f.read_text())]
    if kind == 'eml':
        pay = email.message_from_bytes(f.read_bytes()).get_payload(decode=True)
        return find_envelope(pay) or b64_marker(pay) or find_envelope(f.read_bytes())
    if kind in ('csv',) or kind.endswith('_csv') or kind in ('timeline_csv','dns_csv','hashledger_csv','process_csv','socket_csv','sms_csv'):
        return csv_rows(f)
    if kind == 'pcap':
        for payload in parse_pcap_payloads(f):
            r = find_envelope(payload) or b64_marker(payload)
            if r: return r
        r = find_envelope(f.read_bytes())
        if r: return r
        raise ValueError('pcap: no envelope')
    data = f.read_bytes()
    r = b64_marker(data) or find_envelope(data)
    if r: return r
    # json-family: direct candidates key
    try:
        v = json.loads(data)
        if isinstance(v, dict) and v.get('candidates'): return v['candidates']
    except Exception: pass
    raise ValueError(f'L{n:03}: cannot extract candidates ({kind})')

def unwrap(cand, dep_tokens):
    salt = cand['salt']; ct = bytes.fromhex(cand['ciphertext'])
    key = hashlib.sha256(('UNWRAPD-WRAP-v1|' + '|'.join(dep_tokens) + '|' + salt).encode()).digest()
    s = bytearray(); c = 0
    while len(s) < len(ct):
        s.extend(hashlib.sha256(key + salt.encode() + struct.pack('>I', c)).digest()); c += 1
    return bytes(a ^ b for a, b in zip(ct, s))

# ---------- integrity ----------
ok = 0
for line in (PLAYER/'SHA256SUMS.txt').read_text().splitlines():
    if not line.strip(): continue
    want, rel = line.split(maxsplit=1)
    assert hashlib.sha256((PLAYER/rel.strip()).read_bytes()).hexdigest() == want, rel
    ok += 1
print(f'Integrity verified: {ok} SHA-256 file checks')

manifest = json.loads((PLAYER/'layer_manifest.json').read_text())
ledger = {int(r['layer']): r for r in csv.DictReader((PLAYER/'evidence/shared/decoy_hash_ledger.csv').open())}
checks = {int(r['layer']): r['token_sha256'] for r in csv.DictReader((PLAYER/'pausepoints.csv').open())}

tokens = {}; out = []
for layer in manifest:
    n = layer['layer']
    deps = ['CASE-OPEN-UNWRAPD-17' if d == 'INIT' else tokens[d] for d in layer['deps']]
    cands = extract(layer)
    if n in ledger:
        sel = [c for c in cands if hashlib.sha256(bytes.fromhex(c['ciphertext'])).hexdigest() == ledger[n]['expected_ciphertext_sha256']]
        assert len(sel) == 1, (n, len(sel))
        cand = sel[0]
        if cand.get('observed_at'):
            assert cand['observed_at'] == ledger[n]['expected_observed_at'], n
        decoy = True
    else:
        assert len(cands) == 1, (n, len(cands))
        cand = cands[0]; decoy = False
    plain = unwrap(cand, deps)
    tok = plain.decode('utf-8')
    tokens[n] = tok
    note = ''
    if n in checks:
        vb = json.loads(tok)['flag'].encode() if n == 150 else plain
        dg = hashlib.sha256(vb).hexdigest()
        assert dg == checks[n], (n, dg)
        note = f'PAUSEPOINT PASS {dg[:16]}...'
    out.append({'layer': n, 'format': layer['format'], 'rid': cand.get('rid'), 'token': tok,
                'decoy_resolved': decoy, 'checkpoint': bool(note)})
    print(f"L{n:03d} {tok[:60]}{'...' if len(tok)>60 else ''} [{layer['format']}{'; decoy-ledger selected' if decoy else ''}{'; ' + note if note else ''}]")

json.dump(out, open('/tmp/f7/my_unwrapd.json', 'w'), indent=1)
rep = json.loads(tokens[150])
print('FINAL FLAG:', rep['flag'])
print('FLAG SHA256:', hashlib.sha256(rep['flag'].encode()).hexdigest())
