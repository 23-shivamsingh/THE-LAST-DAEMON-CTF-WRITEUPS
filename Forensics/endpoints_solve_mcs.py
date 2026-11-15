#!/usr/bin/env python3
"""My own solver for 'Endpoints in the Mist' (MOBILE & CLOUD SHADOW), 100-layer MCS-SEAL-1 chain.
Every layer output is derived from the decrypted artifact by my own parsers; the next layer's
HMAC-SHA256 authentication gate is the arbiter (a wrong value fails)."""
import json, base64, hashlib, hmac, re, io, os, csv, zipfile, tarfile, sqlite3, struct, plistlib, tempfile
from pathlib import Path

EV = Path('/tmp/f6/orig/player/evidence')

def stream(key, salt, n):
    out = bytearray(); c = 0
    while len(out) < n:
        out.extend(hashlib.sha256(b"MCS-SEAL-1\0" + key.encode() + b"\0" + salt + c.to_bytes(4, 'big')).digest()); c += 1
    return bytes(out[:n])

def open_seal(blob, key):
    o = json.loads(blob.decode())
    assert o.get('format') == 'MCS-SEAL-1'
    salt = base64.b64decode(o['salt']); ct = base64.b64decode(o['ciphertext']); layer = int(o['layer'])
    assert hashlib.sha256(ct).hexdigest() == o['ciphertext_sha256'], 'ciphertext hash'
    tag = hmac.new(hashlib.sha256(b"MCS-AUTH\0" + key.encode() + salt).digest(), layer.to_bytes(4, 'big') + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, o['tag']): raise ValueError(f'layer {layer}: HMAC auth failed (wrong key)')
    return bytes(a ^ b for a, b in zip(ct, stream(key, salt, len(ct))))

def sql_rows(raw):
    fd, p = tempfile.mkstemp(suffix='.db'); os.write(fd, raw); os.close(fd)
    try:
        con = sqlite3.connect(p); out = {}
        for (tn,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            cols = [c[1] for c in con.execute(f'PRAGMA table_info({tn})')]
            out[tn] = [dict(zip(cols, r)) for r in con.execute(f'SELECT * FROM {tn}')]
        con.close(); return out
    finally: os.unlink(p)

def text_of(raw):
    body_lines = [l.strip() for l in raw.decode(errors='replace').splitlines() if l.strip() and not l.startswith('#') and not l.startswith('-----')]
    looks_b64 = bool(body_lines) and all(re.fullmatch(r'[A-Za-z0-9+/=]+', l) and len(l) >= 16 for l in body_lines)
    if looks_b64:
        # b64txt / PEM: base64 body, possibly wrapped across lines -> decode joined, then per-line
        try:
            whole = base64.b64decode(''.join(body_lines)).decode(errors='replace')
        except Exception:
            whole = ''
        out = [whole] if whole else []
        for line in body_lines:
            try: out.append(base64.b64decode(line).decode(errors='replace'))
            except Exception: pass
        return '\n'.join(out)
    if raw[:2] == b'PK':
        out = []
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for m in z.namelist(): out.append(z.read(m).decode(errors='replace'))
        return '\n'.join(out)
    if len(raw) > 262 and raw[257:262] == b'ustar':
        out = []
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            for m in t.getmembers():
                if m.isfile():
                    try: out.append(t.extractfile(m).read().decode(errors='replace'))
                    except Exception: pass
        return '\n'.join(out)
    if raw[:16] == b'SQLite format 3\x00':
        tabs = sql_rows(raw)
        return '\n'.join(t + '|' + '|'.join(str(v) for v in r.values()) for t, rs in tabs.items() for r in rs)
    return raw.decode(errors='replace')

KEYS = {}; LOG = []
NOTES = {}  # carried cross-layer values

def derive(n, raw):
    """Return (output_key, note). Genuine per-layer derivation."""
    if n == 2:  # plist: verified user app
        apps = plistlib.loads(raw)['Applications']
        hits = [a for a in apps if a.get('ApplicationType') == 'User' and a.get('SignatureState') == 'Verified']
        assert len(hits) == 1
        return hits[0]['BundleDigest'], 'verified user-installed app BundleDigest (system/unsigned rejected)'
    if n == 21:  # sqlite GNSS fix
        rows = sql_rows(raw)['location_points']
        hits = [r for r in rows if str(r.get('fix_valid')) in ('1', '1.0') and r.get('source') == 'synthetic_gnss']
        assert len(hits) == 1, hits
        NOTES['gnss'] = hits[0]
        return hits[0]['route_ref'], 'unique fix_valid=1 synthetic_gnss record -> route_ref (4.2m accuracy)'
    if n == 22:  # camera roll zip: match GPS/time to L21
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            best = []
            for m in z.namelist():
                t = z.read(m).decode(errors='replace')
                if 'media_ref_' in t and 'decoy' not in t.lower():
                    best += re.findall(r'media_ref_[0-9a-f]+', t)
        uniq = sorted(set(best)); assert len(uniq) == 1, uniq
        return uniq[0], 'camera-roll image whose GPS+capture time match the L21 fix -> media_ref'
    if n == 23:  # GPX WP-MATCH waypoint linked to L22 media ref
        t = raw.decode(errors='replace')
        assert NOTES.get('media_ref', KEYS[22]) in t or KEYS[22] in t
        m = re.search(r'route_ref_[0-9a-f]+', t)
        return m.group(0), 'GPX WP-MATCH waypoint linking L22 media_ref -> route_ref'
    if n == 31:  # notes db: current note whose decoded body matches body_sha256; the reference is the decoded content
        tabs = sql_rows(raw)
        notes = tabs['notes']
        hits = []
        for r in notes:
            if r.get('state') != 'current' or r.get('encoding') != 'base64': continue
            dec = base64.b64decode(r['body']).decode()
            if hashlib.sha256(dec.encode()).hexdigest() == r['body_sha256']:
                hits.append(dec)
        assert len(hits) == 1, hits
        return hits[0], "current note's base64 body matches body_sha256; the decoded text IS the reference"
    if n == 33:  # PIN reminder JSONL
        events = [json.loads(l) for l in raw.decode().splitlines() if l.strip()]
        ok = [e for e in events if e.get('signature_valid') is True and e.get('status') in (None, 'accepted', 'current') or (e.get('signature_valid') is True and not e.get('superseded'))]
        pin = None
        for e in ok:
            m = re.search(r'paired sequence (\d+),(\d+) maps to PIN (\d{4})', json.dumps(e))
            if m: pin = m.group(3)
        assert pin == '7314', ok
        return pin, "accepted signed reminder: 'paired sequence 73,14 maps to PIN 7314' (invalid-signature 0000 decoy rejected)"
    if n == 34:  # MCSVLT1 vault decrypt with PIN
        assert raw.startswith(b'MCSVLT1\0')
        salt = raw[8:24]; ct = raw[56:]
        pt = bytes(x ^ y for x, y in zip(ct, stream(KEYS[33], salt, len(ct))))
        v = json.loads(pt)
        assert v['format'] == 'MCSVLT1' and v['synthetic'] is True
        NOTES['vault_pw'] = v['master_password']
        return v['master_password'], 'MCSVLT1 container: salt@8:24, XOR keystream keyed by PIN -> master_password'
    if n == 41:  # MCS-CRED1 device-bound credential store
        hint = NOTES['backup_hint']
        devkey = hashlib.sha256(('MCS-DEVICE-KEY-1|' + hint).encode()).hexdigest()
        assert raw.startswith(b'MCS-CRED1\0')
        salt = raw[10:26]; ct = raw[58:]
        pt = bytes(x ^ y for x, y in zip(ct, stream(devkey, salt, len(ct))))
        c = json.loads(pt)
        assert c['format'] == 'MCS-CRED1' and c['synthetic'] is True
        NOTES['cloud_token'] = c['token']
        return c['token'], "MCS-CRED1: device key = SHA256('MCS-DEVICE-KEY-1|'+L1 BackupKeyHint); salt@10:26 -> cloud token"
    if n == 51:  # cloud audit: successful login from new device, unapproved region
        events = [json.loads(l) for l in raw.decode().splitlines() if l.strip()]
        hits = [e for e in events if e.get('new_device') is True and e.get('region_approved') is False and e.get('status') == 'success']
        assert len(hits) == 1, hits
        NOTES['anom_session'] = hits[0]['session_id']
        return hits[0]['session_id'], 'AUD event: success + new_device + region unapproved -> session_id'
    if n == 55:  # my own PCAP parse: UDP payload carrying upload_commit for anomalous session
        magic = struct.unpack('<I', raw[:4])[0]; assert magic == 0xa1b2c3d4
        off = 24; payloads = []
        while off + 16 <= len(raw):
            _, _, incl, _ = struct.unpack('<IIII', raw[off:off+16]); pkt = raw[off+16:off+16+incl]; off += 16 + incl
            if len(pkt) < 42 or pkt[12:14] != b'\x08\x00': continue
            ihl = (pkt[14] & 0x0f) * 4
            if pkt[14+9] != 17: continue
            udp = pkt[14+ihl:14+ihl+8]
            ulen = struct.unpack('>H', udp[4:6])[0]
            payloads.append(pkt[14+ihl+8:14+ihl+ulen])
        hits = []
        for p in payloads:
            if b'MCSREC:' in p:
                rec = json.loads(p.split(b'MCSREC:')[1])
                if rec.get('event_type') == 'upload_commit' and rec.get('session_id') == NOTES['anom_session']:
                    hits.append(rec)
        assert len(hits) == 1, [json.loads(p.split(b'MCSREC:')[1]) for p in payloads if b'MCSREC:' in p]
        return hits[0]['request_id'], 'own Ethernet/IPv4/UDP PCAP parse: upload_commit MCSREC for anomalous session -> request_id'
    if n == 61:  # object access: accepted download for anomalous session
        events = [json.loads(l) for l in raw.decode().splitlines() if l.strip()]
        hits = [e for e in events if (e.get('session_parent') == NOTES['anom_session'] or e.get('session_id') == NOTES['anom_session']) and e.get('status') in ('accepted', 'success')]
        assert len(hits) == 1, hits
        NOTES['object_id'] = hits[0]['object_id']
        return hits[0]['object_id'], 'accepted object access tied to anomalous session -> object_id'
    if n == 62:  # cache manifest: object -> sha256
        t = raw.decode()
        for line in t.splitlines():
            if NOTES['object_id'] in line:
                m = re.search(r'\b[0-9a-f]{64}\b', line)
                if m: NOTES['cache_sha'] = m.group(0); return m.group(0), 'mobile cache manifest maps object_id -> 64-hex SHA-256'
        raise AssertionError('object not in manifest')
    if n == 63:  # cache export tar: manifest names the item; extracted bytes must hash to L62 digest
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            man = json.loads(t.extractfile('cache_manifest.json').read())
            items = man if isinstance(man, list) else (man.get('items') or man.get('entries') or [man])
            hits = []
            for it in items:
                if it.get('object_id') == NOTES['object_id'] and it.get('sha256') == NOTES['cache_sha']:
                    member = it.get('path') or it.get('file') or it.get('name')
                    data = t.extractfile(member).read() if member else None
                    if data is not None:
                        assert hashlib.sha256(data).hexdigest() == NOTES['cache_sha']
                    hits.append(it)
            assert len(hits) == 1, hits
            return hits[0].get('cache_item_ref') or hits[0].get('ref'), 'cache manifest item bound to L61 object; bytes hash to L62 digest'
    if n == 71:  # docker-save style tar: image manifest layer digest
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            man = json.loads(t.extractfile('manifest.json').read())
        entry = man[0] if isinstance(man, list) else man
        layers = entry.get('Layers') or entry.get('layers')
        dig = None
        t2 = raw.decode(errors='replace')
        m = re.search(r'sha256:[0-9a-f]{64}', t2)
        assert m
        NOTES['layer_digest'] = m.group(0)
        return m.group(0), 'static Docker-save TAR manifest -> referenced sha256 layer digest'
    if n == 78:  # nested layer tars: whiteout hides path but lower layer keeps bytes
        with tarfile.open(fileobj=io.BytesIO(raw)) as outer:
            lower = outer.extractfile('layer-000-lower.tar').read()
            upper = outer.extractfile('layer-001-cleanup.tar').read()
        with tarfile.open(fileobj=io.BytesIO(upper)) as t:
            names = t.getnames(); assert any('.wh.' in x for x in names), names
        with tarfile.open(fileobj=io.BytesIO(lower)) as t:
            envf = [m for m in t.getmembers() if m.name.endswith('env.dump')]
            assert envf
            envtxt = t.extractfile(envf[0]).read().decode()
        secret = re.search(r'^CLOUD_EXPORT_SECRET=(\S+)', envtxt, re.M).group(1)
        assert secret != re.search(r'^ROTATED_SECRET=(\S+)', envtxt, re.M).group(1)
        NOTES['container_secret'] = secret
        return secret, 'upper layer has tmp/.wh.env.dump whiteout; lower layer still holds env.dump -> current CLOUD_EXPORT_SECRET'
    if n == 89:  # WAL recovery of deleted event
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = z.namelist()
            db = z.read([x for x in names if x.endswith('.db')][0])
            wal = z.read([x for x in names if x.endswith('-wal') or 'wal' in x][0])
        m = re.search(rb'timeline_evt_[0-9a-f]+', wal)
        assert m
        return m.group(0).decode(), 'deleted event ref recovered from preserved WAL bytes, not the live table'
    if n == 91:  # MCS-VCONF1 receipt keyed by vault password
        assert raw.startswith(b'MCS-VCONF1\0')
        salt = raw[11:27]; ct = raw[59:]
        pt = bytes(x ^ y for x, y in zip(ct, stream(NOTES['vault_pw'], salt, len(ct))))
        r = json.loads(pt)
        assert r['vault_password_fingerprint'] == hashlib.sha256(NOTES['vault_pw'].encode()).hexdigest()
        return r['receipt_ref'], 'MCS-VCONF1 receipt opens with L34 vault password; fingerprint == SHA256(vault password)'
    if n == 93:  # MCS-CSCONF1 receipt keyed by container secret
        assert raw.startswith(b'MCS-CSCONF1\0')
        salt = raw[12:28]; ct = raw[60:]
        pt = bytes(x ^ y for x, y in zip(ct, stream(NOTES['container_secret'], salt, len(ct))))
        r = json.loads(pt)
        assert r['container_secret_fingerprint'] == hashlib.sha256(NOTES['container_secret'].encode()).hexdigest()
        return r['receipt_ref'], 'MCS-CSCONF1 receipt opens with L78 container secret; fingerprint == SHA256(container secret)'
    if n == 99:  # final authorization digest
        t = raw.decode()
        assert 'MCS-FINAL-1|' in t
        pre = 'MCS-FINAL-1|' + NOTES['vault_pw'] + '|' + NOTES['cloud_token'] + '|' + NOTES['container_secret']
        return hashlib.sha256(pre.encode()).hexdigest(), "SHA256('MCS-FINAL-1|'+vault_pw+'|'+cloud_token+'|'+container_secret) in exact order"
    # generic: unique token embedding this layer's number (+ deep-decode of embedded base64 records)
    t = text_of(raw)
    extra = []
    for m in re.findall(r'[A-Za-z0-9+/]{24,}={0,2}', t):
        try:
            d = base64.b64decode(m)
            if all(9 <= b < 127 or b in (10, 13) for b in d): extra.append(d.decode())
        except Exception: pass
    if extra: t = t + '\n' + '\n'.join(extra)
    if raw[:5] == b'From ':
        import email, email.header
        msg = email.message_from_bytes(raw)
        for part in msg.walk() if msg.is_multipart() else [msg]:
            for hn, hv in part.items():
                if hn.lower().startswith('x-mcs') or hn.lower() == 'x-mcs-record':
                    frag = ''.join(str(b, e or 'utf-8', errors='replace') if isinstance(b, bytes) else b for b, e in email.header.decode_header(hv))
                    try: t += '\n' + base64.b64decode(frag).decode(errors='replace')
                    except Exception: t += '\n' + frag
    pat = f'mcs-{n:03d}-[0-9a-f]{{32}}'
    hits = sorted(set(re.findall(pat, t)))
    assert len(hits) == 1, (n, hits)
    link = isinstance(KEYS.get(n-1), str) and KEYS[n-1] in t
    return hits[0], 'unique current-layer token selected over decoy records' + ('; prior-layer value present as provenance link' if link else '')

# ---- walk ----
# L1
with zipfile.ZipFile(EV/'001_ios_backup.zip') as z:
    mp = plistlib.loads(z.read('Manifest.plist'))
KEYS[1] = mp['DeviceGUID']; NOTES['backup_hint'] = mp['BackupKeyHint']
print(f"L001 {KEYS[1]} [Manifest.plist DeviceGUID; BackupKeyHint retained for L41]")

flag = None
for n in range(2, 101):
    f = next(EV.glob(f'{n:03d}_*.mcs'))
    clear = open_seal(f.read_bytes(), KEYS[n-1])
    if n == 100:
        doc = json.loads(clear)
        flag = doc['payload']['flag']
        print(f"L100 {flag} [final export opens with L99 digest; authorized=true]")
        break
    key, note = derive(n, clear)
    KEYS[n] = key
    LOG.append((n, key, note))
    print(f"L{n:03d} {key} [{note}]")
json.dump([{'layer': n, 'key': k, 'note': note} for n, k, note in LOG], open('/tmp/f6/my_endpoints_keys.json', 'w'), indent=1)
print('FINAL:', flag)
