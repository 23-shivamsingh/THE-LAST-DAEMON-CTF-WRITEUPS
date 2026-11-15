#!/usr/bin/env python3
"""My own end-to-end solver for FULL SPECTRUM (Total Disclosure).
Walks all 100 AES-256-GCM envelopes, deriving each token from the artifact
with independent parsers. The GCM unlock of the next envelope is the arbiter.
"""
import base64, csv, gzip, hashlib, io, json, re, sqlite3, struct, sys, zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path('/tmp/f5/orig/player_bundle')
WORK = Path('/tmp/f5/work'); WORK.mkdir(exist_ok=True)
LOG = []

def unlock(n, token):
    env = json.loads((ROOT/'sealed'/f'{n:03d}.seal').read_text())
    key = hashlib.sha256(token.encode()).digest()
    pt = AESGCM(key).decrypt(base64.b64decode(env['nonce']), base64.b64decode(env['ciphertext']),
                             f'FSS100-1.0|layer={n}'.encode())
    ln = struct.unpack_from('>I', pt, 0)[0]
    meta = json.loads(pt[4:4+ln]); raw = pt[4+ln:]
    assert hashlib.sha256(raw).hexdigest() == meta['plaintext_sha256'] and len(raw) == meta['plaintext_size']
    out = WORK/meta['payload_name']; out.parent.mkdir(parents=True, exist_ok=True); out.write_bytes(raw)
    return out, meta

def rec(n, token, how):
    LOG.append((n, token, how))
    print(f'L{n:03d} {token[:66]:66s} [{how}]', flush=True)

def utc_from_local(ts, off):
    dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
    sign = 1 if off[0]=='+' else -1
    delta = timedelta(hours=int(off[1:3]), minutes=int(off[3:5])) * sign
    return (dt.replace(tzinfo=timezone.utc) - delta).strftime('%Y-%m-%dT%H:%M:%SZ')

def family_timeline(path):
    rows = list(csv.DictReader(open(path)))
    t = [r for r in rows if r['session_id'].startswith('target-')]
    assert len(t) == 1
    return utc_from_local(t[0]['timestamp_local'], t[0]['utc_offset']), 'timeline: target session row -> UTC'

def carve_zip_from_volume(raw):
    start = raw.find(b'PK\x03\x04')
    eocd = raw.rfind(b'PK\x05\x06')
    clen = struct.unpack_from('<H', raw, eocd+20)[0]
    end = eocd + 22 + clen
    return raw[start:end]

def family_volume(path):
    raw = open(path,'rb').read()
    zb = carve_zip_from_volume(raw)
    with zipfile.ZipFile(io.BytesIO(zb)) as z:
        names = z.namelist()
        note = [n for n in names if 'recovery_note' in n][0]
        txt = z.read(note).decode()
    m = re.search(r'RECOVERY_STATUS=VERIFIED[^\n]*', txt)
    tok = re.search(r'(gate-[0-9a-f]+)', m.group(0) if m else txt)
    if not tok:
        # token may be a separate field
        tok = re.search(r'TOKEN=(\S+)', txt)
    return tok.group(1) if tok.re.pattern=='TOKEN=(\\S+)' else tok.group(0), 'FAT16: carved deleted ZIP (PK hdr..EOCD), VERIFIED note token'

def family_eml(path):
    import email
    msg = email.message_from_bytes(open(path,'rb').read())
    expected = (msg.get('X-Expected-Attachment-SHA256') or '').strip()
    for part in msg.walk():
        fn = part.get_filename()
        if not fn: continue
        data = part.get_payload(decode=True)
        if expected and hashlib.sha256(data).hexdigest() == expected:
            return re.search(rb'TOKEN=(\S+)', data).group(1).decode(), 'MIME: attachment sha256 matches X-Expected header -> TOKEN'
    raise ValueError('no matching attachment')

def family_authlog(path):
    txt = open(path).read()
    # accepted publickey from 192.0.2.44 then session gate
    m = re.search(r'session=(gate-[0-9a-f]+)', txt)
    assert 'publickey' in txt and '192.0.2.44' in txt
    return m.group(1), 'auth.log: accepted publickey 192.0.2.44 -> session gate'

def pcap_packets(raw):
    pos = 24
    while pos + 16 <= len(raw):
        sec, usec, incl, orig = struct.unpack_from('<IIII', raw, pos); pos += 16
        yield raw[pos:pos+incl]; pos += incl

def family_dns(path):
    raw = open(path,'rb').read()
    for f in pcap_packets(raw):
        if f[12:14] != b'\x08\x00': continue
        ip = f[14:]; hl = (ip[0]&15)*4
        src = '.'.join(map(str, ip[12:16]))
        if ip[9] != 17: continue
        udp = ip[hl:]; dport = struct.unpack_from('>H', udp[2:4])[0]
        if dport != 53: continue
        dns = udp[8:]
        # decode qname
        q = dns[12:]; labels = []
        i = 0
        while q[i] != 0:
            l = q[i]; labels.append(q[i+1:i+1+l].decode()); i += 1+l
        name = '.'.join(labels)
        m = re.match(r'beacon-([0-9a-f]{16})\.', name)
        if m and src == '192.0.2.44':
            return m.group(1), 'DNS pcap: beacon label from 192.0.2.44 -> hex only'
    raise ValueError('no beacon')

def family_registry(path):
    txt = open(path).read()
    # Recovery key with Workflow=approved-restore
    secs = re.split(r'\n(?=\[)', txt)
    for s in secs:
        if 'Recovery' in s and 'approved-restore' in s:
            m = re.search(r'GateValue"=hex\(2\):([0-9a-fA-F,]+)', s)
            hx = m.group(1).replace(',', '')
            val = bytes.fromhex(hx).decode('utf-16-le').rstrip('\x00')
            return val, 'registry: Recovery/approved-restore hex(2) UTF-16LE GateValue'
    raise ValueError('no recovery key')

def family_browser(path):
    con = sqlite3.connect(path)
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    # generic: query urls-like table
    cols = None
    for t in tables:
        c = [r[1] for r in con.execute(f'PRAGMA table_info({t})')]
        if any('url' in x.lower() for x in c):
            cols = (t, c); break
    t, c = cols
    rows = con.execute(f'select * from {t}').fetchall()
    d = [dict(zip(c, r)) for r in rows]
    # find typed Incident Ledger visit in ProfileA
    for r in d:
        s = json.dumps(r)
        if 'ticket-' in s and 'ProfileA' in s and 'ncident' in s:
            m = re.search(r'ticket=(ticket-[0-9a-f]+)', s)
            if m: return m.group(1), 'browser sqlite: typed Incident Ledger ProfileA ticket param'
    raise ValueError('no ticket row')

def family_memory(path):
    txt = open(path, errors='replace').read()
    recs = re.findall(r'\{[^}]*\}', txt)
    best = None
    for r in recs:
        try: j = json.loads(r)
        except Exception: continue
        s = json.dumps(j)
        if ('ticket' in s or 'gate-' in s) and j.get('state') == 'running':
            best = j
    if best is None:
        # line-based fallback
        for line in txt.splitlines():
            if 'running' in line and ('ticket' in line or 'gate-' in line):
                m = re.search(r'((?:gate|ticket)-[0-9a-f]+)', line)
                if m: return m.group(1), 'synthetic memory: running archive helper ticket (line parse)'
        raise ValueError('no running record')
    m = re.search(r'((?:gate|ticket)-[0-9a-f]+)', json.dumps(best))
    return m.group(1), 'synthetic memory: running archive helper ticket'

def family_cloud(path):
    j = json.load(open(path))
    events = j if isinstance(j, list) else j.get('events') or j.get('Records') or list(j.values())[0]
    for e in events:
        s = json.dumps(e)
        if e.get('sourceIp') == '192.0.2.44' and str(e.get('status')) == '200' or ('192.0.2.44' in s and '"status": 200' in s):
            pass
    for e in events:
        if e.get('sourceIp') == '192.0.2.44' and str(e.get('status')) == '200':
            for k in ('unlock', 'requestId'):
                if k in e: return e[k], 'cloud audit: 200 from 192.0.2.44 -> unlock/requestId'
            m = re.search(r'(req-[0-9a-f]+)', json.dumps(e))
            if m: return m.group(1), 'cloud audit: req token'
    raise ValueError('no event')

def family_png(path):
    from PIL import Image
    img = Image.open(path).convert('RGB')
    w, h = img.size
    px = img.load()
    bits = []
    for y in range(h):
        for x in range(w):
            bits.append(px[x, y][2] & 1)
    by = bytes(int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits)-7, 8))
    i = by.find(b'FSS1:')
    s = by[i+5:]
    tok = s[:s.find(b'\x00')].decode()
    return tok, 'PNG blue-channel LSB, MSB-first, FSS1: NUL-terminated'

def family_proxy(path):
    for line in open(path):
        if '192.0.2.44' in line and 'relay.invalid/sync' in line:
            m = re.search(r'nonce=((?:gate)-[0-9a-f]+)', line)
            if m: return m.group(1), 'proxy: 192.0.2.44 relay.invalid/sync nonce'
    raise ValueError('no proxy line')

def family_correlation(path):
    rows = list(csv.DictReader(open(path)))
    # group token values by source; find token present in auth, pcap and cloud rows with approved correlation
    cols = rows[0].keys()
    bysrc = {}
    for r in rows:
        s = json.dumps(r)
        m = re.search(r'((?:req|gate)-[0-9a-f]+)', s)
        if not m: continue
        src = r.get('source') or ('auth' if 'auth' in s else 'pcap' if 'pcap' in s else 'cloud' if 'cloud' in s else '?')
        if 'approved' in s or True:
            bysrc.setdefault(m.group(1), set()).add(src)
    for tok, srcs in bysrc.items():
        if len(srcs) >= 3:
            return tok, 'correlation csv: token present in all three sources'
    # fallback: most common
    from collections import Counter
    c = Counter()
    for r in rows:
        m = re.search(r'((?:req|gate)-[0-9a-f]+)', json.dumps(r))
        if m: c[m.group(1)] += 1
    return c.most_common(1)[0][0], 'correlation csv: most corroborated token'

def family_gzjson(path):
    data = gzip.decompress(open(path,'rb').read())
    txt = data.decode()
    recs = []
    try:
        j = json.loads(txt)
        if isinstance(j, list): recs = j
        elif isinstance(j, dict) and 'records' in j: recs = j['records']
        else: recs = list(j.values())[0]
    except Exception:
        recs = [json.loads(l) for l in txt.splitlines() if l.strip()]
    for r in recs:
        if r.get('lane') == 'approved' and r.get('verified') is True:
            return r['gate'], 'gzip json: lane=approved verified=true gate'
    raise ValueError('no approved record')

def family_prefetch(path):
    j = json.load(open(path))
    recs = j if isinstance(j, list) else list(j.values())[0]
    cands = [r for r in recs if 'SVCCACHE' in json.dumps(r).upper() and 'ProgramData' in json.dumps(r)]
    if len(cands) == 1:
        r = cands[0]
    else:
        r = max(cands, key=lambda r: r.get('RunCount', 0))
    lt = r.get('LastRunTimes') or r.get('LastRunTime')
    if isinstance(lt, list): lt = lt[0]
    return lt, 'prefetch: ProgramData SVCCACHE.EXE LastRunTimes UTC'

def family_schedtask(path):
    with zipfile.ZipFile(path) as z:
        xml = z.read('tasks/approved.xml').decode()
    assert 'Enabled=true' in xml or '<Enabled>true</Enabled>' in xml
    m = re.search(r'--case-token[=\s"]*((?:gate|ticket)-[0-9a-f]+)', xml)
    return m.group(1), 'scheduled task: approved.xml Enabled=true --case-token'

def family_mft(path):
    rows = list(csv.DictReader(open(path)))
    for r in rows:
        if 'svc_cache.exe' in json.dumps(r):
            fn = {k: v for k, v in r.items() if 'FN' in k.upper() and ('creat' in k.lower() or 'created' in k.lower())}
            if fn: return list(fn.values())[0], 'MFT: svc_cache.exe $FN_Created (SI reset to January)'
    raise ValueError('no svc_cache row')

def family_yara(path):
    with zipfile.ZipFile(path) as z:
        sample = z.read('samples/sample.bin')
        report = z.read('reports/match.txt').decode()
    assert b'FSS_SIMULATED_SAMPLE' in sample
    h = hashlib.sha256(sample).hexdigest()
    assert h in report
    return re.search(rb'TOKEN=(\S+)', sample).group(1).decode(), 'YARA bundle: marker present + sample sha256 matches report -> TOKEN from sample'

def family_history(path):
    for line in open(path):
        if 'approved case replay' in line and 'base64' in line.lower():
            m = re.search(r"printf[^|]*'([A-Za-z0-9+/=]+)'", line) or re.search(r'echo\s+([A-Za-z0-9+/=]{12,})', line) or re.search(r'([A-Za-z0-9+/]{16,}={0,2})', line)
            dec = base64.b64decode(m.group(1)).decode()
            return re.search(r'((?:gate|ticket)-[0-9a-f]+)', dec).group(0), 'shell history: approved replay base64 decode'
    raise ValueError('no approved line')

def family_evzip(path):
    with zipfile.ZipFile(path) as z:
        man = json.loads(z.read('manifest.json'))
        data = z.read('approved/recovery.txt')
    exp = man.get('approved/recovery.txt') or list(man.values())[0]
    assert hashlib.sha256(data).hexdigest() == exp or exp in hashlib.sha256(data).hexdigest()
    return re.search(rb'gate=((?:gate)-[0-9a-f]+)', data).group(1).decode(), 'evidence zip: approved/recovery.txt sha256 vs manifest -> gate'

def family_mobile(path):
    con = sqlite3.connect(path)
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    for t in tables:
        c = [r[1] for r in con.execute(f'PRAGMA table_info({t})')]
        rows = con.execute(f'select * from {t}').fetchall()
        for r in rows:
            d = dict(zip(c, r))
            if d.get('verified') == 1:
                m = re.search(r'gate=((?:gate|ticket)-[0-9a-f]+)', json.dumps(d))
                if m: return m.group(1), 'mobile sqlite: verified=1 sync note gate='
    raise ValueError('no verified row')

def family_smb(path):
    raw = open(path,'rb').read()
    for f in pcap_packets(raw):
        i = f.find(b'\xfeSMB')
        if i >= 0:
            sid = struct.unpack_from('<Q', f, i+40)[0]
            return f'sid-{sid & 0xFFFFFFFFFFFF:012x}', 'SMB2 SessionId LE at +40 -> sid-<12hex>'
    raise ValueError('no smb')

def solve_special(n, path):
    if n == 12:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            eml = [x for x in names if x.endswith('.eml')][0]
            data = z.read(eml).decode(errors='replace')
        m = re.search(r'Date: (.*)', data)
        dt = datetime.strptime(m.group(1).strip(), '%a, %d %b %Y %H:%M:%S %z')
        return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'L12: phishing email Date normalized to UTC'
    if n == 35:
        with zipfile.ZipFile(path) as z:
            mft = list(csv.DictReader(io.TextIOWrapper(z.open('mft/mft_attributes.csv'))))
            pf = json.loads(z.read('prefetch/prefetch_export.json'))
            ev = json.loads(z.read('events/process_creation.json'))
        mrow = next(r for r in mft if r['file_name'] == 'svc_cache.exe')
        assert mrow['$SI_Modified'].startswith('2026-01-01') and mrow['$FN_Modified'].startswith('2026-09-14')
        p = next(e for e in pf['entries'] if e['ExecutableName'] == 'SVCCACHE.EXE' and 'ProgramData' in e['path'])
        e4 = next(e for e in ev['events'] if e['EventID'] == 4688 and 'svc_cache.exe' in e['NewProcessName'])
        assert p['LastRunTimes'][0] == e4['UtcTime']
        return e4['UtcTime'], 'L35: MFT shows SI timestomp; prefetch + EventID 4688 independently agree on true execution UTC'
    if n == 59:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            reg = z.read([x for x in names if x.endswith('.reg')][0]).decode()
            db = z.read([x for x in names if x.endswith('.sqlite')][0])
        pk = re.search(r'ProfileKey"?\s*=\s*"?([0-9a-f]{64})', reg).group(1)
        key = hashlib.sha256(('FSS-DPAPI-SIM|' + pk).encode()).digest()
        import tempfile, os
        fd, p = tempfile.mkstemp(suffix='.sqlite'); os.write(fd, db); os.close(fd)
        con = sqlite3.connect(p)
        row = con.execute("select * from logins where cred_ref='cred-7f2a' and profile='profile17'").fetchone()
        cols = [c[1] for c in con.execute('PRAGMA table_info(logins)')]
        d = dict(zip(cols, row)); con.close(); os.unlink(p)
        nonce = d['nonce']; ct = d['ciphertext']
        if isinstance(nonce, str): nonce = bytes.fromhex(nonce)
        if isinstance(ct, str): ct = bytes.fromhex(ct)
        pt = AESGCM(key).decrypt(nonce, ct, b'FSS-DPAPI-SIM-v1|profile17')
        global CRED_REF
        CRED_REF = re.search(rb'cred_ref=(\S+)', pt).group(1).decode()
        pw = re.search(rb'password=(\S+)', pt).group(1).decode()
        return pw, 'L59: FSS-DPAPI-SIM KDF+AAD AES-GCM decrypt -> password'
    if n == 69:
        env = json.loads(open(path).read())
        key = hashlib.sha256(T59.encode()).digest()
        pt = AESGCM(key).decrypt(base64.b64decode(env['nonce']), base64.b64decode(env['ciphertext']), b'FSS-STAGING-v1')
        assert hashlib.sha256(pt).hexdigest() == 'ac58f7a7c1dfc042c041d73bd50793ec6fc6981fc38759d45e7d5aec15cb0651'
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(pt), mode='r:gz') as tf:
            man = json.loads(tf.extractfile('stage/manifest.json').read())
            idx = tf.extractfile('stage/index.txt').read().decode()
        gate = re.search(r'(gate-[0-9a-f]+)', idx).group(1)
        assert gate in json.dumps(man)
        return gate, 'L69: .senc decrypt (t59 key) -> gzip tar -> index/manifest gate'
    if n == 79:
        h = hashlib.sha256(open('/tmp/f5/work/069_staging_bundle.senc','rb').read()).hexdigest()
        with zipfile.ZipFile(path) as z:
            pcap = z.read('network/exfil.pcap')
            audit = json.loads(z.read('cloud/audit.json'))
        assert h.encode() in pcap
        assert h in json.dumps(audit)
        return h, 'L79: sha256 of original .senc matches pcap header + audit PutObject'
    if n == 99:
        with zipfile.ZipFile(path) as z:
            recon = z.read('final/reconciliation.txt').decode()
            rows = list(csv.DictReader(io.TextIOWrapper(z.open('final/root_cause_hypotheses.csv'))))
        piv = dict(l.split('=', 1) for l in recon.splitlines() if '=' in l)
        assert piv['initial_access_utc'] == T12 and piv['true_execution_utc'] == T35
        assert piv['credential_ref'] == CRED_REF and piv['archive_sha256'] == T79
        hit = [r for r in rows if r['mail_utc'] == T12 and r['execution_utc'] == T35
               and r['credential_ref'] == CRED_REF and r['object_sha256'] == T79]
        assert len(hit) == 1 and not hit[0]['salt'].startswith('vault-salt-decoy')
        return hit[0]['salt'], 'L99: only row matching all four independent pivots -> salt'
    if n == 100:
        with zipfile.ZipFile(path) as z:
            enc = json.loads(z.read('flag_bundle.enc.json'))
        pre = f"FSS100|{T12}|{T35}|{T59}|{T79}|{T99}"
        key = hashlib.sha256(pre.encode()).digest()
        ct = base64.b64decode(enc['ciphertext'])
        assert hashlib.sha256(ct).hexdigest() == 'e19e3f33cda10ff6788ba32722f0717fe03cdafdcb98c450e8df73bff5f3035f'
        pt = AESGCM(key).decrypt(base64.b64decode(enc['nonce']), ct, b'FSS100-FINALE-v1')
        assert hashlib.sha256(pt).hexdigest() == 'f3f78c8a879c6e4cdc44fe87505bc5e3648ab03a564ed5fb3827703773491db4'
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(pt), mode='r:gz') as tf:
            flag = tf.extractfile('flag.txt').read().decode().strip()
        return flag, 'L100: finale KDF + AES-GCM + gzip tar flag.txt'
    raise ValueError(f'no special {n}')

FAMILIES = [
    ('_timeline.csv', family_timeline), ('_ws17_volume.raw', family_volume),
    ('_mail.eml', family_eml), ('_auth.log', family_authlog), ('_dns.pcap', family_dns),
    ('_registry.reg', family_registry), ('_browser_history.sqlite', family_browser),
    ('_synthetic_memory_region.bin', family_memory), ('_cloud_audit.json', family_cloud),
    ('_normal_photo.png', family_png), ('_proxy_access.log', family_proxy),
    ('_correlation.csv', family_correlation), ('_compressed_export.json.gz', family_gzjson),
    ('_prefetch_parser_export.json', family_prefetch), ('_scheduled_tasks.zip', family_schedtask),
    ('_mft_attribute_report.csv', family_mft), ('_yara_case_bundle.zip', family_yara),
    ('_bash_history.txt', family_history), ('_evidence_archive.zip', family_evzip),
    ('_mobile_backup.sqlite', family_mobile), ('_lateral_sessions.pcap', family_smb),
]
SPECIALS = {12, 35, 59, 69, 79, 99, 100}

T12=T35=T59=T79=T99=None
CRED_REF=None
tok = hashlib.sha256(open(ROOT/'starter/anchor.bin','rb').read()).hexdigest()
rec(1, tok, 'starter anchor sha256 (matches case_index.csv verified row)')

for n in range(2, 101):
    out, meta = unlock(n, tok)
    name = meta['payload_name']
    if n in SPECIALS:
        tok, how = solve_special(n, out)
        if n==12: T12=tok
        if n==35: T35=tok
        if n==59: T59=tok
        if n==79: T79=tok
        if n==99: T99=tok
    else:
        for suf, fn in FAMILIES:
            if name.endswith(suf):
                tok, how = fn(out); break
        else:
            print(f'L{n:03d} NO FAMILY for {name}'); sys.exit(1)
    rec(n, tok, how)

print()
print('FINAL:', tok)
json.dump([{'layer':n,'token':t,'how':h} for n,t,h in LOG], open('/tmp/f5/my_tokens.json','w'), indent=1)
