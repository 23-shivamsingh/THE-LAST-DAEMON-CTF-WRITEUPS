#!/usr/bin/env python3
"""My own independent Dark Wire channel decodes (written for this review,
not the bundle's scripts). Covers stages 1, 2, 22, 42."""
import io, json, re, struct, zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYS = json.loads(open('/tmp/f2/writeup/DARK_WIRE/stage_keys.json').read())

def frames(pcap):
    assert pcap[:4] == b'\xd4\xc3\xb2\xa1', 'expect little-endian pcap'
    pos = 24
    while pos + 16 <= len(pcap):
        sec, usec, incl, orig = struct.unpack_from('<IIII', pcap, pos); pos += 16
        yield sec*1_000_000+usec, pcap[pos:pos+incl]; pos += incl

def ip_packets(pcap):
    for t, f in frames(pcap):
        if len(f) < 34 or f[12:14] != b'\x08\x00': continue
        ip = f[14:]
        if ip[0] >> 4 != 4: continue
        hl = (ip[0] & 15) * 4
        proto = ip[9]
        seg = ip[hl:]
        yield t, ip, proto, seg

def stage_blob(z, n):
    enc = z.read(f'packet_trail_player/stages/stage{n:02d}.ptenc')
    assert enc[:6] == b'PTENC1'
    k = Scrypt(salt=enc[6:22], length=32, n=2**14, r=8, p=1).derive(KEYS[str(n-1)].encode())
    return AESGCM(k).decrypt(enc[22:34], enc[34:], b'PacketTrail-Stage-v1')

def stage_files(z, n):
    with zipfile.ZipFile(io.BytesIO(stage_blob(z, n))) as sz:
        return {nm: sz.read(nm) for nm in sz.namelist()}

z = zipfile.ZipFile('/downloads/file-111a07e1-21cdbfac.bin')

# --- Stage 1: HTTP body of /download/case-note.txt ---
pcap = z.read('packet_trail_player/stages/stage01.pcap')
bodies = []
for t, ip, proto, seg in ip_packets(pcap):
    if proto != 6 or len(seg) < 20: continue
    sport = int.from_bytes(seg[:2], 'big')
    payload = seg[(seg[12] >> 4)*4:]
    if sport == 80 and payload:
        bodies.append(payload)
http = b''.join(bodies)
m = re.search(rb'next_stage_key=([0-9a-f]{24})', http)
k1 = m.group(1).decode()
print('Stage 01 my decode:', k1, 'MATCH' if k1 == KEYS['1'] else 'MISMATCH')
# show the case-note body as evidence
i = http.find(b'case-note')
print('  context snippet:', http[max(0,i-80):i+120].decode(errors='replace').replace('\r','').strip()[:200])

# --- Stage 2: X-Receipt-0N header fragments, sorted by N ---
s2 = stage_files(z, 2)['capture.pcap']
resp = []
for t, ip, proto, seg in ip_packets(s2):
    if proto != 6 or len(seg) < 20: continue
    if int.from_bytes(seg[:2],'big') == 80:
        p = seg[(seg[12] >> 4)*4:]
        if p: resp.append(p)
hdr_blob = b''.join(resp)
frags = dict(re.findall(rb'X-Receipt-(\d\d):\s*([0-9a-f]{8})', hdr_blob))
k2 = b''.join(frags[k] for k in sorted(frags)).decode()
print('Stage 02 my decode:', k2, 'MATCH' if k2 == KEYS['2'] else 'MISMATCH', '(headers found:', sorted(frags), ')')

# --- Stage 22: ICMP PTC1 chunks in packet order ---
s22 = stage_files(z, 22)['capture.pcap']
chunks = []
for t, ip, proto, seg in ip_packets(s22):
    if proto != 1: continue
    payload = seg[8:]
    if payload.startswith(b'PTC1'):
        chunks.append(payload)
joined = b''.join(c[4:] for c in chunks)
m = re.search(rb'([0-9a-f]{24})', joined)
k22 = m.group(1).decode()
print('Stage 22 my decode:', k22, 'MATCH' if k22 == KEYS['22'] else 'MISMATCH', f'({len(chunks)} ICMP chunks)')

# --- Stage 42: WAV tone frequency encoding ---
s42 = stage_files(z, 42)
names = list(s42)
print('Stage 42 files:', names)
