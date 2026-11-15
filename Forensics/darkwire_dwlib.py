"""My own shared helpers for independent Dark Wire decodes.
Ledger keys are used ONLY to open the AES-GCM stage bundles (the opening is
itself authenticated); every channel value below is derived from the opened
capture by my own parsing code."""
import io, json, re, struct, zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYS = json.loads(open('/tmp/f2/writeup/DARK_WIRE/stage_keys.json').read())
Z = zipfile.ZipFile('/downloads/file-111a07e1-21cdbfac.bin')

def stage_files(n):
    if n == 1:
        return {'capture.pcap': Z.read('packet_trail_player/stages/stage01.pcap')}
    enc = Z.read(f'packet_trail_player/stages/stage{n:02d}.ptenc')
    assert enc[:6] == b'PTENC1'
    k = Scrypt(salt=enc[6:22], length=32, n=2**14, r=8, p=1).derive(KEYS[str(n-1)].encode())
    blob = AESGCM(k).decrypt(enc[22:34], enc[34:], b'PacketTrail-Stage-v1')
    with zipfile.ZipFile(io.BytesIO(blob)) as sz:
        return {nm: sz.read(nm) for nm in sz.namelist()}

def packets(pcap):
    """yield (t_us, src_ip, dst_ip, proto, sport, dport, l4_payload) for IPv4 TCP/UDP/ICMP"""
    assert pcap[:4] == b'\xd4\xc3\xb2\xa1'
    pos = 24
    while pos + 16 <= len(pcap):
        sec, usec, incl, orig = struct.unpack_from('<IIII', pcap, pos); pos += 16
        f = pcap[pos:pos+incl]; pos += incl
        if len(f) < 34 or f[12:14] != b'\x08\x00':
            continue
        ip = f[14:]
        if ip[0] >> 4 != 4:
            continue
        hl = (ip[0] & 15) * 4
        proto = ip[9]
        src = '.'.join(map(str, ip[12:16])); dst = '.'.join(map(str, ip[16:20]))
        seg = ip[hl:]
        if proto == 6 and len(seg) >= 20:
            yield sec*1_000_000+usec, src, dst, 6, int.from_bytes(seg[:2],'big'), int.from_bytes(seg[2:4],'big'), seg[(seg[12]>>4)*4:]
        elif proto == 17 and len(seg) >= 8:
            yield sec*1_000_000+usec, src, dst, 17, int.from_bytes(seg[:2],'big'), int.from_bytes(seg[2:4],'big'), seg[8:]
        elif proto == 1:
            yield sec*1_000_000+usec, src, dst, 1, 0, 0, seg[8:]

def check(n, actual):
    exp = KEYS[str(n)]
    status = 'MATCH' if actual == exp else f'MISMATCH expected {exp}'
    print(f'Stage {n:02d}: {actual}  => {status}')
    return actual == exp

def tcp_streams(pcap):
    """reassemble TCP payloads per direction of each connection, in arrival order.
    returns dict {(src,sport,dst,dport): bytes}"""
    streams = {}
    for t, s, d, proto, sp, dp, pl in packets(pcap):
        if proto == 6 and pl:
            streams.setdefault((s, sp, d, dp), b'')
            streams[(s, sp, d, dp)] += pl
    return streams

def http_responses(pcap):
    """list of (headers_bytes, body_bytes) for each server response (port 80 server side)."""
    out = []
    streams = tcp_streams(pcap)
    for (s, sp, d, dp), data in streams.items():
        if sp != 80:
            continue
        # one request/response per connection in this capture set
        if not data.startswith(b'HTTP/1.1'):
            continue
        hdr, _, rest = data.partition(b'\r\n\r\n')
        m = re.search(rb'Content-Length:\s*(\d+)', hdr)
        body = rest[:int(m.group(1))] if m else rest
        out.append((hdr, body))
    return out

def http_requests(pcap):
    out = []
    for (s, sp, d, dp), data in tcp_streams(pcap).items():
        if dp == 80 and data.startswith((b'GET', b'POST')):
            out.append(data)
    return out
