"""My own TLS 1.2 keylog decryptor for synthetic Dark Wire captures."""
import struct, hashlib, hmac, sys
sys.path.insert(0, '/tmp/f2')
from dwlib import packets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SUITES = {0xC030: (32, hashlib.sha384), 0xC02F: (16, hashlib.sha256),
          0x009C: (16, hashlib.sha256), 0x009D: (32, hashlib.sha384),
          0xC02B: (16, hashlib.sha256), 0xC02C: (32, hashlib.sha384)}

def prf(secret, label, seed, length, hashmod):
    out, a = b'', hmac.new(secret, label + seed, hashmod).digest()
    while len(out) < length:
        out += hmac.new(secret, a + label + seed, hashmod).digest()
        a = hmac.new(secret, a, hashmod).digest()
    return out[:length]

def stream_records(pcap, sport):
    buf = b''
    for t, s, d, proto, sp, dp, pl in packets(pcap):
        if proto == 6 and sp == sport and pl:
            buf += pl
    recs, i = [], 0
    while i + 5 <= len(buf):
        ln = int.from_bytes(buf[i+3:i+5], 'big')
        recs.append((buf[i], buf[i+1:i+3], buf[i+5:i+5+ln]))
        i += 5 + ln
    return recs

def decrypt_flow(pcap, keylog_text, client_port):
    cli = stream_records(pcap, client_port)
    srv = stream_records(pcap, 443)
    crand = cli[0][2][6:38]
    sh = srv[0][2]
    p = 6 + 32
    sid_len = sh[p]; p += 1 + sid_len
    suite = int.from_bytes(sh[p:p+2], 'big')
    srand = sh[6:38]
    keylen, hashmod = SUITES[suite]
    master = None
    for line in keylog_text.decode().splitlines():
        if line.startswith('CLIENT_RANDOM'):
            _, cr, ms = line.split()
            if cr == crand.hex():
                master = bytes.fromhex(ms)
    assert master, 'no keylog entry'
    kb = prf(master, b'key expansion', srand + crand, 2*keylen + 8, hashmod)
    keys = {'c': (kb[:keylen], kb[2*keylen:2*keylen+4]),
            's': (kb[keylen:2*keylen], kb[2*keylen+4:2*keylen+8])}
    plain = {'c': [], 's': []}
    for name, recs in (('c', cli), ('s', srv)):
        key, salt = keys[name]
        aead = AESGCM(key)
        seq, active = 0, False
        for ct, ver, body in recs:
            if ct == 20:
                active = True
                continue
            if not active:
                continue
            nonce = salt + body[:8]
            cttag = body[8:]
            aad = struct.pack('>Q', seq) + bytes([ct]) + ver + struct.pack('>H', len(cttag) - 16)
            data = aead.decrypt(nonce, cttag, aad)
            seq += 1
            if ct == 23:
                plain[name].append(data)
    return plain
