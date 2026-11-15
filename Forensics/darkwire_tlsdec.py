"""My own TLS 1.2 AES-GCM decryption from a CLIENT_RANDOM keylog."""
import hashlib, hmac, struct

def prf(secret, label, seed, length, hashmod):
    out = b''
    a = hmac.new(secret, label + seed, hashmod).digest()
    while len(out) < length:
        out += hmac.new(secret, a + label + seed, hashmod).digest()
        a = hmac.new(secret, a, hashmod).digest()
    return out[:length]

GCM_SUITES = {
    0xC02F: ('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 16, hashlib.sha256),
    0xC030: ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 32, hashlib.sha384),
    0x009C: ('TLS_RSA_WITH_AES_128_GCM_SHA256', 16, hashlib.sha256),
    0x009D: ('TLS_RSA_WITH_AES_256_GCM_SHA384', 32, hashlib.sha384),
    0xC02B: ('TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 16, hashlib.sha256),
    0xC02C: ('TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 32, hashlib.sha384),
}

def parse_records(payload):
    """split a TCP payload chunk into TLS records (assumes aligned)"""
    recs = []
    i = 0
    while i + 5 <= len(payload):
        ct, ver, ln = payload[i], payload[i+1:i+3], int.from_bytes(payload[i+3:i+5], 'big')
        recs.append((ct, ver, payload[i+5:i+5+ln]))
        i += 5 + ln
    return recs

def server_hello_info(records_by_dir):
    for d, recs in records_by_dir.items():
        for ct, ver, body in recs:
            if ct == 22 and body and body[0] == 2:
                p = 4
                srv_ver = body[p:p+2]; p += 2
                srv_rand = body[p:p+32]; p += 32
                sid_len = body[p]; p += 1 + sid_len
                suite = int.from_bytes(body[p:p+2], 'big')
                return srv_rand, suite
    raise ValueError('no ServerHello')

def client_hello_random(records_by_dir):
    for d, recs in records_by_dir.items():
        for ct, ver, body in recs:
            if ct == 22 and body and body[0] == 1:
                return body[6:38]
    raise ValueError('no ClientHello')

def decrypt_tls_flow(flow_records, client_random, keylog, direction_is_client):
    """flow_records: list of (ct, ver, body) in wire order for ONE direction.
    Returns list of plaintext bytes for application-data records."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    master = bytes.fromhex(keylog[client_random.hex()])
    srv_rand, suite = server_hello_info_cache['info']
    name, keylen, hashmod = GCM_SUITES[suite]
    kb = prf(master, b'key expansion', srv_rand + client_random, 2*keylen + 8, hashmod)
    ck, sk = kb[:keylen], kb[keylen:2*keylen]
    civ, siv = kb[2*keylen:2*keylen+4], kb[2*keylen+4:2*keylen+8]
    key, salt = (ck, civ) if direction_is_client else (sk, siv)
    aead = AESGCM(key)
    out = []
    seq = 0
    for ct, ver, body in flow_records:
        if ct != 23:
            continue
        nonce = salt + body[:8]
        ct_tag = body[8:]
        aad = struct.pack('>Q', seq) + bytes([23]) + ver + struct.pack('>H', len(ct_tag) - 16)
        out.append(aead.decrypt(nonce, ct_tag, aad))
        seq += 1
    return out

server_hello_info_cache = {}
