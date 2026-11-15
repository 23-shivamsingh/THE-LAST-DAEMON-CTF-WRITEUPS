import json, base64, hashlib

raw = open('/tmp/f4/orig/ghost_process_player/ghostprocess.mem','rb').read()
HL = int.from_bytes(raw[8:12], 'big')
HDR = json.loads(raw[12:12+HL])

def dec_layer(n, ans):
    rec = HDR['records'][n-1]
    ct = base64.b64decode(rec['ciphertext_b64'])
    if not rec['locked_by_previous_output']:
        return ct
    k = hashlib.sha256(b'GP-REPLAY-V1|' + ans.encode()).digest()
    out = bytearray(len(ct))
    for off in range(0, len(ct), 32):
        blk = hashlib.sha256(k + (off//32).to_bytes(4,'big')).digest()
        take = min(32, len(ct)-off)
        for i in range(take):
            out[off+i] = ct[off+i] ^ blk[i]
    return bytes(out)

def unlock(n, candidates):
    rec = HDR['records'][n-1]
    for a in candidates:
        clear = dec_layer(n, a)
        if hashlib.sha256(clear).hexdigest() == rec['plaintext_sha256']:
            open(f'/tmp/f4/work/layer{n:02d}.json','wb').write(clear)
            print(f'--- L{n:02d} key={a!r} token={hashlib.sha256(clear).hexdigest()[:12]} MATCH')
            return a, json.loads(clear)
    raise SystemExit(f'LAYER {n}: no candidate matched')

def show(o):
    print('TASK:', o['task'])
    print(json.dumps(o['evidence'], indent=1)[:1600])
