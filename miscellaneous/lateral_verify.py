#!/usr/bin/env python3
"""Lateral Conundrum full-chain verifier: unwraps all 150 PBX1 containers with the
recorded outputs, recomputes receipts, decrypts core.lock and checks both SHA-256 gates."""
import json, hashlib, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lateral_pack/tools'))
import common
base = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lateral_pack')
outputs = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lateral_outputs.json')))
values = {str(k): v for k, v in outputs.items()}
m = json.load(open(os.path.join(base, 'manifest.json')))
dg = m['dependency_graph']
for n in range(1, 151):
    key = common.derive_key(values, dg[str(n)])
    common.unwrap(open(os.path.join(base, 'layers', f'{n:03d}.wbox'), 'rb').read(), key)
print('containers unwrapped and integrity-checked: 150/150')
rc = {n: f"PBX-{n:03d}-{hashlib.sha256(values[str(n)].encode()).hexdigest()[:12]}" for n in (1, 25, 50, 75, 100, 125, 149)}
for n, r in rc.items(): print('receipt', r)
key150 = common.derive_key(values, dg['150'])
data = common.unwrap(open(os.path.join(base, 'layers', '150.wbox'), 'rb').read(), key150)
files = common.archive_files(data)
task = json.loads(files['task.json'])
core = files['core.lock']
assert hashlib.sha256(core).hexdigest() == task['ciphertext_sha256'], 'ciphertext digest mismatch'
print('core.lock ciphertext_sha256: MATCH')
pt = common.xor_stream(core, common.derive_key(values, task['key_layers']), bytes.fromhex(task['nonce']))
assert hashlib.sha256(pt).hexdigest() == task['payload_sha256'], 'payload digest mismatch'
print('payload_sha256: MATCH')
print('FINAL FLAG:', pt.decode().splitlines()[0])
