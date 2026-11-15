import sys, os, hashlib; sys.path.insert(0, '/tmp/f3')
from zipcrypto import open_encrypted_zip

BASE = '/tmp/f3/stages'
os.makedirs(BASE, exist_ok=True)

def open_stage(n, password):
    """open stageNN.zip (in current stage's folder) with password; verify hashes; extract."""
    # stageNN.zip lives inside stage n-1's folder (or /tmp/f3 for stage02)
    here = os.path.join(BASE, f'stage{n-1:02d}', f'stage{n:02d}.zip')
    if not os.path.exists(here):
        here = f'/tmp/f3/stage{n:02d}.zip'
    files = open_encrypted_zip(open(here, 'rb').read(), password)
    outdir = os.path.join(BASE, f'stage{n:02d}')
    os.makedirs(outdir, exist_ok=True)
    root = f'Layer{n:02d}/'
    verify = None
    for name, content in files.items():
        if name.endswith('/'):
            continue
        rel = name[len(root):] if name.startswith(root) else name
        with open(os.path.join(outdir, rel), 'wb') as fh:
            fh.write(content)
        if rel == 'verify.sha256':
            verify = content.decode()
    # hash verification
    if verify:
        bad = []
        for line in verify.splitlines():
            if not line.strip(): continue
            h, rel = line.split(None, 1)
            p = os.path.join(outdir, rel)
            actual = hashlib.sha256(open(p,'rb').read()).hexdigest()
            if actual != h:
                bad.append(rel)
        status = 'all hashes OK' if not bad else f'HASH FAIL: {bad}'
    else:
        status = 'no verify.sha256'
    print(f'--- stage {n:02d} opened ({len(files)} entries), {status}')
    readme = os.path.join(outdir, 'README.txt')
    if os.path.exists(readme):
        print(open(readme).read().strip()[:600])
    print('files:', sorted(os.listdir(outdir)))
    return outdir
