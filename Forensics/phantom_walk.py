import json, subprocess, sys

MEM='ghostprocess.mem'
def try_extract(n, keys):
    for key in keys:
        cmd = ['python3','ghostmem.py','extract',MEM,'--layer',str(n),'--out',f'/tmp/f4/work/layer{n:02d}.json']
        if key is not None: cmd += ['--key', key]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            tok = [l for l in r.stdout.splitlines() if 'Verification token' in l][0]
            print(f'--- layer {n:02d} key={key!r} {tok}')
            return key, json.load(open(f'/tmp/f4/work/layer{n:02d}.json'))
    print(f'LAYER {n}: all candidate keys failed: {keys}')
    sys.exit(1)
