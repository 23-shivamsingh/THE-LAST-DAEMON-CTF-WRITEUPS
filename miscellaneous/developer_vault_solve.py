
import json, sys, hashlib, hmac, base64
sys.path.insert(0, '/tmp/misc/dev_pack/player_bundle')
from runtime import START_KEY, answer_digest, decrypt_stage, load_stage, next_key, decrypt_credits

# handlers: kind -> function(artifact, prompt) -> answer string
HANDLERS = {}

def h(kind):
    def deco(fn):
        HANDLERS[kind] = fn
        return fn
    return deco

import struct

@h('be32')
def _(a, p):
    raw = bytes.fromhex(a['header_hex'])
    return str(struct.unpack('>I', raw[0:4])[0])

import zlib

CARRY = {}

def _sha10(s):
    return hashlib.sha256(s.encode()).hexdigest()[:10]

@h('final_gate')
def _(a, p):
    seq = CARRY['99']
    proof = hashlib.sha256(f"ENGINE-ROOM|{seq}|{CARRY['96']}".encode()).hexdigest()[:16]
    return f'FINAL:{seq}:{proof}'

@h('unlock_sequence')
def _(a, p):
    parts = [CARRY[str(i)] for i in (92, 93, 94, 95, 97, 98)]
    return 'DEV:' + ':'.join(parts)

@h('decoy_gate_b')
def _(a, p):
    return hashlib.sha256(f"B|{CARRY['96']}|{CARRY['94']}".encode()).hexdigest()[:8]

@h('decoy_gate_a')
def _(a, p):
    return hashlib.sha256(f"A|{CARRY['96']}|{CARRY['91']}".encode()).hexdigest()[:8]

@h('final_checksum')
def _(a, p):
    s = '|'.join(CARRY[str(i)] for i in range(91, 96))
    return hashlib.sha256(s.encode()).hexdigest()[:12]

@h('base36_join')
def _(a, p):
    n = int(CARRY['36'].split('-')[1])
    xs, ys = CARRY['47'].split(',')
    x, y = abs(int(xs)) % 1000, abs(int(ys)) % 1000
    first6 = CARRY['89'][:6]
    try:
        sv = int(first6, 16)
    except ValueError:
        sv = sum(ord(c) for c in first6)
    total = n * 1000000 + x * 1000 + y + sv
    digits = '0123456789abcdefghijklmnopqrstuvwxyz'
    out = ''
    while total:
        out = digits[total % 36] + out
        total //= 36
    return out or '0'

@h('save_transform')
def _(a, p):
    return CARRY['89'][::-1]

@h('action_proof')
def _(a, p):
    xs, ys = CARRY['47'].split(',')
    x, y = int(xs), int(ys)
    return [f'X{x:+03d}Y{y:+03d}', f'X{x:+3d}Y{y:+3d}']

@h('forecast_route')
def _(a, p):
    xx = int(CARRY['36'].split('-')[1])
    return a['routes'][xx % len(a['routes'])]

@h('memory_checksum')
def _(a, p):
    return hashlib.sha256(f"{CARRY['36']}|{CARRY['47']}|{CARRY['89']}".encode()).hexdigest()[:12
    ]

@h('ledger_check')
def _(a, p):
    code = CARRY['89']
    pref = hashlib.sha256(('LEDGER|' + code).encode()).hexdigest()[:8]
    return 'VALID' if pref == a['expected_ledger_prefix'] else 'INVALID'

@h('three_save')
def _(a, p):
    frag = a['save_records']['A'] + a['save_records']['B']
    combined = f"{CARRY['36']}|{CARRY['47']}|{frag}"
    return _sha10(combined)

@h('missing_score')
def _(a, p):
    return str(a['aggregate_score'] - sum(a['known_scores']))

@h('sort_join')
def _(a, p):
    return ''.join(f['tag'] for f in sorted(a['fragments'], key=lambda f: f['seq']))

@h('replay_graph')
def _(a, p):
    from collections import deque
    adj = {}
    for u, v in a['edges']:
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)
    q = deque([(a['start'], [a['start']])])
    seen = {a['start']}
    while q:
        u, path = q.popleft()
        if u == a['goal']:
            return ['>'.join(path), ' > '.join(path)]
        for v in sorted(adj.get(u, ())):
            if v not in seen:
                seen.add(v)
                q.append((v, path + [v]))
    return 'NONE'

@h('cross_xor')
def _(a, p):
    v = 0
    for h in a['fragments_hex']:
        v ^= int(h, 16)
    return format(v, '02x')

@h('weighted_score')
def _(a, p):
    return str(sum(a['scores'][k] * a['weights'][k] for k in a['scores']))

@h('difference')
def _(a, p):
    u = a['unlocks']
    res = set(u['P1']) - set(u['P2']) - set(u['P3'])
    return [','.join(sorted(res)), ', '.join(sorted(res))]

@h('intersection')
def _(a, p):
    sets = [set(v) for v in a['achievements'].values()]
    common = set.intersection(*sets)
    return [','.join(sorted(common)), ', '.join(sorted(common))]

@h('timestamp')
def _(a, p):
    from datetime import datetime
    best = max(a['records'], key=lambda r: datetime.fromisoformat(r['local']).timestamp())
    return best['save']

@h('hidden_directory')
def _(a, p):
    addr = a['directory_base'] + a['hidden_entry_offset']
    return a['directory_dump']['entries'][str(addr)]

@h('sequence_gap')
def _(a, p):
    seqs = sorted(r['sequence'] for r in a['records'])
    for x, y in zip(seqs, seqs[1:]):
        if y - x > 1:
            return str(x + 1)
    return 'NONE'

@h('dev_checksum')
def _(a, p):
    for r in a['records']:
        if format(zlib.crc32(r['value'].encode()) & 0xffffffff, '08x') == r['crc32']:
            return r['slot']
    return 'NONE'

@h('magic_repair')
def _(a, p):
    return a['documented_magic_ascii']

@h('rle_repair')
def _(a, p):
    return str(a['expected_decoded_width'] - sum(r for r in a['runs'] if r is not None))

@h('duplicate_slot')
def _(a, p):
    ok = [r for r in a['records'] if format(zlib.crc32(r['payload'].encode()) & 0xffffffff, '08x') == r['crc32']]
    r = max(ok, key=lambda r: r['sequence'])
    return str(r['sequence'])

@h('tlv_repair')
def _(a, p):
    rec = a['damaged_records'][0]
    return str(len(bytes.fromhex(rec['payload_hex'])))

@h('byte_order')
def _(a, p):
    raw = bytes.fromhex(a['stored_hex'])[::-1]
    return str(int.from_bytes(raw, 'big'))

@h('parity_repair')
def _(a, p):
    m = a['observed_matrix']
    R, C = len(m), len(m[0])
    bad_r = [r for r in range(R) if sum(m[r]) % 2 != a['row_parity_expected'][r]]
    bad_c = [c for c in range(C) if sum(m[r][c] for r in range(R)) % 2 !=
    a['column_parity_expected'][c]]
    return f'{bad_r[0]},{bad_c[0]}'

@h('crc_repair')
def _(a, p):
    i = a['unknown_index_zero_based']
    s = a['damaged_ascii']
    for ch in a['candidate_alphabet']:
        cand = s[:i] + ch + s[i+1:]
        if format(zlib.crc32(cand.encode()) & 0xffffffff, '08x') == a['crc32_expected']:
            return cand
    return 'NONE'

@h('debug_command')
def _(a, p):
    return f"dev unlock --slot={a['slot']} --proof={a['proof']}"

@h('precedence_eval')
def _(a, p):
    import re
    e = a['expression']
    e = re.sub(r'\bAND\b', 'and', e)
    e = re.sub(r'\bOR\b', 'or', e)
    e = re.sub(r'\bNOT\b', 'not', e)
    return 'TRUE' if eval(e, {}, dict(a['values'])) else 'FALSE'

@h('quoted')
def _(a, p):
    esc = a['argument'].replace('\\', '\\\\').replace('"', '\\"')
    return f'"{esc}"'

@h('alias_resolve')
def _(a, p):
    return a['aliases'][a['input_alias']]

@h('nested_parse')
def _(a, p):
    import re
    leaves = []
    def parse(s):
        m = re.match(r'(\w+)\((.*)\)$', s)
        if not m:
            return
        name, inner = m.group(1), m.group(2)
        children = []
        depth = 0; cur = ''
        for ch in inner:
                if ch in '()':
                    depth += 1 if ch == '(' else -1
                    cur += ch
                elif ch == ',' and depth == 0:
                    children.append(cur.strip()); cur = ''
                else:
                    cur += ch
        if cur.strip(): children.append(cur.strip())
        if any('(' in c for c in children):
            for c in children: parse(c)
        else:
            leaves.append(f"{name}({','.join(children)})")
    parse(a['expression'])
    return [','.join(leaves), ', '.join(leaves)]

@h('proof_suffix')
def _(a, p):
    c = a['command_without_suffix']
    return f"{c}#{format(sum(c.encode('utf-8')) % 97, '02d')}"

@h('separator')
def _(a, p):
    return f"OPEN|{a['slot']}|{a['checksum']}"

@h('case_verb')
def _(a, p):
    import re
    m = re.search(r"verb == '(\w+)': mode='read'", a['source_fragment'])
    return m.group(1)

@h('percent_encode')
def _(a, p):
    import urllib.parse
    return urllib.parse.quote(a['raw_argument'], safe='')

@h('tokenize')
def _(a, p):
    return a['input_parts']['proof']

@h('pin_csp')
def _(a, p):
    import itertools
    for d in itertools.product(range(10), repeat=4):
        if len(set(d)) != 4: continue
        d0, d1, d2, d3 = d
        ok = True
        for c in a['constraint_types']:
            if c['type'] == 'sum' and d0+d1+d2+d3 != c['value']: ok = False
            elif c['type'] == 'alternating' and d0-d1+d2-d3 != c['value']: ok = False
            elif c['type'] == 'first_parity' and (d0 % 2 == 1) != (c['parity'] == 'odd'): ok = False
            elif c['type'] == 'pair_sum' and d0+d3 != c['value']: ok = False
            elif c['type'] == 'product' and d1*d2 != c['value']: ok = False
            if not ok: break
        if ok:
            return ''.join(map(str, d))
    return 'NONE'

@h('schedule_csp')
def _(a, p):
    import itertools
    ts = a['switches']
    lo, hi = (int(x) for x in a['slot_domain'].split(';')[0].split('..'))
    for perm in itertools.permutations(range(lo, hi + 1)):
        slot = dict(zip(ts, perm))
        ok = True
        for c in a['constraint_types']:
            if c['type'] == 'before' and not slot[c['a']] < slot[c['b']]: ok = False
            elif c['type'] == 'adjacent' and abs(slot[c['a']] - slot[c['b']]) != 1: ok = False
            elif c['type'] == 'not_slot' and slot[c['task']] == c['slot']: ok = False
            elif c['type'] == 'parity':
                even = slot[c['task']] % 2 == 0
                if (c['parity'] == 'even') != even: ok = False
            if not ok: break
        if ok:
            return ''.join(sorted(ts, key=lambda t: slot[t]))
    return 'NONE'

@h('circuit')
def _(a, p):
    import re
    e = a['gate_expression']
    e = re.sub(r'\bAND\b', '&', e)
    e = re.sub(r'\bOR\b', '|', e)
    e = re.sub(r'\bXOR\b', '^', e)
    e = re.sub(r'NOT\s+(\w+)', r'(1-\1)', e)
    return str(eval(e, {}, dict(a['inputs'])))

@h('modular_csp')
def _(a, p):
    import re, itertools
    m = a['modulus']
    sols = []
    for x, y in itertools.product(range(m), repeat=2):
        ok = True
        for c in a['constraints']:
            g = re.match(r'(.+) = (\d+) \(mod \d+\)', c)
            expr, rhs = g.group(1), int(g.group(2))
            if eval(expr, {}, {'x': x, 'y': y}) % m != rhs % m:
                ok = False; break
        if ok: sols.append((x, y))
    x, y = sols[0]
    return [f'{x},{y}', f'{x}{y}']

@h('latin_csp')
def _(a, p):
    g = [row[:] for row in a['grid']]
    n = len(g)
    def solve():
        for r in range(n):
            for c in range(n):
                if g[r][c] == 0:
                    for v in range(1, n + 1):
                        if v not in g[r] and all(g[i][c] != v for i in range(n)):
                            g[r][c] = v
                            if solve(): return True
                            g[r][c] = 0
                    return False
        return True
    solve()
    vals = []
    orig = a['grid']
    for r in range(n):
        for c in range(n):
            if orig[r][c] == 0:
                vals.append(str(g[r][c]))
    return [','.join(vals), ''.join(vals)]

@h('precedence_csp')
def _(a, p):
    import itertools, re
    cons = [re.match(r'(\w+) before (\w+)', c).groups() for c in a['constraints']]
    for perm in itertools.permutations(a['tasks']):
        pos = {t: i for i, t in enumerate(perm)}
        if all(pos[u] < pos[v] for u, v in cons):
            return ''.join(perm)
    return 'NONE'

@h('bitvector_csp')
def _(a, p):
    chain = sorted(a['xor_equations'])
    sols = []
    for va in range(256):
        b = va ^ int(chain[0].split('=')[1], 16)
        c = b ^ int(chain[1].split('=')[1], 16)
        d = c ^ int(chain[2].split('=')[1], 16)
        if max(b, c, d) > 255: continue
        if va + b + c + d != int(a['sum_constraint'].split('=')[1]): continue
        w = int(a['weighted_constraint'].split('=')[1])
        if va + 2 * b + 3 * c + 5 * d != w: continue
        import re
        m = re.search(r'= (\d+)$', a['cross_constraint'])
        if (va * d + b * c) % 257 != int(m.group(1)): continue
        sols.append((va, b, c, d))
    va, b, c, d = sols[0]
    return ','.join(format(v, '02x') for v in (va, b, c, d))

@h('color_csp')
def _(a, p):
    import itertools, re
    excl = {}
    for c in a['clues']:
        m = re.match(r'(\w+) is not (\w+)', c)
        excl.setdefault(m.group(1), set()).add(m.group(2))
    ents = a['entities']
    for perm in itertools.permutations(a['colors']):
        ok = all(perm[i] not in excl.get(ents[i], set()) for i in range(len(ents)))
        if ok:
            pairs = [f'{e}={c}' for e, c in zip(ents, perm)]
            return [','.join(pairs), ','.join(perm), ', '.join(pairs), ';'.join(pairs)]
    return 'NONE'

@h('xor_csp')
def _(a, p):
    import re
    xs = {int(x.split('=')[1], 16) for x in a['xor_equations']}
    chain = sorted(a['xor_equations'])
    sols = []
    for va in range(256):
        b = va ^ int(chain[0].split('=')[1], 16)
        c = b ^ int(chain[1].split('=')[1], 16)
        d = c ^ int(chain[2].split('=')[1], 16)
        if max(b, c, d) > 255: continue
        if va + b + c + d != int(a['sum_constraint'].split('=')[1]): continue
        w = int(a['weighted_constraint'].split('=')[1])
        if va + 2 * b + 3 * c + 4 * d != w: continue
        sols.append((va, b, c, d))
    va, b, c, d = sols[0]
    return ','.join(format(v, '02x') for v in (va, b, c, d))

@h('linear_csp')
def _(a, p):
    import itertools, re
    vs = a['variables']
    lo, hi = (int(x) for x in a['range'].split('..'))
    envs = []
    for combo in itertools.product(range(lo, hi + 1), repeat=len(vs)):
        env = dict(zip(vs, combo))
        ok = True
        for eq in a['equations']:
            lhs, rhs = eq.split('=')
            if eval(lhs, {}, env) != int(rhs):
                ok = False; break
        if ok:
            envs.append(env)
    e = envs[0]
    vals = [str(e[v]) for v in vs]
    return [','.join(vals), ''.join(vals), ', '.join(vals), ','.join(f'{v}={e[v]}' for v in vs)]

@h('loop_expansion')
def _(a, p):
    return str(a['initial_x'] + a['count'] * a['delta'])

@h('stack_machine')
def _(a, p):
    st = []
    for op, v in a['operations']:
        if op == 'PUSH': st.append(v)
        elif op == 'POP': st.pop()
    return st[-1]

@h('event_precedence')
def _(a, p):
    es = sorted(a['events'], key=lambda x: (-x['priority'], x['event']))
    return [','.join(x['event'] for x in es), ', '.join(x['event'] for x in es)]

@h('action_replay')
def _(a, p):
    x, y = a['initial_position']
    d = {'R': (1, 0), 'L': (-1, 0), 'U': (0, -1), 'D': (0, 1)}
    for s in a['script']:
        dx, dy = d[s]
        x += dx; y += dy
    return [f'{x},{y}', f'({x},{y})']

@h('opcode_checksum')
def _(a, p):
    v = sum((i + 1) * x for i, x in enumerate(a['opcode_values'])) % a['modulus']
    return [format(v, '02d'), str(v)]

@h('frame_gate')
def _(a, p):
    for i in a['inputs']:
        if i['frame'] == a['required_frame']:
            return f"{i['frame']}:{i['input']}"
    return 'NONE'

@h('input_latch')
def _(a, p):
    held = set()
    for ev, k in a['events']:
        if ev == 'press': held.add(k)
        else: held.discard(k)
    return ','.join(sorted(held)) if held else 'NONE'

@h('action_macro')
def _(a, p):
    import re
    x = y = 0
    d = {'R': (1, 0), 'L': (-1, 0), 'U': (0, -1), 'D': (0, 1)}
    for m in a['macro']:
        g = re.match(r'([RLUD])(\d+)', m)
        dx, dy = d[g.group(1)]
        n = int(g.group(2))
        x += dx * n; y += dy * n
    return [f'{x},{y}', f'({x},{y})']

@h('frame_ledger')
def _(a, p):
    x, y = a['start']
    d = {'R': (1, 0), 'L': (-1, 0), 'U': (0, -1), 'D': (0, 1)}
    for f in a['frames']:
        dx, dy = d[f['command']]
        x += dx; y += dy
    return [f'{x},{y}', f'({x},{y})']

@h('hook_order')
def _(a, p):
    hs = sorted(a['hooks'], key=lambda x: (-x['priority'], x['name']))
    return [','.join(x['name'] for x in hs), ', '.join(x['name'] for x in hs)]

@h('rng_commit')
def _(a, p):
    s = ','.join(str(v) for v in a['observed_outputs'])
    return hashlib.sha256(s.encode()).hexdigest()[:12]

@h('xor_stream')
def _(a, p):
    x = bytes(x ^ y for x, y in zip(bytes.fromhex(a['stream_a_hex']),
    bytes.fromhex(a['stream_b_hex'])))
    return x.hex()

@h('shuffle')
def _(a, p):
    items = list(a['initial_items'])
    for i, j in a['swaps']:
        items[i], items[j] = items[j], items[i]
    return items[a['final_slot_zero_based']]

@h('rejection')
def _(a, p):
    import re
    m = re.search(r'reject values >= (\d+)', a['rule'])
    lim = int(m.group(1))
    for d in a['draws']:
        if d < lim:
            return a['table'][d % a['range_size']]
    return 'NONE'

@h('loot_forecast')
def _(a, p):
    s = (1103515245 * a['observed_state'] + 12345) % (2 ** 31)
    return 'loot-' + format(s % 97, '02d')

@h('seed_recovery')
def _(a, p):
    return str((a['a'] * a['observed_output'] + a['c']) % a['m'])

@h('lcg_reverse')
def _(a, p):
    inv = pow(a['a'], -1, a['m'])
    return str(((a['observed_next'] - a['c']) * inv) % a['m'])

@h('bounded_draw')
def _(a, p):
    return a['mapping'][a['state'] % len(a['mapping'])]

@h('xorshift')
def _(a, p):
    M = 0xffffffff
    x = int(a['state_hex'], 16)
    x = (x ^ (x << 13)) & M
    x = (x ^ (x >> 17)) & M
    x = (x ^ (x << 5)) & M
    return format(x, '08x')

@h('lcg_next')
def _(a, p):
    return str((a['a'] * a['observed_state'] + a['c']) % a['m'])

@h('inscription')
def _(a, p):
    rows = [r.replace(' ', '') for r in a['grid']]
    return ''.join(rows[r][c] for r, c in a['coordinates'])

@h('door_logic')
def _(a, p):
    import re
    st = a['state']
    open_doors = []
    for d, rule in a['door_rules'].items():
        expr = re.sub(r'\bAND\b', 'and', rule)
        expr = re.sub(r'\bOR\b', 'or', expr)
        expr = re.sub(r'\bNOT\b', 'not', expr)
        if eval(expr, {}, st):
            open_doors.append(d)
    open_doors.sort()
    return [','.join(open_doors), ', '.join(open_doors)]

@h('trigger')
def _(a, p):
    st = dict(a['initial_switches'])
    for e in a['events']:
        _, name = e.split()
        st[name] = not st[name]
    return ''.join('1' if st[k] else '0' for k in sorted(st))

@h('morse')
def _(a, p):
    return ''.join(a['local_codebook'][g] for g in a['tile_glyphs'])

@h('tile_dictionary')
def _(a, p):
    return ''.join(a['dictionary'][t] for t in a['tile_ids'])

@h('rle')
def _(a, p):
    return ''.join(ch * n for ch, n in a['runs'])

@h('overlay')
def _(a, p):
    v = int(a['plane_a_byte'], 16) ^ int(a['plane_b_byte'], 16)
    return chr(v)

@h('transform')
def _(a, p):
    W, H = a['board_size']
    x, y = a['point']
    for op in a['operations']:
        if op == 'flipx': x = W - 1 - x
        elif op == 'flipy': y = H - 1 - y
        elif op == 'rotate90cw': x, y = H - 1 - y, x
        elif op == 'rotate90ccw': x, y = y, W - 1 - x
    return [f'{x},{y}', f'({x},{y})']

@h('bfs')
def _(a, p):
    from collections import deque
    g = a['grid']
    R, C = len(g), len(g[0])
    for r in range(R):
        for c in range(C):
            if g[r][c] == 'S': s = (r, c)
            if g[r][c] == 'G': t = (r, c)
    order = [('D', 1, 0), ('L', 0, -1), ('R', 0, 1), ('U', -1, 0)]
    q = deque([(s, '')])
    seen = {s}
    while q:
        (r, c), path = q.popleft()
        if (r, c) == t:
            return path
        for d, dr, dc in order:
            nr, nc = r + dr, c + dc
            if 0 <= nr < R and 0 <= nc < C and g[nr][nc] != '#' and (nr, nc) not in seen:
                seen.add((nr, nc))
                q.append(((nr, nc), path + d))
    return 'NONE'

@h('room_coords')
def _(a, p):
    for r, row in enumerate(a['grid']):
        c = row.find('R')
        if c >= 0:
            return [f'{r},{c}', f'{c},{r}', f'({r},{c})', f'{r}, {c}']
    return 'NONE'

@h('object_graph')
def _(a, p):
    adj = {}
    for u, v in a['edges']:
        adj.setdefault(u, []).append(v)
    path = []
    def dfs(u, seen):
        if u == a['target']:
            path.append(u); return True
        for v in adj.get(u, []):
            if v not in seen:
                if dfs(v, seen | {v}):
                    path.append(u); return True
        return False
    dfs(a['start'], {a['start']})
    pth = list(reversed(path))
    return ['>'.join(pth), ' > '.join(pth)]

@h('mangled')
def _(a, p):
    import re
    m = re.search(r'self\.(\w+)', a['source_line'])
    attr = m.group(1).lstrip('_')
    mangled = f"_{a['class_name']}__{attr}"
    return [a['stored_value'], mangled]

@h('branch')
def _(a, p):
    env = {k: v for k, v in a.items() if k not in ('source', 'question') and isinstance(v,
    (int, str, bool))}
    exec(a['source'], {}, env)
    return str(env.get('result'))

@h('defaults')
def _(a, p):
    import re
    m = re.search(r'\((.+)\)', a['call'])
    inside = m.group(1).strip()
    cands = []
    if inside:
        cands.append(inside)
    d = re.search(r'code=(\d+)', a['signature'])
    if d:
        cands.append(d.group(1))
    return cands

@h('iterator')
def _(a, p):
    return str(a['values'][a['already_consumed']])

@h('cached_property')
def _(a, p):
    return str(a['base_initial'] * a['multiplier'])

@h('mutable_default')
def _(a, p):
    items = list(a['initial_default_list']) + a['calls_append']
    return [','.join(items), ', '.join(items)]

@h('closure')
def _(a, p):
    return str(a['initial_counter'] + a['calls'] * a['increment_per_call'])

@h('generator')
def _(a, p):
    import re
    m = re.search(r'start=(\d+), step=(\d+)', a['yield_expression'])
    start, step = int(m.group(1)), int(m.group(2))
    return str(start + a['already_consumed'] * step)

@h('alias')
def _(a, p):
    items = list(a['initial_list']) + [a['NEW_TAG']]
    return [','.join(items), ', '.join(items)]

@h('transition')
def _(a, p):
    return str(a['starting_score'] + sum(e['delta'] for e in a['events']))

@h('slot_select')
def _(a, p):
    for r in a['records']:
        if hashlib.sha256(r['value'].encode()).hexdigest()[:12] == r['sha256_prefix']:
            return [r['slot'], r['value']]
    return 'NONE'

@h('migration')
def _(a, p):
    old = list(a['migration_map'])[0]
    return str(a['legacy_save'][old])

@h('decode_stack')
def _(a, p):
    return bytes.fromhex(base64.b64decode(a['wrapped']).decode('ascii')).decode('ascii')

@h('tlv')
def _(a, p):
    vals = [bytes.fromhex(r['value_hex']).decode('ascii') for r in a['records'] if r['type'] == a['requested_type']]
    return vals
@h('length_record')
def _(a, p):
    raw = bytes.fromhex(a['record_hex'])
    return raw[1:1+raw[0]].decode('ascii')

@h('bitmask')
def _(a, p):
    m = int(a['mask'], 16)
    names = [a['bits'][str(i)] for i in sorted(int(x) for x in a['bits']) if m >> i & 1]
    return [','.join(names), ', '.join(names), '|'.join(names)]

@h('json_diff')
def _(a, p):
    b, af = a['before'], a['after']
    diff = [k for k in b if b[k] != af.get(k)]
    k = diff[0]
    v = af[k]
    vs = str(v).lower() if isinstance(v, bool) else str(v)
    return [k, f"{k}={vs}", f"{k}:{vs}", vs, f"{k} {vs}"]

@h('crc_pick')
def _(a, p):
    for r in a['records']:
        c = format(zlib.crc32(bytes.fromhex(r['payload_hex'])) & 0xffffffff, '08x')
        if c == r['crc32']:
            return r['id']
    return 'NONE'

def run():
    key = START_KEY
    answers = {}
    for n in range(1, 101):
        st = load_stage(n)
        body = decrypt_stage(st, key)
        kind = body['kind']
        fn = HANDLERS.get(kind)
        if fn is None:
            print(f'L{n:03d} UNHANDLED kind={kind}')
            print('PROMPT:', body['prompt'])
            print('ARTIFACT:', json.dumps(body['artifact'], indent=1)[:3000])
            return answers, key, n
        res = fn(body['artifact'], body['prompt'])
        cands = res if isinstance(res, list) else [res]
        ans = None
        for c in cands:
            c = str(c)
            if answer_digest(st['salt'], c) == st['answer_hash']:
                ans = c
                break
        if ans is None:
            print(f'L{n:03d} WRONG kind={kind} cands={cands[:6]!r}')
            print('PROMPT:', body['prompt'])
            print('ARTIFACT:', json.dumps(body['artifact'], indent=1)[:3000])
            return answers, key, n
        answers[str(n)] = ans
        CARRY[str(n)] = ans
        CARRY[str(n)] = ans
        key = next_key(key, n, ans)
    print('ALL 100 SOLVED')
    print('FLAG:', decrypt_credits(key))
    return answers, key, 101

if __name__ == '__main__':
    run()
