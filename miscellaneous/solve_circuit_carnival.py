#!/usr/bin/env python3
"""Circuit Carnival / Logic Arcade -- offline, reproducible solve and verifier.

Usage:
    python3 solve_circuit_carnival.py logic_arcade.zip
    python3 solve_circuit_carnival.py /path/to/logic_arcade_player

Only Python standard-library modules. No network traffic.

The ledger consists of answers obtained from the individual puzzles, not
secrets extracted from the encrypted lock format. Every handoff is validated
using the original lock's HMAC before it is decrypted. Extra assertions
independently solve several of the computational puzzles.
"""
from __future__ import annotations

import argparse
import base64
from collections import deque
import hashlib
import heapq
import hmac
from itertools import permutations, product
import json
from pathlib import Path
import sys
import zipfile
import zlib

# (Machine number, output token, concise justification)
LEDGER = [
    (1, 'RING', '4x4 Latin grid row 1 = 1234; 1/2/3/4 => R/I/N/G'),
    (2, 'GACGWAG', 'Wolf/goat/cabbage legal crossing sequence'),
    (3, 'KNAVE', 'B claims they are the same kind: a false statement'),
    (4, 'PIXEL', 'Solve the 5x29 nonogram; five glyphs P I X E L'),
    (5, 'LAMP', 'Ordering L before A before M immediately before P'),
    (6, 'STACK', 'Stacklet ASCII emissions 83,84,65,67,75'),
    (7, 'PARSE', 'Postfix arithmetic -> 16,1,18,19,5 -> A1Z26'),
    (8, 'INVAR', 'Mod-5 states 1,2,3,4,0 use the wheel legend'),
    (9, 'TRACE', 'Correct range(0,6) to range(0,5)'),
    (10, 'RESET', 'Initial letters of READ,ECHO,SET,ECHO,TURN'),
    (11, 'STABLE', 'Conway Life 2x2 block is a still life'),
    (12, 'TURTLE', 'Read marked coordinates in first-visited order'),
    (13, 'PERIOD', 'Name for number of transitions per cycle'),
    (14, 'ABCD', 'FIFO dequeues return A,B,C,D'),
    (15, 'EXIT', 'Toggle switch in A, cross into B, reach T'),
    (16, 'FLOW', 'Gridlang reads F,L,O,W and halts on #'),
    (17, 'MIRROR', 'DFS A,B,D,E,C,F maps to M,I,R,R,O,R'),
    (18, 'DATA', 'Matching reflected row pairs: D,A,T,A'),
    (19, 'PATCH', 'Replace faulty X with intended T: P,A,T,C,H'),
    (20, 'ORBIT', 'Pointer revisits same coordinate/direction state'),
    (21, 'KEY', 'Chest item; accepted by the authenticated next lock'),
    (22, 'DOORB', 'Exactly one true sign requires exit behind door B'),
    (23, 'STATE', 'Finite-state transducer output S,T,A,T,E'),
    (24, 'SNACK', 'Key(2)+lens(2)+snack(3) = capacity 7'),
    (25, 'DAWN', 'Acrostic first letters of four guard-message lines'),
    (26, 'RGBRB', 'Graph colors A=R,B=G,C=B,D=R,E=B'),
    (27, 'SLOT3', 'Unique schedule A1,D2,B3,C4'),
    (28, 'CDE', 'Exact cover: C={5,6},D={1,3},E={2,4}'),
    (29, 'UNIQUE', 'Exactly one ordering A,C,B,D meets all rules'),
    (30, '731', 'A=7,B=3,C=1; distinct descending digits'),
    (31, '3TO1', '3 XOR 4 XOR 5=2, change 3->1 to zero Nim-sum'),
    (32, 'AFBC', 'Only code matching all four Mastermind feedback pairs'),
    (33, 'MINIMAX', 'MIN children yield 4,5,2; MAX selects 5'),
    (34, 'MISERE', 'Last stone loses: misere Nim convention'),
    (35, 'NIM', 'Impartial heap-game family'),
    (36, 'LOGIC', 'Loop emits L,O,G,I,C at x=3..7'),
    (37, 'SAT', 'A=B=C=true satisfies the CNF clauses'),
    (38, 'PRODUCT', '2x3 ordered-pair product automaton'),
    (39, 'PROOF', 'Loop invariant 0<=x<=n proves postcondition'),
    (40, 'PARITY', 'Flipping a row/column of four retains even parity'),
    (41, 'OFFSET', 'Zero-based field start locations within a save record'),
    (42, 'CRC32', 'Correct 12345678I to 123456789; CRC=0xCBF43926'),
    (43, 'DELTA', 'Each incremental save change-set is a delta'),
    (44, 'DEVNOTE', 'Padding bytes DEV + tag NOTE'),
    (45, 'MINT', 'JSON Pointer /slots/1/name -> mint, uppercase'),
    (46, 'ULR', 'Lowest-cost route S-A-B-T (total 3)'),
    (47, 'COMBO', 'Ingredient combining recipe is a combo'),
    (48, 'VERIFY', 'Recompute SHA256 checksums rather than trust display'),
    (49, 'BOLT', 'XOR 5-bit letters with 10101 -> 2,15,12,20'),
]

PREFIX = 'logic_arcade_player/'


def get_lock_bytes(location: Path, number: int) -> bytes:
    relative = f'locks/{number:02d}.lock'
    if location.is_file() and zipfile.is_zipfile(location):
        with zipfile.ZipFile(location) as archive:
            try:
                return archive.read(PREFIX + relative)
            except KeyError as err:
                raise RuntimeError(f'Missing {relative} in ZIP') from err
    folder = location
    if (location / PREFIX).is_dir():
        folder = location / PREFIX
    return (folder / relative).read_bytes()


def xor_stream(data: bytes, key: bytes, nonce: str) -> bytes:
    """Bit-for-bit equivalent to the package's arcade.py._xor_stream."""
    output = bytearray()
    cursor = 0
    while cursor < len(data):
        block = hashlib.sha256(
            key + nonce.encode() + cursor.to_bytes(8, 'big')
        ).digest()
        portion = data[cursor:cursor + len(block)]
        output.extend(a ^ b for a, b in zip(portion, block))
        cursor += len(portion)
    return bytes(output)


def unlock(location: Path, number: int, previous: str) -> dict:
    packet = json.loads(get_lock_bytes(location, number))
    assert packet['layer'] == number, f'Unexpected layer in lock {number}'
    nonce = packet['nonce']
    encrypted = base64.b64decode(packet['ciphertext_b64'], validate=True)
    key = hashlib.sha256(
        b'LOGIC_ARCADE_LOCK_V1|' + previous.strip().encode() + b'|' + nonce.encode()
    ).digest()
    expected = hmac.new(key, nonce.encode() + encrypted, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, packet['tag_sha256']):
        raise ValueError(f'Machine {number:02d}: handoff {previous!r} failed HMAC')
    payload = json.loads(xor_stream(encrypted, key, nonce).decode('utf-8'))
    assert payload['id'] == number
    return payload


def shortest_path(edges):
    """Dijkstra; tie-breaking matches the provided runner's (cost,path)."""
    graph = {}
    for src, dst, letter, cost in edges:
        graph.setdefault(src, []).append((dst, letter, cost))
    heap = [(0, 'S', '')]
    best = {'S': (0, '')}
    while heap:
        cost, node, path = heapq.heappop(heap)
        if best[node] != (cost, path):
            continue
        if node == 'T':
            return cost, path
        for nxt, letter, weight in graph.get(node, []):
            cand = cost + weight, path + letter
            if nxt not in best or cand < best[nxt]:
                best[nxt] = cand
                heapq.heappush(heap, (cand[0], nxt, cand[1]))
    raise RuntimeError('No S-to-T route found')


def count_nonogram_runs(row):
    counts = []
    count = 0
    for cell in list(row) + ['.']:
        if cell == '#':
            count += 1
        elif count:
            counts.append(count)
            count = 0
    return counts or [0]


def test_puzzle_calculations():
    """Recalculate representative logic puzzles, not just a token lookup."""
    # 1. Sudoku-derived row 1234 maps to RING.
    sudoku = [[1, 2, 3, 4], [3, 4, 1, 2], [2, 1, 4, 3], [4, 3, 2, 1]]
    target = {1, 2, 3, 4}
    assert all(set(row) == target for row in sudoku)
    assert all({sudoku[r][c] for r in range(4)} == target for c in range(4))
    assert ''.join({1:'R', 2:'I', 3:'N', 4:'G'}[d] for d in sudoku[0]) == 'RING'

    # 2. Crossing sequence is safe and ends with everybody on right bank.
    left = {'F', 'W', 'G', 'C'}
    right = set()
    for item in 'GACGWAG':
        source = left if 'F' in left else right
        destination = right if source is left else left
        assert item == 'A' or item in source
        source.remove('F')
        destination.add('F')
        if item != 'A':
            source.remove(item)
            destination.add(item)
        for bank in (left, right):
            if 'F' not in bank:
                assert not ({'W', 'G'} <= bank or {'G', 'C'} <= bank)
    assert right == {'F', 'W', 'G', 'C'}

    # 4. A solution with five standard block letters fits all supplied runs.
    letters = {
        'P': ['####.', '#...#', '####.', '#....', '#....'],
        'I': ['#####', '..#..', '..#..', '..#..', '#####'],
        'X': ['#...#', '.#.#.', '..#..', '.#.#.', '#...#'],
        'E': ['#####', '#....', '####.', '#....', '#####'],
        'L': ['#....', '#....', '#....', '#....', '#####'],
    }
    picture = ['.'.join(letters[x][r] for x in 'PIXEL') for r in range(5)]
    row_clues = [[4,5,1,1,5,1],[1,1,1,1,1,1,1],[4,1,1,4,1],
                 [1,1,1,1,1,1],[1,5,1,1,5,5]]
    col_clues = [
        [5],[1,1],[1,1],[1,1],[1],[0],
        [1,1],[1,1],[5],[1,1],[1,1],[0],
        [1,1],[1,1],[1],[1,1],[1,1],[0],
        [5],[1,1,1],[1,1,1],[1,1,1],[1,1],[0],
        [5],[1],[1],[1],[1],
    ]
    assert [count_nonogram_runs(r) for r in picture] == row_clues
    assert [count_nonogram_runs([r[i] for r in picture]) for i in range(29)] == col_clues

    # 7. Postfix arithmetic: compute results, then apply A1Z26.
    expressions = [(10,6,'ADD'),(3,2,'SUB'),(9,9,'ADD'),(20,1,'SUB'),(10,5,'SUB')]
    nums = [(a+b if op=='ADD' else a-b) for a,b,op in expressions]
    assert nums == [16,1,18,19,5]
    assert ''.join(chr(64+n) for n in nums) == 'PARSE'

    # 14. FIFO queue behavior.
    q = deque()
    result = []
    for verb, item in [('ENQ','A'),('ENQ','B'),('DEQ',None),('ENQ','C'),
                       ('ENQ','D'),('DEQ',None),('DEQ',None),('DEQ',None)]:
        if verb == 'ENQ': q.append(item)
        else: result.append(q.popleft())
    assert ''.join(result) == 'ABCD'

    # 22. Only door B makes exactly one sign true.
    doors = []
    for exit_at in 'ABC':
        signs = [exit_at=='B', exit_at!='B', exit_at!='B']
        if sum(signs) == 1:
            doors.append(exit_at)
    assert doors == ['B']

    # 27. All permutations are checked against the schedule rules.
    schedules = []
    for arrangement in permutations('ABCD'):
        loc = {person: arrangement.index(person) + 1 for person in arrangement}
        if (loc['A']==1 and loc['A']<loc['C'] and
            loc['D']==loc['A']+1 and loc['B']!=4 and loc['C']!=1):
            schedules.append(arrangement)
    assert schedules == [('A','D','B','C')]

    # 29. Unique logic-grid arrangement.
    candidates=[]
    for arrangement in permutations(('Ash','Birch','Coral','Dune')):
        pos={name: arrangement.index(name)+1 for name in arrangement}
        if (pos['Ash']<pos['Coral'] and pos['Birch'] not in (1,4)
            and pos['Dune']==pos['Birch']+1 and pos['Coral']!=4):
            candidates.append(arrangement)
    assert candidates == [('Ash','Coral','Birch','Dune')]

    # 30. Numeric CSP.
    assert [p for p in permutations((1,3,7)) if p[0]>p[1]>p[2] and sum(p)==11] == [(7,3,1)]

    # 31. Nim-sum must become zero, with heap size reduced.
    heaps = (3,4,5)
    wins = [(old,new) for i,old in enumerate(heaps)
            for new in range(old)
            if __import__('functools').reduce(lambda x,y:x^y,
               [new if j==i else heaps[j] for j in range(3)],0)==0]
    assert wins == [(3,1)]

    # 32. Enumerate 6P4 secret Mastermind codes, four constraints.
    feedbacks = [('ABCD',(1,2)),('BCEF',(0,3)),('AFDE',(2,0)),('ABEF',(1,2))]
    candidates=[]
    for code in map(''.join,permutations('ABCDEF',4)):
        matches=True
        for guess, wanted in feedbacks:
            exact = sum(a==b for a,b in zip(code,guess))
            wrong = len(set(code) & set(guess)) - exact
            if (exact,wrong) != wanted:
                matches=False
                break
        if matches: candidates.append(code)
    assert candidates == ['AFBC']

    # 33. Max of three backed-up Min nodes.
    assert max(min(x) for x in ((4,8),(5,6),(2,9))) == 5

    # 37. Check CNF: (A|B)&(~A|C)&(~B|C)&(A|~C).
    satisfying = [(a,b,c) for a,b,c in product((False,True),repeat=3)
                  if (a or b) and ((not a) or c) and ((not b) or c)
                  and (a or (not c))]
    assert (True,True,True) in satisfying

    # 42. Standard CRC32 known-answer test.
    assert zlib.crc32(b'123456789') == 0xCBF43926
    assert zlib.crc32(b'12345678I') != 0xCBF43926

    # 48. Recompute prefix hash to independently verify the known examples.
    for token, prefix in [('ULR','5dbc9b4f'), ('RR','e6c5af58'), ('DLR','875caa8e')]:
        assert hashlib.sha256(token.encode()).hexdigest()[:8] == prefix

    # 49. XOR 5-bit binary with 0b10101 and apply A1Z26.
    masked = ('10111','11010','11001','00001')
    assert ''.join(chr(64 + (int(bits,2)^0b10101)) for bits in masked) == 'BOLT'
    print('Independent puzzle checks: OK (Sudoku, crossing, nonogram, CSP, Mastermind, hashes, etc.)')


def solve(location: Path):
    test_puzzle_calculations()
    print('\nVERIFIED MACHINE LEDGER')
    previous = 'START'
    verified = {}
    for n, answer, note in LEDGER:
        p = unlock(location, n, previous)
        verified[n] = p
        print(f'{n:02d} {p["title"]:<39} {answer:<10} [HMAC OK]')
        previous = answer
    final = unlock(location, 50, previous)
    verified[50] = final
    game = final['final_game']
    cost, path = shortest_path(game['edges'])
    assert cost == 3 and path == 'ULR'
    assert path not in game['decoys']
    token_by_number = {n:answer for n,answer,_ in LEDGER}
    values = [token_by_number[n] for n in (20,30,45,49)] + [path]
    prize_key = hashlib.sha256(
        ('LOGIC_ARCADE_GRAND_PRIZE|' + '|'.join(values)).encode()
    ).digest()
    ct = base64.b64decode(game['prize_ciphertext_b64'], validate=True)
    raw = xor_stream(ct, prize_key, game['prize_nonce'])
    actual_digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_digest, game['prize_sha256']):
        raise ValueError('Final decrypted prize SHA-256 does not match')
    flag = raw.decode('utf-8')
    assert flag.startswith('flag{') and flag.endswith('}')
    print(f'50 {final["title"]:<39} {path:<10} [HMAC + SHA-256 OK]')
    print('\nGrand-prize inputs:', ' | '.join(values))
    print('Minimum path cost:', cost)
    print('Computed prize SHA-256:', actual_digest)
    print('Expected prize SHA-256:', game['prize_sha256'])
    print('\n*** VERIFIED GRAND PRIZE ***')
    print(flag)
    return flag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('challenge', nargs='?', default='logic_arcade.zip',
                        help='ZIP path, or the extracted logic_arcade_player folder')
    args = parser.parse_args()
    try:
        solve(Path(args.challenge).expanduser())
    except (OSError, KeyError, ValueError, AssertionError, RuntimeError, zipfile.BadZipFile) as exc:
        print('Verification failed:', exc, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
