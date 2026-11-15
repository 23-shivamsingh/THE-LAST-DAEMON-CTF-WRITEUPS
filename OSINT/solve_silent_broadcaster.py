#!/usr/bin/env python3
"""Reproduce The Vanishing Vlogger / Silent Broadcaster flag offline.

Usage:
  python3 solve_silent_broadcaster.py vanishing_vlogger.zip
  python3 solve_silent_broadcaster.py Vanishing_Vlogger_Player_Pack/
No external libraries or network requests are required.

The 49 previous-layer solutions are included as an independently checked
answer ledger. The six final values are re-derived from source evidence;
the flag itself is NOT hard-coded.
"""
from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import hmac
import json
import re
import tempfile
import zipfile
from datetime import date
from pathlib import Path

ANSWERS = [
    'mir4_roams', 'BIO17', '#dullgold', 'acct-mq-03', 'mir4_roams',
    'mira.afterglow', '#wet-copper', 'blog-mq-08', 'roan_kite', 'POSTSET-03',
    'Vellum Quay', 'quill_reef', 'map-folding', 'THREAD-14', 'EXIF-PACKET-A',
    '2025-04-14T19:42', 'VTR-09', 'img-044', 'NACRE-SIGN-4', 'WAVE-3-7',
    'LOC-02', 'Nacre Steps', 'bridge-4', 'DUSK-1840', 'PB-10',
    'TIMELINE-10', '2025-04-15T06:00', 'WINDOW-APR15', 'GAP-APR15_18',
    'COMMENT-BATCH-9', 'roan_kite', 'acct-archway-2', 'WAYFARER-6',
    'WG-APR-OK', 'NEWSLETTER-ROUTE-2', 'route_desk', 'collab-02',
    'NEWS-7', 'archive-profile-11', 'SNAP-MIRA-3', 'mira.quietmap',
    'arch-771', 'tideglass-28', 'WAYFARER-6', 'ITIN-APR-15',
    'IT-03', 'Tallowmere', '2025-04-16', 'CHECKIN-LEDGER-7',
]


def from_json(root: Path, relative: str):
    return json.loads((root / relative).read_text(encoding='utf-8'))


def validate_layers(root: Path) -> None:
    """Check every recorded answer against the challenge's original SHA hashes."""
    tree = ast.parse((root / 'tools/case_runner.py').read_text(encoding='utf-8'))
    hashes = None
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == 'HASHES' for t in statement.targets):
                hashes = ast.literal_eval(statement.value)
                break
    if hashes is None or len(hashes) != 50:
        raise RuntimeError('Original 50-layer validation list missing')
    for index, answer in enumerate(ANSWERS):
        norm = ' '.join(answer.strip().split())
        digests = {
            hashlib.sha256(norm.casefold().encode()).hexdigest(),
            hashlib.sha256(norm.encode()).hexdigest(),
        }
        if hashes[index] not in digests:
            raise RuntimeError(f'Answer mismatch at layer {index + 1}: {answer!r}')
    print(f'[OK] All {len(ANSWERS)} investigation-layer answer hashes match.')


def derive_final_values(root: Path) -> list[str]:
    old = (root / 'evidence/archives/profile_snapshot_2025-03-01.html').read_text()
    new = (root / 'evidence/archives/profile_snapshot_2025-04-10.html').read_text()
    old_handle = re.search(r'Old handle:\s*<code>([^<]+)</code>', old)
    assert old_handle, 'Old handle not found in March snapshot'
    handle = old_handle.group(1)
    assert handle not in new, 'Handle is not actually removed in April snapshot'
    assert 'PF-MIRA-001' in old and 'PF-MIRA-001' in new

    with (root / 'evidence/groups/group_roster.csv').open(newline='') as f:
        roster = list(csv.DictReader(f))
    group_matches = [r for r in roster if r['member'] == handle and 'active' in r['roster_status']]
    assert len(group_matches) == 1
    group = group_matches[0]['group_id']
    group_export = from_json(root, 'evidence/groups/group_export.json')['groups']
    assert any(g['group_id'] == group and g['membership_ref'] == group_matches[0]['membership_ref']
               for g in group_export)

    itineraries = from_json(root, 'evidence/indexes/itinerary_details.json')['entries']
    relevant = [r for r in itineraries if r['member_handle'] == handle and r['group_id'] == group]
    assert len(relevant) == 1, 'Could not identify a unique itinerary entry'
    entry = relevant[0]
    hometown, destination, entry_id = entry['origin_town'], entry['destination_town'], entry['entry_id']
    # Independent hometown corroboration in profile export and dated forum mirror.
    profile = (root / 'evidence/profiles/fieldbook.html').read_text()
    forum = (root / 'evidence/posts/forum_hometown.txt').read_text()
    assert hometown in profile and hometown in forum

    clock = from_json(root, 'evidence/logs/case_clock.json')
    start = date.fromisoformat(clock['gap_window_start'][:10])
    end_exclusive = date.fromisoformat(clock['gap_window_end_exclusive'][:10])
    with (root / 'evidence/logs/itinerary_schedule.csv').open(newline='') as f:
        schedule = list(csv.DictReader(f))
    in_gap = [r for r in schedule if r['entry_id'] == entry_id
              and r['destination'] == destination
              and start <= date.fromisoformat(r['date']) < end_exclusive]
    assert len(in_gap) == 1, 'Itinerary date is ambiguous'
    row = in_gap[0]
    travel_date = row['date']

    ledger = from_json(root, 'evidence/logs/checkin_ledger.json')['fictional_checkins']
    accepted = [c for c in ledger if c['ledger_id'] == row['checkin_ref']
                and c['entry_id'] == entry_id and c['date'] == travel_date
                and c['town'] == destination and c['group_id'] == group]
    assert len(accepted) == 1
    checkin = accepted[0]
    # Verify image object provenance against the actual image bytes.
    transfers = from_json(root, 'evidence/logs/cdn_transfer_log.json')['objects']
    item = next(o for o in transfers if o['object_id'] == checkin['image_object'])
    file_digest = hashlib.sha256((root / 'evidence/images/field_041.jpg').read_bytes()).hexdigest()
    assert item['content_sha256'] == file_digest
    assert item['capture_time'] == checkin['capture_time']
    assert '2025-04-14' in checkin['capture_time']  # distinct from scheduled 16 Apr

    return [handle, group, hometown, destination, travel_date, checkin['ledger_id']]


def decrypt_final_packet(root: Path, values: list[str]) -> str:
    lines = (root / 'evidence/final_payload.enc').read_text(encoding='utf-8').splitlines()
    assert lines[0].strip() == 'VVG50-ENC 1', 'Unknown packet format'
    fields = dict(line.split('=', 1) for line in lines[1:] if '=' in line)
    normalized = [part.strip().casefold() for part in values]
    key_material = fields['PUBLIC_SALT'] + '|' + '|'.join(normalized)
    key = hashlib.sha256(key_material.encode('utf-8')).digest()
    nonce = bytes.fromhex(fields['NONCE_HEX'])
    ciphertext = base64.b64decode(fields['CIPHERTEXT_B64'])
    expected = hmac.new(key, b'VVG50-AUTH|' + nonce + ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, fields['AUTH_TAG_HEX']):
        raise ValueError('HMAC verification failed: source findings are inconsistent')

    pad = bytearray()
    counter = 0
    while len(pad) < len(ciphertext):
        pad.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, 'big')).digest())
        counter += 1
    plain = bytes(a ^ b for a, b in zip(ciphertext, pad))
    flag = plain.decode('utf-8')
    assert flag.startswith('flag{') and flag.endswith('}')
    print('[OK] HMAC-SHA256 authenticated ciphertext')
    return flag


def solve(root: Path) -> None:
    if not (root / 'tools/final_unlock.py').is_file():
        raise FileNotFoundError(f'Not the player pack root: {root}')
    validate_layers(root)
    values = derive_final_values(root)
    labels = ['Deleted handle', 'Canonical group', 'Hometown', 'Destination', 'Itinerary date', 'Ledger ID']
    for label, value in zip(labels, values):
        print(f'{label:16}: {value}')
    print('\nFINAL FLAG: ' + decrypt_final_packet(root, values))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('pack', type=Path, help='ZIP archive or extracted player-pack directory')
    args = parser.parse_args()
    pack = args.pack.resolve()
    if pack.suffix.lower() != '.zip':
        solve(pack)
        return
    with tempfile.TemporaryDirectory(prefix='silent-broadcaster-') as tmp:
        dest = Path(tmp)
        with zipfile.ZipFile(pack) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if not target.is_relative_to(dest):
                    raise ValueError('Unsafe ZIP path rejected')
            zf.extractall(dest)
        candidates = list(dest.rglob('tools/final_unlock.py'))
        assert len(candidates) == 1, 'Could not uniquely locate the player pack'
        solve(candidates[0].parent.parent)


if __name__ == '__main__':
    main()
