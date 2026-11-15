#!/usr/bin/env python3
"""Operation Glasshouse: offline 100-layer evidence solver and flag decoder.

Usage:
  python3 glasswall_solve.py operation_glasshouse.zip
  python3 glasswall_solve.py operation_glasshouse.zip --audit glasswall_audit.csv
  python3 glasswall_solve.py /path/to/operation_glasshouse_player

Uses Python 3 standard library only. Never makes network requests.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import tempfile
import zipfile
from contextlib import nullcontext
from html.parser import HTMLParser
from pathlib import Path
import xml.etree.ElementTree as ET


class CandidateHTMLParser(HTMLParser):
    """Read embedded structured candidate data from HTML <tr> rows."""
    def __init__(self):
        super().__init__()
        self.records = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'tr' and 'data-candidate-id' in a:
            self.records.append({
                'candidate_id': a['data-candidate-id'],
                'source_key': a['data-source-key'],
                'features': json.loads(a['data-features']),
            })


def parse_candidates(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    content = path.read_text(encoding='utf-8')
    if suffix == '.json':
        return json.loads(content)['records']
    if suffix == '.csv':
        with path.open(newline='', encoding='utf-8') as f:
            return [{**r, 'features': json.loads(r['features_json'])}
                    for r in csv.DictReader(f)]
    if suffix == '.html':
        parser = CandidateHTMLParser()
        parser.feed(content)
        return parser.records
    if suffix in {'.xml', '.svg'}:
        root = ET.fromstring(content)
        records = []
        for el in root.iter():
            a = el.attrib
            if 'candidate_id' in a and 'source_key' in a:
                feature_tag = next((c for c in el if c.tag.rsplit('}', 1)[-1] == 'features'), None)
                if feature_tag is None:
                    raise ValueError(f'Missing features child in {path}')
                features = json.loads(feature_tag.text)
                records.append({'candidate_id': a['candidate_id'],
                                'source_key': a['source_key'], 'features': features})
            if 'data-candidate-id' in a:
                records.append({'candidate_id': a['data-candidate-id'],
                                'source_key': a['data-source-key'],
                                'features': json.loads(a['data-features'])})
        return records
    if suffix == '.md':
        records = []
        for line in content.splitlines():
            if not line.startswith('| C'):
                continue
            match = re.match(r'^\|\s*(C[A-Z0-9]+)\s*\|\s*([^|]+?)\s*\|\s*`([^`]+)`', line)
            if match:
                records.append({'candidate_id': match[1], 'source_key': match[2].strip(),
                                'features': json.loads(match[3])})
        return records
    if suffix in {'.txt', '.eml'}:
        records = []
        for block in re.findall(r'\[RECORD\](.*?)\[END\]', content, flags=re.S):
            fields = {}
            for line in block.strip().splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    fields[key.strip()] = value.strip()
            records.append({'candidate_id': fields['candidate_id'],
                            'source_key': fields['source_key'],
                            'features': json.loads(fields['features'])})
        return records
    raise ValueError(f'Unsupported format: {path}')


def normalize(value: object) -> str:
    return ''.join(c for c in str(value).casefold() if c.isalnum())


def matches(rule: str, primary: dict, reference: dict) -> bool:
    p, r = primary, reference
    if rule == 'exact':
        return p.get('stamp') == r.get('stamp')
    if rule == 'normalize':
        return normalize(p.get('phrase')) == normalize(r.get('phrase'))
    if rule == 'date':
        # Date literals in the shipped index use ISO YYYY-MM-DD.
        return p.get('date') == r.get('date')
    if rule == 'tags':
        return len(set(p.get('tags', [])) & set(r.get('tags', []))) >= 2
    if rule == 'count':
        return p.get('interaction_count') == r.get('observed_count')
    if rule == 'metadata':
        return p.get('metadata') == r.get('metadata')
    if rule == 'timeline':
        return p['start'] <= r['event_time'] <= p['end']
    if rule == 'domain':
        return (p.get('host'), p.get('registrant_code')) == (
            r.get('host'), r.get('registrant_code'))
    if rule == 'style':
        u, v = p['vector'], r['vector']
        return len(u) == len(v) == 5 and sum(abs(a-b) for a,b in zip(u,v)) <= 1
    if rule == 'graph':
        return len(set(p['neighbors']) & set(r['neighbors'])) >= 3
    if rule == 'geo':
        return len(set(p['landmarks']) & set(r['landmarks'])) >= 2
    if rule == 'archive':
        return (p.get('old_text') == r.get('old_text') and
                p.get('new_text') == r.get('new_text'))
    raise ValueError('Unsupported rule: ' + rule)


def inspect_case(root: Path) -> tuple[list[dict], str]:
    with (root/'layer_manifest.csv').open(newline='', encoding='utf-8') as f:
        manifest = list(csv.DictReader(f))
    if len(manifest) != 100:
        raise ValueError(f'Expected 100 layers; got {len(manifest)}')

    pivot = 'morrow_glass'
    audit = []
    key_parts = {}
    for expected_layer, step in enumerate(manifest, 1):
        layer = int(step['Layer #'])
        if layer != expected_layer:
            raise ValueError(f'Unexpected layer ordering: {layer}')

        artifact = step['Primary file']
        primary_records = parse_candidates(root / artifact)
        # Manifest layer 71-80 contains a second CSV reference; the primary
        # index is always the first path in "Mini-index".
        index_path = step['Mini-index'].split(' + ')[0].strip()
        index_records = json.loads((root/index_path).read_text(encoding='utf-8'))['records']
        if 71 <= layer <= 80:
            # The fabricated breach index links candidate IDs to synthetic rows.
            # Its companion CSV holds the exact rule feature and next pivot.
            with (root/'indexes/synthetic_breach.csv').open(newline='', encoding='utf-8') as f:
                synthetic_rows = list(csv.DictReader(f))
            by_id = {r['candidate_id']: r for r in index_records}
            reference_by_id = {}
            for r in synthetic_rows:
                index_entry = by_id.get(r['candidate_id'])
                if (index_entry is not None and
                    index_entry['synthetic_row_id'] == r['synthetic_row_id'] and
                    index_entry['fictional_email_alias'] == r['fictional_email_alias']):
                    reference_by_id[r['candidate_id']] = {
                        'features': json.loads(r['features_json']),
                        'next_reference': r['next_reference'],
                    }
        else:
            reference_by_id = {
                rec['candidate_id']: rec for rec in index_records
                if rec.get('artifact_ref') == artifact
            }

        valid = []
        filtered = [rec for rec in primary_records if rec['source_key'] == pivot]
        for rec in filtered:
            reference = reference_by_id.get(rec['candidate_id'])
            if reference and matches(step['Rule ID'], rec['features'], reference['features']):
                valid.append((rec, reference))

        if len(valid) != 1:
            raise ValueError(f'Layer {layer}: expected ONE corroborated match, '
                             f'found {len(valid)}; active pivot={pivot!r}; '
                             f'filter candidates={[r["candidate_id"] for r in filtered]}')

        primary, reference = valid[0]
        output = reference['next_reference']
        if layer in {97, 98, 99}:
            key_parts[layer] = output
        audit.append({
            'layer': layer,
            'input_pivot': pivot,
            'candidate_id': primary['candidate_id'],
            'rule': step['Rule ID'],
            'primary_file': artifact,
            'index_file': index_path,
            'verified_output': output,
        })
        pivot = output

    expected = {97: 'SQ-K4', 98: 'quiet_handoff_after_ledger_audit', 99: 'tin_moth'}
    if key_parts != expected:
        raise ValueError(f'Unexpected final key parts: {key_parts}')

    # Independent summary cross-check against the case's reference artifacts.
    gate_log = list(csv.DictReader((root/'evidence/reference/transfer_gate_log.csv').open()))
    assert any(r['grid_alias'] == key_parts[97]
               and r['last_admission'] == '2041-09-14T21:12:00'
               and r['no_entry_after'].lower() == 'true'
               for r in gate_log)
    associate_post = (root/'evidence/reference/final_associate_post.html').read_text()
    assert key_parts[97] in associate_post and key_parts[99] in associate_post

    if not pivot.startswith('SEAL:'):
        raise ValueError('Last output is not a sealed payload.')
    key_string = '|'.join(key_parts[k] for k in (97, 98, 99))
    digest = hashlib.sha256(key_string.encode('utf-8')).digest()
    ciphertext = base64.b64decode(pivot.removeprefix('SEAL:'), validate=True)
    plaintext = bytes(byte ^ digest[i % len(digest)] for i, byte in enumerate(ciphertext))
    flag = plaintext.decode('utf-8')
    if not re.fullmatch(r'flag\{[A-Za-z0-9_]+\}', flag):
        raise ValueError(f'Decryption output is not flag-shaped: {flag!r}')
    return audit, flag


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('source', type=Path, help='Original ZIP or extracted operation_glasshouse_player directory')
    ap.add_argument('--audit', type=Path, default=None, help='Optional output CSV with all 100 verified layers')
    args = ap.parse_args()
    if args.source.is_file() and args.source.suffix.lower() == '.zip':
        context = tempfile.TemporaryDirectory(prefix='glasswall_')
    else:
        context = nullcontext(None)
    with context as temp_dir:
        if temp_dir is not None:
            with zipfile.ZipFile(args.source) as z:
                names = z.namelist()
                if any(Path(n).is_absolute() or '..' in Path(n).parts for n in names):
                    raise ValueError('Archive contains unsafe extraction path')
                z.extractall(temp_dir)
            root = Path(temp_dir) / 'operation_glasshouse_player'
        else:
            root = args.source
            if not (root/'layer_manifest.csv').is_file():
                root = root/'operation_glasshouse_player'

        audit, flag = inspect_case(root)
        if args.audit:
            args.audit.parent.mkdir(parents=True, exist_ok=True)
            with args.audit.open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=list(audit[0]))
                writer.writeheader()
                writer.writerows(audit)
            print(f'[+] Wrote 100-layer audit to {args.audit}')

        for rec in audit[:10] + audit[-10:]:
            print(f"L{rec['layer']:03d} | {rec['candidate_id']} | {rec['rule']:8} | {rec['verified_output']}")
        print(f'\n[+] Verified layers: {len(audit)}/100')
        print(f'[+] Final flag: {flag}')


if __name__ == '__main__':
    main()
