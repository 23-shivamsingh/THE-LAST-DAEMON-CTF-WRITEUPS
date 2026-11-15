#!/usr/bin/env python3
"""CORPORATE VEIL (fictional offline CTF) - 50-lead, evidence-checked solver.

Usage:
    python3 -m pip install pypdf
    python3 solve_corporate_veil.py shell_company.zip
    # Or: python3 solve_corporate_veil.py SHELL_COMPANY_PLAYER/

No network requests, no hard-coded flag or final key.  Reads only the puzzle pack.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import io
import json
import re
import zipfile
from pathlib import Path

try:
    from pypdf import PdfReader
except ImportError:
    raise SystemExit("Missing dependency: install with 'python3 -m pip install pypdf'")

class Pack:
    def __init__(self, source: str):
        self.path = Path(source)
        self.zf = zipfile.ZipFile(self.path) if self.path.is_file() else None
        self.prefix = "SHELL_COMPANY_PLAYER/" if self.zf else ""
        if self.zf is None and (self.path / 'SHELL_COMPANY_PLAYER').is_dir():
            self.path = self.path / 'SHELL_COMPANY_PLAYER'

    def raw(self, name: str) -> bytes:
        if self.zf:
            return self.zf.read(self.prefix + name)
        return (self.path / name).read_bytes()

    def text(self, name: str) -> str:
        return self.raw(name).decode('utf-8-sig')

    def json(self, name: str):
        return json.loads(self.text(name))

    def rows(self, name: str):
        delim = '\t' if name.endswith('.tsv') else ','
        return list(csv.DictReader(io.StringIO(self.text(name)), delimiter=delim))

    def pdf(self, name: str):
        return PdfReader(io.BytesIO(self.raw(name)))

    def pdftext(self, name: str):
        return '\n'.join(page.extract_text() or '' for page in self.pdf(name).pages)


def one(seq, desc="unique match"):
    items = list(seq)
    if len(items) != 1:
        raise AssertionError(f'{desc}: expected one match, found {len(items)}')
    return items[0]


def match(pattern, text, desc='', flags=0):
    obj = re.search(pattern, text, flags)
    if not obj:
        raise AssertionError(f'{desc or pattern}: no match')
    return obj.group(1)


def html_records(txt):
    for chunk in re.findall(r'<div class="record">(.*?)</div>', txt, flags=re.S):
        chunk = re.sub(r'<br\s*/?>', '\n', chunk)
        chunk = re.sub(r'<[^>]+>', '', chunk)
        yield html.unescape(chunk).strip()


def flag_decrypt(salt, ciphertext_b64, key):
    ciphertext = base64.b64decode(ciphertext_b64)
    seed = (salt + '|' + key).encode('utf-8')
    stream = bytearray()
    counter = 0
    while len(stream) < len(ciphertext):
        stream.extend(hashlib.sha256(seed + b'|' + str(counter).encode('ascii')).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(ciphertext, stream)).decode('utf-8')


def solve(pack: Pack):
    findings = []
    def save(n, value, path, check=None):
        if check is not None:
            assert check, f'L{n:02}: validation failed'
        findings.append((f'L{n:02}', value, path))
        print(f'L{n:02} | {value}')
        return value

    # Band 1: public director -> active domain
    page = pack.text('evidence/sites/solara/about.html')
    director = save(1, match(r'Public Director:</strong>\s*([^<]+)', page), 'evidence/sites/solara/about.html')
    row = one((r for r in pack.rows('indexes/director_directory.csv')
               if r['full_name'] == director and r['entity'] == 'Solara Ventures Pvt.' and r['status'] == 'Current'), 'director roster')
    director_id = save(2, row['director_id'], 'indexes/director_directory.csv')
    profile = pack.json(f'evidence/personnel/{director_id}.json')
    handle = save(3, profile['username'], f'evidence/personnel/{director_id}.json', profile['full_name'] == director)
    records = list(html_records(pack.text('indexes/username_platform_search.html')))
    active = one((r for r in records if f'Handle: {handle}\n' in r and 'Profile: Solara Ventures Pvt.' in r
                  and 'active corporate domain' in r and '2031-06-18' in r), 'active bulletin')
    ref = save(4, match(r'Bulletin ref:\s*(\S+)', active), 'indexes/username_platform_search.html')
    archive = pack.text('archives/solara_snapshot_2031-06.txt')
    snapshot = one(b for b in re.split(r'(?=Snapshot \d{4}-\d\d-\d\d)', archive)
                   if f'Footer tag: {ref}' in b and 'Listing state: active' in b)
    domain = save(5, match(r'Domain:\s*(\S+)', snapshot), 'archives/solara_snapshot_2031-06.txt')

    # Band 2: WHOIS-style local lookup -> registration docket
    whois = one(r for r in pack.json('indexes/domain_whois.json') if r['domain'] == domain and r['status'] == 'active')
    email = save(6, whois['registrant_email'], 'indexes/domain_whois.json')
    reversed_records = list(html_records(pack.text('indexes/registrant_email_reverse_lookup.html')))
    other_domains = sorted(match(r'->\s*(\S+)', r) for r in reversed_records
                           if r.startswith(email + ' ->') and 'Status: active' in r and match(r'->\s*(\S+)', r) != domain)
    save(7, ', '.join(other_domains), 'indexes/registrant_email_reverse_lookup.html', len(other_domains) == 2)
    registrars = pack.rows('indexes/registrar_registry.csv')
    linked = [one(r for r in registrars if r['domain'] == d and r['status'] == 'active') for d in other_domains]
    org = save(8, linked[0]['registrant_organization'], 'indexes/registrar_registry.csv',
               linked[0]['registrant_organization'] == linked[1]['registrant_organization'])
    registration = one(r for r in pack.json('indexes/business_registry.json')
                       if r['organization'] == org and r['status'] == 'active')
    regid = save(9, registration['registry_id'], 'indexes/business_registry.json')
    regpdf = pack.pdftext(f'evidence/{regid}.pdf')
    docket = save(10, match(r'Filing family:\s*([A-Z0-9-]+)', regpdf), f'evidence/{regid}.pdf', regid in regpdf)

    # Band 3: hidden director -> filing clause
    docket_txt = pack.text(f'evidence/docket_{docket}.txt')
    other_director = save(11, match(r'Supplementary director named in the signed schedule:\s*([^\n]+)', docket_txt),
                          f'evidence/docket_{docket}.txt')
    ci = pack.rows('indexes/director_company_index.csv')
    active_company = one(r for r in ci if r['director_name'] == other_director
                         and r['filing_family'] == docket and r['status'] == 'Current')
    company = save(12, active_company['company'], 'indexes/director_company_index.csv')
    appointment = pack.text('evidence/paleharbor_appointments.html')
    appointment_record = one(r for r in html_records(appointment) if other_director in r and docket in r and 'state current' in r)
    new_director_id = save(13, match(r'ID\s+(DIR-\d+)', appointment_record), 'evidence/paleharbor_appointments.html',
                           active_company['director_id'] in appointment_record)
    filing = one(r for r in pack.json('indexes/director_identity_index.json')
                 if r['director_id'] == new_director_id and r['docket'] == docket)
    filing_ref = save(14, filing['current_filing'], 'indexes/director_identity_index.json')
    annex = pack.text(f'evidence/{filing_ref}-annex.md')
    clause = save(15, match(r'Cross-reference clause:\s*\*\*([^*]+)\*\*', annex), f'evidence/{filing_ref}-annex.md')

    # Band 4: press/phrase relationship -> Ember Trust entity
    pr = pack.text('evidence/pressrelease_astervale.html')
    partner = save(16, match(r'For the fictional local record,\s*(.+?) confirms', pr),
                   'evidence/pressrelease_astervale.html', clause in pr)
    releases = pack.rows('indexes/press_archive.tsv')
    rr = one(r for r in releases if r['company'] == partner and r['cross_reference'] == clause
             and r['release_type'] == 'partnership')
    release_id = save(17, rr['release_id'], 'indexes/press_archive.tsv')
    compare = pack.text('evidence/website_phrase_compare.html')
    phrases = re.findall(r'<blockquote>(.*?)</blockquote>', compare, flags=re.S)
    assert len(phrases) >= 3 and phrases[0] == phrases[1] and phrases[0] != phrases[2]
    fp_rec = one(r for r in pack.json('indexes/phrase_fingerprint_index.json')
                 if r['exact_phrase'] == phrases[0] and r['status'] == 'active')
    fingerprint = save(18, fp_rec['fingerprint'], 'evidence/website_phrase_compare.html; indexes/phrase_fingerprint_index.json')
    matched_domain = save(19, fp_rec['matching_domain'], 'indexes/phrase_fingerprint_index.json')
    ember_pdf = pack.pdftext('evidence/embertrust_registry.pdf')
    pdf_entity = match(r'Entity ID:\s*(ENT-[A-Z0-9-]+)', ember_pdf)
    entity_row = one(r for r in pack.rows('indexes/entity_directory.csv')
                     if r['domain'] == matched_domain and r['status'] == 'active' and r['entity_id'] == pdf_entity)
    entity_id = save(20, entity_row['entity_id'], 'evidence/embertrust_registry.pdf; indexes/entity_directory.csv')

    # Band 5: finance officer -> older organization
    employee = pack.text('evidence/employee_profile_ember.html')
    person = save(21, match(r'<strong>Person:</strong>\s*([^<]+)', employee),
                  'evidence/employee_profile_ember.html', entity_id in employee)
    roles = [r for r in pack.rows('indexes/employee_roles.csv')
             if r['person_name'] == person and r['role'] == 'Finance Director' and r['status'] == 'active']
    profile_id = save(22, roles[0]['profile_id'], 'indexes/employee_roles.csv',
                      len(roles) == 2 and len({r['company'] for r in roles}) == 2 and len({r['profile_id'] for r in roles}) == 1)
    emp = pack.json(f'evidence/employment/{profile_id}.json')
    curr_handle = save(23, emp['primary_handle'], f'evidence/employment/{profile_id}.json')
    exp_row = one(r for r in pack.rows('indexes/synthetic_exposure_export.tsv')
                  if r['observed_handle'] == curr_handle and r['profile_key'] == emp['legacy_profile_key'])
    org_prior = save(24, exp_row['prior_organization'], 'indexes/synthetic_exposure_export.tsv',
                     exp_row['alternate_handle'] in pack.text('indexes/username_miniindex.html'))
    cost = one(r for r in pack.rows('indexes/finance_orgchart.csv') if r['organization'] == org_prior)
    cost_center = save(25, cost['cost_center'], 'indexes/finance_orgchart.csv')

    # Band 6: PDF properties -> internal graph code
    memo = pack.pdf(f'evidence/finance_memo_{cost_center}.pdf')
    parent = save(26, str(memo.metadata.get('/Company')), f'evidence/finance_memo_{cost_center}.pdf (/Company)')
    meta_records = [r for r in pack.json('indexes/document_metadata_index.json') if r['company'] == parent]
    templates = {r['author_template_id'] for r in meta_records}
    template_id = save(27, one(templates, 'shared template ID'), 'indexes/document_metadata_index.json')
    txt = pack.text('evidence/document_properties_comparison.txt')
    assert f'Author/template {template_id}' in txt
    date = save(28, match(r'DOC-COST-77\s*\| created (\d{4}-\d\d-\d\d)', txt),
                'evidence/document_properties_comparison.txt', bool(re.search(r'DOC-VG-14\s*\| created 2031-07-14', txt)))
    same_docs = [r for r in pack.rows('indexes/document_catalog.tsv')
                 if r['author_template_id'] == template_id and r['creation_date'] == date]
    dept = save(29, one({r['department_key'] for r in same_docs}, 'department key'), 'indexes/document_catalog.tsv', len(same_docs) == 2)
    routing = pack.text('evidence/finance_department_note.md')
    graph_ref = save(30, match(r'`' + re.escape(dept) + r'` maps to graph reference `([^`]+)`', routing),
                     'evidence/finance_department_note.md')

    # Band 7: illustration -> canonical office / suite
    image = pack.text('evidence/images/team_ember_01.svg')
    assert graph_ref in image and 'MORROW QUAY' in image and 'ANNEX FOUR' in image
    landmark = save(31, 'Morrow Quay Annex Four', 'evidence/images/team_ember_01.svg')
    sheet = pack.text('evidence/image_contact_sheet.html')
    assert 'team_ember_01.svg' in sheet and 'team_aster_02.svg' in sheet and 'team_decoy_03.svg' in sheet
    assets = pack.json('indexes/image_asset_registry.json')
    asset = one(r for r in assets if r['landmark'] == landmark
                and r['visual_signature'] == '9 vertical mullions, asymmetric divider, crescent vent')
    asset_id = save(32, asset['asset_id'], 'evidence/image_contact_sheet.html; indexes/image_asset_registry.json')
    address = save(33, asset['address'], 'indexes/image_asset_registry.json')
    matched_addr = one(r for r in pack.rows('indexes/address_normalizer.csv') if r['alias'] == address)
    prop = save(34, matched_addr['property_id'], 'indexes/address_normalizer.csv')
    directory = pack.pdftext(f'evidence/building_directory_{prop}.pdf')
    suite = save(35, match(r'Suite / tenant group code:\s*(\S+)', directory),
                 f'evidence/building_directory_{prop}.pdf', prop in directory)

    # Band 8: registrations -> amended route
    registration_rows = [r for r in pack.rows('indexes/company_registration_dates.csv') if r['suite_code'] == suite]
    week = save(36, one({r['week_key'] for r in registration_rows}, 'week'), 'indexes/company_registration_dates.csv')
    events = [r for r in pack.json('indexes/registration_events.json') if r['week_key'] == week]
    aliases = {r['alias'].casefold(): r['normalized_address'] for r in pack.rows('indexes/address_normalizer.csv')}
    groups = {}
    for event in events:
        norm = aliases.get(event['registered_address'].casefold())
        if norm: groups.setdefault(norm, []).append(event)
    group = one(v for v in groups.values() if len(v) == 3 and
                {x['company'] for x in v} == {x['company'] for x in registration_rows})
    companies = {r['company'] for r in group}
    save(37, ', '.join(sorted(companies)), 'indexes/registration_events.json; indexes/address_normalizer.csv')
    addr_notes = pack.text('evidence/address_normalization_notes.html')
    addr_token = one(k for k, v in groups.items() if {x['company'] for x in v} == companies)
    save(38, addr_token, 'evidence/address_normalization_notes.html', addr_token in addr_notes)
    joined = [r for r in pack.rows('indexes/registry_address_join.tsv')
              if r['normalized_address'] == addr_token and r['week_key'] == week and r['company'] in companies]
    assert len(joined) == 3 and new_director_id == 'DIR-882' and any(r['director'] == other_director for r in joined)
    lattice = save(39, one({r['filing_ref'] for r in joined}, 'shared filing'), 'indexes/registry_address_join.tsv')
    snapshot = pack.text('evidence/lattice_archive_snapshots.html')
    assert lattice in snapshot
    current = one(r for r in html_records(snapshot) if 'state: current' in r and lattice in r)
    route = save(40, match(r'routing field:\s*([A-Z0-9-]+)', current), 'evidence/lattice_archive_snapshots.html')

    # Band 9: payee route, filing, and distinctive memo style
    financial = pack.pdftext(f'evidence/financial_extract_{route}.pdf')
    payee = save(41, match(r'Recurring service-fee payee:\s*([^\n]+)', financial),
                 f'evidence/financial_extract_{route}.pdf')
    tx = [r for r in pack.json('indexes/financial_transactions.json') if r['payee'] == payee and r['route'] == route]
    assert len(tx) == 7, f'Expected 7 matched transactions, got {len(tx)}'
    common_account = one({r['account_code'] for r in tx}, 'payment account')
    account = save(42, common_account, 'indexes/financial_transactions.json',
                   all('reconcilliation :: monthly service fee' == r['memo'] for r in tx))
    filing_txt = pack.text('evidence/quietledger_filing.txt')
    filing_director = save(43, match(r'Listed director:\s*([^\n(]+)', filing_txt).strip(),
                           'evidence/quietledger_filing.txt', account in filing_txt and other_director in filing_txt)
    style_notes = pack.text('evidence/payment_memo_stylometry.md')
    misspelling, delimiter, tail = 'reconcilliation', '::', 'monthly service fee'
    assert all(part in style_notes for part in (misspelling, delimiter, tail, filing_director))
    style_rec = one(r for r in pack.json('indexes/stylometry_profiles.json')
                    if (r['misspelling'], r['delimiter'], r['memo_tail']) == (misspelling, delimiter, tail))
    style = save(44, style_rec['profile_key'], 'evidence/payment_memo_stylometry.md; indexes/stylometry_profiles.json')
    payment_row = one(r for r in pack.rows('indexes/payment_route_index.tsv')
                      if r['stylometry_key'] == style and r['account_code'] == account and r['payee'] == payee)
    payee_filing = save(45, payment_row['filing_id'], 'indexes/payment_route_index.tsv')

    # Band 10: fully corroborated ownership -> base64 key -> XOR payload
    ownership = one(r for r in pack.json('indexes/ownership_graph.json')
                    if r['payee_filing'] == payee_filing and r['director'] == filing_director
                    and r['office_suite'] == suite and r['payee'] == payee
                    and r['independent_matches'] == 3)
    ownership_node = save(46, ownership['ownership_node'], 'indexes/ownership_graph.json')
    chart = pack.text('evidence/ownership_chart.html')
    assert ownership_node in chart
    candidates = re.findall(r'Candidate \d+: ([^<]+)</h2>', chart)
    save(47, ', '.join(candidates), 'evidence/ownership_chart.html', len(candidates) == 3)
    hist = pack.text('evidence/archive_owner_snapshots.txt')
    selected = one(c for c in candidates if f'Candidate noted: {c}' in hist
                   and f'only {c} has multiple independent' in hist)
    save(48, selected, 'evidence/archive_owner_snapshots.txt')
    decoder_row = one(r for r in pack.rows('indexes/owner_decoder.tsv')
                      if r['owner_name'] == selected and r['suite_code'] == suite
                      and r['payee_filing'] == payee_filing)
    key = base64.b64decode(decoder_row['encoded_unlock_key']).decode('utf-8')
    save(49, key, 'indexes/owner_decoder.tsv')
    payload = pack.json('evidence/final_unlock.json')
    flag = flag_decrypt(payload['salt'], payload['ciphertext_b64'], key)
    save(50, flag, 'evidence/final_unlock.json; tools/unlock_final.py',
         flag.startswith('flag{') and flag.endswith('}') and 20 <= len(flag[5:-1]) <= 40)

    assert len(findings) == 50
    print('\nFINAL FLAG:', flag)
    return findings, flag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', nargs='?', default='shell_company.zip',
                        help='original shell_company.zip or extracted SHELL_COMPANY_PLAYER folder')
    args = parser.parse_args()
    solve(Pack(args.source))

if __name__ == '__main__':
    main()
