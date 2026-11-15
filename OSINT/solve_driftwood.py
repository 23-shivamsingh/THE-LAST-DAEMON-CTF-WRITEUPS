#!/usr/bin/env python3
"""Operation Driftwood / Blackwood Trail -- offline, Python standard-library solver.

Usage: python3 solve_driftwood.py Driftwood_Player.zip
No network access or third-party libraries are required.
"""
from __future__ import annotations

import base64
import csv
from datetime import datetime
import hashlib
import hmac
import io
import json
import math
from pathlib import Path
import re
import sys
import zipfile

CHALLENGE_ID = "OPERATION-DRIFTWOOD"
PREFIX = "Operation_Driftwood_Player/"
SEED = "mira_seed_07"


def get_packet_key(layer: int, salt: str, handoff: str, memories: dict[int, str]) -> bytes:
    memo = "|".join(f"{i}={memories[i]}" for i in sorted(memories))
    value = f"{CHALLENGE_ID}|sealed-v1|{layer}|{salt}|{handoff}|{memo}"
    return hashlib.sha256(value.encode()).digest()


def repeated_xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[i % len(key)] for i, byte in enumerate(data))


def parse_rows(data: bytes, name: str) -> list[dict]:
    """Read evidence hidden in JSON/JSONL/CSV/TSV or OD_EVIDENCE_B64 wrappers."""
    text = data.decode("utf-8", errors="replace")
    match = re.search(r"OD_EVIDENCE_B64\s*:\s*([A-Za-z0-9+/=]+)", text)
    if match:
        decoded = json.loads(base64.b64decode(match.group(1)))
        if isinstance(decoded, list):
            return decoded
        return decoded.get("records", decoded.get("candidates", []))

    suffix = Path(name).suffix.lower()
    if suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if suffix in (".csv", ".tsv"):
        delimiter = "\t" if suffix == ".tsv" else ","
        return list(csv.DictReader(io.StringIO(text), delimiter=delimiter))
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return parsed.get("records", parsed.get("candidates", []))
    except json.JSONDecodeError:
        pass
    chunks = re.findall(r'\{[^{}]*"candidate_id"[^{}]*"handoff"[^{}]*\}', text)
    return [json.loads(chunk) for chunk in chunks]


def consistent(a: dict, b: dict) -> bool:
    """Compare overlapping independent facts; special cases for dates/invoices."""
    for field, value in b.items():
        if field in ("candidate_id", "handoff", "timestamp"):
            continue
        if field in a and str(a[field]) != str(value):
            return False
    if "line_items" in a and "invoice_total" in b:
        if abs(sum(map(float, a["line_items"])) - float(b["invoice_total"])) > 1e-7:
            return False
    if "timestamp" in a and "timestamp" in b:
        t1 = datetime.fromisoformat(str(a["timestamp"]).replace("Z", "+00:00"))
        t2 = datetime.fromisoformat(str(b["timestamp"]).replace("Z", "+00:00"))
        if abs((t1 - t2).total_seconds()) > 420:
            return False
    return True


def open_packet(archive: zipfile.ZipFile, layer: int, handoff: str,
                solved: dict[int, str]) -> dict:
    name = f"{PREFIX}sealed/L{layer:03d}.bundle.enc"
    packet = json.loads(archive.read(name))
    deps = packet.get("required_memories", [])
    memory = {i: solved[i] for i in deps}
    key = get_packet_key(layer, packet["salt"], handoff, memory)
    ciphertext_b64 = packet["ciphertext_b64"]
    actual_mac = hmac.new(key, ciphertext_b64.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual_mac, packet["mac_sha256"]):
        raise ValueError(f"Layer {layer}: invalid handoff/memory (HMAC failed)")
    payload = json.loads(repeated_xor(base64.b64decode(ciphertext_b64), key))
    files = {f["path"]: base64.b64decode(f["content_b64"])
             for f in payload["files"]}
    record = payload["index_record"]
    first = record["candidates"][0]
    rows_a = {r["candidate_id"]: r for r in parse_rows(files[first["evidence_a"]], first["evidence_a"])
              if "candidate_id" in r}
    rows_b = {r["candidate_id"]: r for r in parse_rows(files[first["evidence_b"]], first["evidence_b"])
              if "candidate_id" in r}
    accepted = []
    for candidate in record["candidates"]:
        cid = candidate["candidate_id"]
        if cid not in rows_a or cid not in rows_b:
            continue
        h = rows_b[cid].get("handoff", "")
        if not h or str(h).startswith("decoy:"):
            continue
        if consistent(rows_a[cid], rows_b[cid]):
            accepted.append((candidate, h))
    if len(accepted) != 1:
        raise ValueError(f"Layer {layer}: expected one corroborated candidate, found {len(accepted)}")
    candidate, next_handoff = accepted[0]
    return {"candidate": candidate["candidate_id"], "handoff": next_handoff,
            "rule": record["rule"], "query_key": record.get("query_key", ""),
            "evidence_a": candidate["evidence_a"],
            "evidence_b": candidate["evidence_b"], "files": files}

# English/JSON byte frequencies for repeating-key XOR cryptanalysis.
FREQUENCY = {
    " ": .14, "e": .09, "t": .068, "a": .062, "o": .064, "i": .055,
    "n": .057, "s": .055, "r": .05, "h": .04, "l": .038, "d": .036,
    "c": .028, "u": .027, "m": .024, "f": .022, "p": .018, "g": .018,
    "y": .017, "b": .016, "v": .009, "k": .006, "x": .003, "w": .017,
    "_": .018, ":": .025, '"': .05, ",": .023, "{": .01,
    "}": .01, "[": .01, "]": .01, "-": .008, "\n": .06,
    ".": .008, "'": .005, "/": .004, "\\": .001,
    "(": .004, ")": .004, ";": .001, "=": .001, "@": .002,
    "\r": .001,
}
for d in "0123456789":
    FREQUENCY[d] = .006
for letter in list(FREQUENCY):
    if letter.isalpha():
        FREQUENCY[letter.upper()] = FREQUENCY[letter] * .12


def byte_score(b: int) -> float:
    if b < 32 and b not in (9, 10, 13) or b >= 127:
        return -25.0
    if b == 9:
        return -3.0
    return math.log(FREQUENCY.get(chr(b), .001))


def score_plaintext(pt: bytes, operator: str) -> float:
    value = sum(byte_score(c) for c in pt)
    text = pt.decode("utf-8", errors="replace")
    # Known *format* and metadata names, not the unknown final flag.
    if text.startswith('{"flag":"flag{'):
        value += 120
    if text.rstrip().endswith("}"):
        value += 20
    for field in ("flag", "ordered_by", "operator_node", "held_at",
                  "held_location_id", "case_closed", "evidence_refs"):
        if f'"{field}"' in text:
            value += 35
    if operator in text:
        value += 35
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and re.fullmatch(r"flag\{[A-Za-z0-9_]+\}", str(obj.get("flag", ""))):
            value += 100
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return value


def recover_final(final_file: bytes, operator: str) -> dict:
    envelope = json.loads(final_file)
    if envelope.get("format") != "OD-XOR-SHA256-REPEAT-v1":
        raise ValueError("Unexpected final envelope format")
    ct = base64.b64decode(envelope["ciphertext_b64"])
    # A SHA-256 digest is 32 bytes. Since it is reused as an XOR keystream,
    # each column of ciphertext can be attacked like single-byte XOR.
    options = []
    for column in range(32):
        sample = ct[column::32]
        ranked = sorted(range(256),
                        key=lambda guess: sum(byte_score(b ^ guess) for b in sample),
                        reverse=True)
        options.append(ranked[:8])
    key = bytearray(row[0] for row in options)
    # Refine the statistical guess using expected JSON structural fields.
    # This disambiguates near-tied byte candidates without knowing the flag.
    for _ in range(3):
        changed = False
        for column, choices in enumerate(options):
            old = key[column]
            best = key[column]
            best_score = -float("inf")
            for choice in choices:
                key[column] = choice
                pt = repeated_xor(ct, key)
                s = score_plaintext(pt, operator)
                if s > best_score:
                    best_score, best = s, choice
            if old != best:
                changed = True
            key[column] = best
        if not changed:
            break
    pt = repeated_xor(ct, key)
    try:
        report = json.loads(pt)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Final XOR key recovery did not yield JSON: {exc}") from exc
    if report.get("operator_node") != operator:
        raise ValueError("Operator anchor does not match; reject XOR guess")
    if set(report) != {"flag", "ordered_by", "operator_node", "held_at",
                       "held_location_id", "case_closed", "evidence_refs"}:
        raise ValueError("Unexpected metadata fields; final XOR key not fully recovered")
    if not re.fullmatch(r"flag\{[a-z0-9_]+\}", report["flag"]):
        raise ValueError("Final flag has an unexpected format")
    return report


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 solve_driftwood.py Driftwood_Player.zip [output_folder]")
        return 2
    archive_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path("driftwood_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    solved: dict[int, str] = {}
    log: list[dict] = []
    final_files: dict[str, bytes] | None = None
    with zipfile.ZipFile(archive_path) as archive:
        for layer in range(1, 151):
            handoff = SEED if layer == 1 else solved[layer - 1]
            result = open_packet(archive, layer, handoff, solved)
            solved[layer] = result["handoff"]
            log.append({"layer": layer, "candidate": result["candidate"],
                        "rule": result["rule"], "query_key": result["query_key"],
                        "evidence_a": result["evidence_a"],
                        "evidence_b": result["evidence_b"], "handoff": result["handoff"]})
            if layer in (1, 15, 30, 45, 60, 75, 85, 90, 105, 120, 135, 149, 150):
                print(f"L{layer:03d}: {result['candidate']:<9} -> {result['handoff']}")
            if layer == 150:
                final_files = result["files"]
    assert final_files is not None
    report = recover_final(final_files["artifacts/final_unlock.enc"], solved[135])
    (output_dir / "solved_layers.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
    (output_dir / "final_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with (output_dir / "casefile.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(log[0]))
        writer.writeheader()
        writer.writerows(log)
    print("\nAll 150 layers authenticated and independently corroborated.")
    print("Operator:     ", report["ordered_by"], report["operator_node"])
    print("Held at:      ", report["held_at"])
    print("FINAL FLAG:   ", report["flag"])
    print("Evidence saved to:", output_dir.resolve())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, FileNotFoundError, zipfile.BadZipFile) as e:
        raise SystemExit(f"Error: {e}")
