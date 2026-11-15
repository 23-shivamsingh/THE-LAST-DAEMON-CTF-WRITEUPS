#!/usr/bin/env python3
"""Offline solver for The Shadow Syndicate (fictional CTF).

Usage:
    python3 solve_shadow_portable.py impersonation_network.zip
    python3 solve_shadow_portable.py player_bundle

Uses the Python standard library only. Extracts ZIP to a temporary directory,
validates both primary and independent corroboration markers for all 99 layers,
then performs the specified SHA-256/XOR final memo decrypt.
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
import tempfile
import zipfile
from pathlib import Path


def candidates_from_artifact(path: Path):
    content = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".html", ".svg", ".xml"):
        # Candidates are embedded in the attributes of tr/g/candidate tags.
        for match in re.finditer(r'<(?:tr|g|candidate)\b[^>]*(?:data-ref|ref)="(L\d{3}-C\d+)"[^>]*>', content):
            tag = match.group(0)
            val = re.search(r'(?:data-value|(?<!data-)value)="([^"]*)"', tag)
            sig = re.search(r'(?:data-primary|primary_marker)="([^"]*)"', tag)
            if val and sig:
                yield {"ref": match.group(1), "value": html.unescape(val.group(1)), "primary_marker": sig.group(1)}
    elif suffix == ".json":
        yield from json.loads(content)["candidates"]
    elif suffix == ".csv":
        for row in csv.DictReader(io.StringIO(content)):
            if row.get("record_type") == "candidate":
                yield {"ref": row["candidate_ref"], "value": row["value"], "primary_marker": row["primary_marker"]}
    elif suffix == ".jsonl":
        for line in content.splitlines():
            if line.strip():
                record = json.loads(line)
                if record.get("kind") == "candidate":
                    yield record
    elif suffix == ".yaml":
        # All candidate YAML entries in the player bundle follow this simple schema.
        # Avoid a third-party PyYAML dependency for reproducibility.
        rx = r'^  - ref: "(L\d{3}-C\d+)"\s*\n    value: "([^"]*)"\s*\n    primary_marker: "([^"]*)"'
        for match in re.finditer(rx, content, flags=re.M):
            yield {"ref": match.group(1), "value": match.group(2), "primary_marker": match.group(3)}
    elif suffix in (".txt", ".eml"):
        for match in re.finditer(r'^CANDIDATE\|(L\d{3}-C\d+)\|([^|]*)\|([^|\r\n]*)\|', content, flags=re.M):
            yield {"ref": match.group(1), "value": match.group(2), "primary_marker": match.group(3)}
    elif suffix == ".md":
        rx = r'^\| `?(L\d{3}-C\d+)`? \| `?([^|`]*?)`? \| `?([^|`]*?)`? \|'
        for match in re.finditer(rx, content, flags=re.M):
            yield {"ref": match.group(1), "value": match.group(2).strip(), "primary_marker": match.group(3).strip()}
    else:
        raise ValueError(f"Unsupported artifact type: {path}")


def unique_file(directory: Path, pattern: str) -> Path:
    found = sorted(directory.glob(pattern))
    if len(found) != 1:
        raise RuntimeError(f"Expected one file matching {directory / pattern}, found {len(found)}")
    return found[0]


def one_marker(text: str, regex: str, layer: int) -> str:
    matches = set(re.findall(regex, text))
    if len(matches) != 1:
        raise RuntimeError(f"Layer {layer:03d}: expected unique anchor; got {sorted(matches)}")
    return next(iter(matches))


def solve(bundle: Path, verbose=True):
    directory = json.loads((bundle / "layer_directory.json").read_text(encoding="utf-8"))
    pivot = directory["starting_pivot"]
    all_results = []
    for layer in range(1, 100):
        primary = unique_file(bundle / "evidence" / "layers", f"layer_{layer:03d}.*")
        # Ignore the task MD cards, which are metadata rather than candidate artifacts.
        if primary.name.endswith("_task.md"):
            primary = unique_file(bundle / "evidence" / "layers", f"layer_{layer:03d}.[!m]*")
        support = unique_file(bundle / "evidence" / "corroboration", f"crossref_{layer:03d}.*")
        idx = unique_file(bundle / "mini_indexes", f"index_{layer:03d}_*.jsonl")

        primary_anchor = one_marker(primary.read_text(encoding="utf-8"), rf'\b[A-Z]{{4,}}-{layer:03d}-[A-F0-9]{{6}}\b', layer)
        secondary_anchor = one_marker(support.read_text(encoding="utf-8"), rf'\bXREF[A-Z]*-{layer:03d}-[A-F0-9]{{6}}\b', layer)
        candidates = list(candidates_from_artifact(primary))
        if len(candidates) < 3:
            raise RuntimeError(f"Layer {layer:03d}: only {len(candidates)} candidates parsed from {primary.name}")
        rows = [json.loads(line) for line in idx.read_text(encoding="utf-8").splitlines() if line.strip()]
        indexed = {r["candidate_ref"]: r for r in rows if r["pivot"] == pivot}
        winners = [c for c in candidates
                   if c["primary_marker"] == primary_anchor
                   and c["ref"] in indexed
                   and indexed[c["ref"]]["corroboration_marker"] == secondary_anchor]
        if len(winners) != 1:
            raise RuntimeError(f"Layer {layer:03d}: {len(winners)} valid candidates; check pivot {pivot!r}")
        chosen = winners[0]
        all_results.append({
            "layer": layer,
            "pivot": pivot,
            "candidate_ref": chosen["ref"],
            "value": chosen["value"],
            "primary_anchor": primary_anchor,
            "corroboration_anchor": secondary_anchor,
            "artifact": str(primary.relative_to(bundle)),
            "support": str(support.relative_to(bundle)),
            "index": str(idx.relative_to(bundle)),
            "candidates_considered": len(candidates),
        })
        if verbose:
            print(f"Layer {layer:03d}: {chosen['ref']} -> {chosen['value']}")
        pivot = chosen["value"]

    chosen = {r["layer"]: r["value"] for r in all_results}
    ingredients = {
        "operator": chosen[78],
        "billing": chosen[56],
        "filing": chosen[89],
        "previous": chosen[99],
    }
    memo = json.loads((bundle / "evidence" / "layers" / "layer_100.memo").read_text(encoding="utf-8"))
    key_material = "|".join(ingredients[k] for k in ("operator", "billing", "filing", "previous"))
    access_code = hashlib.sha256(key_material.encode("utf-8")).hexdigest()[:16]
    stream = hashlib.sha256((access_code + "|" + memo["nonce"] + "|0").encode("utf-8")).digest()
    ciphertext = base64.b64decode(memo["ciphertext_b64"])
    plaintext = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(ciphertext)).decode("utf-8")
    if not (plaintext.startswith("flag{") and plaintext.endswith("}")):
        raise RuntimeError("Final decryption failed: unexpected plaintext")
    return {"flag": plaintext, "ingredients": ingredients, "nonce": memo["nonce"], "access_code": access_code, "steps": all_results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="Path to original challenge ZIP or extracted player_bundle folder")
    parser.add_argument("--output", type=Path, default=Path("shadow_solution.json"), help="Output JSON evidence path")
    parser.add_argument("--quiet", action="store_true", help="Only print final result")
    args = parser.parse_args()
    if args.bundle.is_file() and args.bundle.suffix.lower() == ".zip":
        with tempfile.TemporaryDirectory(prefix="shadow_ctf_") as name:
            temp = Path(name)
            with zipfile.ZipFile(args.bundle) as archive:
                for info in archive.infolist():
                    dest = (temp / info.filename).resolve()
                    if not dest.is_relative_to(temp.resolve()):
                        raise ValueError("Refusing unsafe ZIP path: " + info.filename)
                archive.extractall(temp)
            result = solve(temp / "player_bundle", verbose=not args.quiet)
    else:
        bundle = args.bundle
        if (bundle / "player_bundle").is_dir():
            bundle = bundle / "player_bundle"
        result = solve(bundle, verbose=not args.quiet)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\nOperator :", result["ingredients"]["operator"])
    print("Billing  :", result["ingredients"]["billing"])
    print("Filing   :", result["ingredients"]["filing"])
    print("Layer 99 :", result["ingredients"]["previous"])
    print("Access   :", result["access_code"])
    print("FLAG     :", result["flag"])
    print("Evidence :", args.output)


if __name__ == "__main__":
    main()
