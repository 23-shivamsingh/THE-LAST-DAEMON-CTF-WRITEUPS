#!/usr/bin/env python3
"""Polyglot Sanctuary / FORMAT ZOO CTF — offline, reproducible solver.

Usage:
  python3 -m pip install pillow numpy opencv-python-headless
  python3 Polyglot_Sanctuary_solver.py format_zoo.zip

Reads the ORIGINAL zip directly; no manual extraction or network required.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import itertools
import json
import sys
import zipfile
from pathlib import Path

try:
    import cv2
    import numpy as np
    from PIL import Image
except ImportError as exc:
    raise SystemExit(
        f"Missing dependency ({exc}). Install: "
        "python3 -m pip install pillow numpy opencv-python-headless"
    ) from exc

BASE = "FORMAT_ZOO_PLAYER/layers/"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def reverse_caesar(text: str, shift: int) -> str:
    """Undo an alphabetic Caesar shift; preserve other characters."""
    return "".join(
        chr((ord(ch) - ord("a") - shift) % 26 + ord("a"))
        if "a" <= ch <= "z" else ch
        for ch in text
    )


def extract_qr_candidates(archive: zipfile.ZipFile) -> tuple[list[str], Image.Image]:
    """Layer 26: reconstruct stacked PNG strips and decode QR content."""
    strips = [
        Image.open(io.BytesIO(archive.read(f"{BASE}26/strip_{i}.png"))).convert("RGB")
        for i in range(1, 4)
    ]
    if len({im.width for im in strips}) != 1:
        raise ValueError("Layer 26 strips have different widths")
    combined = Image.new("RGB", (strips[0].width, sum(im.height for im in strips)))
    y = 0
    for im in strips:
        combined.paste(im, (0, y))
        y += im.height

    qr_bgr = cv2.cvtColor(np.array(combined), cv2.COLOR_RGB2BGR)
    decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(qr_bgr)
    if not decoded:
        raise RuntimeError("Could not decode the reassembled QR code")
    return decoded.split("|"), combined


def extract_json_candidates(archive: zipfile.ZipFile) -> list[str]:
    """Layer 36: follow explicit path through JSON and decode Base64."""
    node = json.loads(archive.read(f"{BASE}36/deep.json"))
    for name in (
        "packet", "archive", "relay", "capsule", "container",
        "metadata", "payload", "candidates",
    ):
        node = node[name]
    return [base64.b64decode(value, validate=True).decode("utf-8") for value in node]


def extract_pixel_candidates(archive: zipfile.ZipFile) -> list[str]:
    """Layer 41: red channel bytes form ASCII strings, one per row."""
    image = Image.open(io.BytesIO(archive.read(f"{BASE}41/red_bytes.png"))).convert("RGB")
    return [
        "".join(chr(image.getpixel((x, y))[0]) for x in range(image.width))
        for y in range(image.height)
    ]


def extract_csv_candidates(archive: zipfile.ZipFile) -> list[str]:
    """Layer 49: sort fragments by position, then undo per-lane shifts."""
    text = archive.read(f"{BASE}49/fragments.csv").decode("utf-8-sig")
    rows = sorted(csv.DictReader(io.StringIO(text)), key=lambda r: int(r["position"]))
    lanes = (("lane_a", 3), ("lane_b", 5), ("lane_c", 7), ("lane_d", 9))
    return [
        reverse_caesar("".join(row[lane] for row in rows), shift)
        for lane, shift in lanes
    ]


def main() -> int:
    input_zip = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("format_zoo.zip")
    if not input_zip.is_file():
        print(f"File not found: {input_zip}", file=sys.stderr)
        return 2

    with zipfile.ZipFile(input_zip) as archive:
        qr_candidates, qr_image = extract_qr_candidates(archive)
        json_candidates = extract_json_candidates(archive)
        pixel_candidates = extract_pixel_candidates(archive)
        final_candidates = extract_csv_candidates(archive)
        polyglot = archive.read(f"{BASE}50/last_resort.png")

    # Layer 50 looks like a PNG, but is also an appended ZIP archive.
    if not polyglot.startswith(b"\x89PNG\r\n\x1a\n") or not zipfile.is_zipfile(io.BytesIO(polyglot)):
        raise ValueError("Layer 50 was not the expected PNG/ZIP polyglot")
    with zipfile.ZipFile(io.BytesIO(polyglot)) as inner:
        manifest = json.loads(inner.read("manifest.json"))
        cipher = inner.read("parcel.bin")

    expected_hash = manifest["expected_plaintext_sha256"]
    print("Layer 26 QR candidates:   ", qr_candidates)
    print("Layer 36 JSON candidates: ", json_candidates)
    print("Layer 41 pixel candidates:", pixel_candidates)
    print("Layer 49 CSV candidates:  ", final_candidates)
    print("PNG header:", polyglot[:8].hex(), "ZIP header offset:", polyglot.find(b"PK\x03\x04"))

    # The manifest specifies QR | JSON | PIXEL | LAYER49 | format-zoo-final.
    # The final layer's note is contradictory; the manifest SHA-256
    # is an independent integrity check and resolves the ambiguity.
    attempts = 0
    for qr_key, json_key, pixel_key, last_key in itertools.product(
        qr_candidates, json_candidates, pixel_candidates, final_candidates
    ):
        attempts += 1
        seed_text = "|".join((qr_key, json_key, pixel_key, last_key, "format-zoo-final"))
        seed_digest = sha256(seed_text.encode("utf-8"))
        stream = b"".join(
            sha256(seed_digest + counter.to_bytes(4, "big"))
            for counter in range((len(cipher) + 31) // 32)
        )
        plaintext = bytes(a ^ b for a, b in zip(cipher, stream))
        if hashlib.sha256(plaintext).hexdigest() != expected_hash:
            continue

        flag = plaintext.decode("utf-8")
        if not flag.startswith("flag{") or not flag.endswith("}"):
            raise ValueError("Hash matched but flag format was unexpected")
        print("\n[+] VERIFIED FLAG:", flag)
        print("[+] Key order: QR | JSON | PIXEL | LAYER49")
        print("[+] Keys:", qr_key, json_key, pixel_key, last_key)
        print("[+] Seed:", seed_text)
        print("[+] SHA-256:", expected_hash)
        print("[+] Candidate combinations tested:", attempts)
        output = Path("polyglot_flag.txt")
        output.write_text(flag + "\n", encoding="utf-8")
        print("[+] Written:", output.resolve())
        return 0

    print(f"[-] No matching plaintext after {attempts} combinations", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
