#!/usr/bin/env python3
"""Reproducible 25-layer solver for The Apprentice's Warm-Up (local-only CTF).

Requires: Python 3.9+ and Pillow (`python3 -m pip install pillow`).
Usage:
    python3 solve_apprentice.py The_Apprentices_Warm_Up_Player_Pack.zip

The script extracts the supplied player pack to a temporary directory, follows
all exact-match catalog selectors, reconstructs the three fragments, checks the
SHA-256 of the decoded final payload, and rejects the included checksum decoy.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import hashlib
import io
import re
import struct
import tempfile
import zipfile
from pathlib import Path
from PIL import Image

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_trailer(path: Path) -> bytes:
    """Return only bytes after the actual PNG IEND chunk (not a guessed match)."""
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError(f"Not PNG: {path}")
    offset = len(PNG_SIGNATURE)
    while offset + 12 <= len(data):
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        next_offset = offset + 12 + size  # length, type, payload, CRC32
        if next_offset > len(data):
            raise ValueError(f"Truncated PNG chunk: {path}")
        if kind == b"IEND":
            return data[next_offset:]
        offset = next_offset
    raise ValueError(f"IEND not found: {path}")


def assignment(blob: bytes | str, key: str) -> str:
    """Get one KEY=value assignment from a line of ASCII or UTF-8 text."""
    if isinstance(blob, bytes):
        blob = blob.decode("utf-8", "replace")
    found = re.findall(r"(?m)^" + re.escape(key) + r"=([^\r\n]+)$", blob)
    if len(found) != 1:
        raise ValueError(f"Expected one {key}= assignment; found {len(found)}")
    return found[0]


def select_file(root: Path, layer: int, handoff: str) -> Path:
    """Catalogs contain an exact-match selector plus two misleading decoys."""
    catalog = root / "evidence" / "catalogs" / f"layer{layer:02d}_selector.txt"
    rows = re.findall(r"(?m)^selector=([^\s|]+) \| file=([^\s]+)$", catalog.read_text())
    matched = [rel for key, rel in rows if key == handoff]
    if len(matched) != 1:
        raise ValueError(f"Layer {layer}: no unique selector for {handoff!r}")
    file = (root / matched[0]).resolve()
    if not file.is_relative_to(root.resolve()) or not file.is_file():
        raise ValueError(f"Unsafe or missing evidence path: {file}")
    return file


def exif_tag(path: Path, tag: int) -> str:
    with Image.open(path) as image:
        value = image.getexif().get(tag)
    if value is None:
        raise ValueError(f"Missing EXIF tag {tag}: {path}")
    if isinstance(value, bytes):
        if value.startswith(b"ASCII\x00\x00\x00"):
            value = value[8:]
        return value.rstrip(b"\x00").decode("utf-8")
    return str(value)


def png_text(path: Path, key: str) -> str:
    with Image.open(path) as image:
        value = image.info.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Missing PNG text field {key!r}: {path}")
    return value


def blue_lsb(path: Path) -> str:
    """RGB pixels: left-to-right/top-to-bottom; blue LSB; MSB-first; NUL stop."""
    with Image.open(path) as opened:
        image = opened.convert("RGB")
    pixels = image.load()
    accumulator = 0
    bit_count = 0
    result = bytearray()
    for y in range(image.height):
        for x in range(image.width):
            blue = pixels[x, y][2]
            accumulator = (accumulator << 1) | (blue & 1)
            bit_count += 1
            if bit_count == 8:
                if accumulator == 0:
                    return result.decode("utf-8")
                result.append(accumulator)
                accumulator = 0
                bit_count = 0
    raise ValueError(f"Missing NUL terminator in blue LSB: {path}")


def final_record(path: Path) -> dict[str, str]:
    trailer = png_trailer(path).decode("ascii")
    if "--APPRENTICE-TRAIL--" not in trailer or "--END-TRAIL--" not in trailer:
        raise ValueError(f"Appended trail markers absent: {path}")
    return {field: assignment(trailer, field) for field in ("record_id", "payload_b64", "sha256")}


def decode_and_check(record: dict[str, str]) -> tuple[bytes, str, bool]:
    """Verify the checksum over decoded payload bytes, never the Base64 text."""
    try:
        decoded = base64.b64decode(record["payload_b64"], validate=True)
    except binascii.Error as error:
        raise ValueError("Invalid Base64 payload") from error
    digest = hashlib.sha256(decoded).hexdigest()
    claimed = record["sha256"]
    valid = bool(re.fullmatch(r"[0-9a-f]{64}", claimed)) and digest == claimed
    return decoded, digest, valid


def safe_extract(archive: zipfile.ZipFile, destination: Path) -> None:
    for member in archive.infolist():
        target = (destination / member.filename).resolve()
        if not target.is_relative_to(destination.resolve()):
            raise ValueError(f"Unsafe ZIP path: {member.filename}")
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, target.open("wb") as sink:
            import shutil
            shutil.copyfileobj(source, sink)


def solve(zip_path: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="apprentice_ctf_") as tmp:
        temp = Path(tmp)
        with zipfile.ZipFile(zip_path) as archive:
            safe_extract(archive, temp)
        root = temp / "Player_Pack"
        if not root.is_dir():
            raise ValueError("Player_Pack/ not found in ZIP")

        output: dict[int, str] = {}
        selected: dict[int, Path] = {}

        specimen = root / "evidence/band1/01_specimen.png"
        binary = specimen.read_bytes()
        if binary[:4] != b"PK\x03\x04":
            raise ValueError("Layer 01 specimen is not a ZIP despite its .png extension")
        with zipfile.ZipFile(io.BytesIO(binary)) as nested_zip:
            output[1] = assignment(nested_zip.read("card.txt"), "HANDOFF")
        print(f"Layer 01 | ZIP magic bytes in disguised PNG     -> {output[1]}")

        for layer in range(2, 26):
            selected[layer] = select_file(root, layer, output[layer - 1])
            target = selected[layer]
            if layer == 2:
                # Binary uses NUL separators, so a line-anchored text parser would miss PASS.
                candidates = re.findall(rb"(?:^|\x00)PASS=([A-Za-z0-9_]+)(?:\x00|$)", target.read_bytes())
                if len(candidates) != 1:
                    raise ValueError("Layer 02 PASS marker not unique")
                output[layer] = candidates[0].decode("ascii")
                method = "binary strings / PASS"
            elif layer == 3:
                output[layer] = assignment(png_trailer(target), "MESSAGE")
                method = "PNG IEND appended note"
            elif layer == 4:
                blob = target.read_bytes()
                if b"\x21\xfe" not in blob:
                    raise ValueError("GIF comment extension not present")
                # Read the named ASCII field from the GIF comment extension.
                match = re.search(rb"MESSAGE=([A-Za-z0-9_]+)", blob)
                if match is None:
                    raise ValueError("MESSAGE absent from GIF comment")
                output[layer] = match.group(1).decode("ascii")
                method = "GIF comment extension"
            elif layer == 5:
                # BMP image-length field excludes the deliberately appended note.
                data = target.read_bytes()
                if data[:2] != b"BM":
                    raise ValueError("Layer 05 is not BMP")
                declared_length = struct.unpack_from("<I", data, 2)[0]
                output[layer] = assignment(data[declared_length:], "ARCHIVE_NOTE")
                method = "BMP appended note"
            elif layer in (6, 8, 10):
                tag = {6: 37510, 8: 270, 10: 315}[layer]
                output[layer] = exif_tag(target, tag)
                method = f"JPEG EXIF tag {tag}"
            elif layer in (7, 9):
                field = {7: "Comment", 9: "Description"}[layer]
                output[layer] = png_text(target, field)
                method = f"PNG text / {field}"
            elif 11 <= layer <= 15:
                record = target.read_text(encoding="utf-8")
                value = assignment(record, "VALUE")
                transform = assignment(record, "TRANSFORM")
                if transform == "BASE64":
                    output[layer] = base64.b64decode(value, validate=True).decode("utf-8")
                elif transform == "ROT13":
                    output[layer] = codecs.decode(value, "rot_13")
                else:
                    raise ValueError(f"Unexpected transform: {transform}")
                method = f"{transform} text transform"
            elif 16 <= layer <= 20:
                output[layer] = blue_lsb(target)
                method = "BMP blue-channel LSB"
            elif layer == 21:
                card = target.read_text(encoding="utf-8")
                if not all(f"Layer {n}" in card for n in (11, 12, 20)):
                    raise ValueError("Assembly card does not match layer order")
                output[layer] = output[11] + output[12] + output[20]
                method = "assemble layers 11 + 12 + 20"
            elif layer == 22:
                output[layer] = "final_carrier"
                method = "select final PNG via record ID"
            elif layer == 23:
                record = final_record(target)
                if record["record_id"] != output[21]:
                    raise ValueError("Appended record ID differs from assembled identifier")
                output[layer] = "trail_record"
                method = "parse appended PNG trail"
            elif layer == 24:
                decoded, digest, valid = decode_and_check(record)
                if not valid:
                    raise ValueError("Final carrier failed SHA-256 validation")
                decoy_file = root / "evidence/finale/decoy_sketch.png"
                decoy_record = final_record(decoy_file)
                decoy_decoded, decoy_digest, decoy_valid = decode_and_check(decoy_record)
                if decoy_valid:
                    raise ValueError("Expected decoy to fail checksum")
                output[layer] = "checksum_valid"
                method = "verify SHA-256; reject decoy"
            elif layer == 25:
                # The decoded payload passed SHA-256 in the previous layer.
                output[layer] = decoded.decode("utf-8")
                if re.fullmatch(r"flag\{[A-Za-z0-9_]+\}", output[layer]) is None:
                    raise ValueError("Verified payload is not a flag")
                method = "decode verified Base64 payload"
            else:
                raise AssertionError(layer)
            print(f"Layer {layer:02d} | {method:<36} -> {output[layer]}")

        print("\nAssembled record ID:", output[21])
        print("Authentic decoded payload:", output[25])
        print("Authentic payload SHA-256:", digest)
        print("Expected SHA-256:         ", record["sha256"])
        print("SHA-256 match:             YES")
        print("Decoy decoded payload:    ", decoy_decoded.decode("utf-8"))
        print("Decoy calculated SHA-256: ", decoy_digest)
        print("Decoy expected SHA-256:   ", decoy_record["sha256"])
        print("Decoy SHA-256 match:       NO (rejected)")
        print("\nFINAL FLAG:", output[25])
        return output[25]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_file", nargs="?", type=Path,
                        default=Path(__file__).with_name("The_Apprentices_Warm_Up_Player_Pack.zip"))
    args = parser.parse_args()
    solve(args.zip_file)


if __name__ == "__main__":
    main()
