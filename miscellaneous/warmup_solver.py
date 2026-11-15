#!/usr/bin/env python3
"""Reproducible local solution for WARM-UP PUZZLES (25 linked puzzles).

Usage:
    python3 -m pip install Pillow pypdf opencv-python
    python3 Warm_Up_Puzzles_Solver.py Warm_Up_Puzzles_Player_Pack.zip
    # or run on an already extracted pack:
    python3 Warm_Up_Puzzles_Solver.py /path/to/extracted/pack

This script reads local puzzle files and runs the original, bundled local
verifier. It neither makes network requests nor alters the player pack.
"""

import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

try:
    import cv2
    from PIL import Image
    from pypdf import PdfReader
except ImportError as exc:
    raise SystemExit(
        "Missing dependency. Run: python3 -m pip install Pillow pypdf opencv-python"
    ) from exc


def next_label(text: str) -> str:
    match = re.search(r"Next label:\s*([A-Za-z0-9_]+)", text)
    if not match:
        raise ValueError(f"No 'Next label' found in {text!r}")
    return match.group(1)


def bf_run(program: str) -> str:
    """Interpret the challenge's three Brainfuck commands: +, -, ."""
    value = 0
    output = []
    for op in program:
        if op == "+":
            value = (value + 1) % 256
        elif op == "-":
            value = (value - 1) % 256
        elif op == ".":
            output.append(chr(value))
        elif op in "<>[],":
            raise ValueError(f"Unsupported BF command {op!r} in this simple challenge")
    return "".join(output)


def qr_decode(path: Path) -> str:
    image = cv2.imread(str(path))
    if image is None:
        raise ValueError(f"Could not load QR: {path}")
    content, vertices, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not content or vertices is None:
        raise ValueError(f"Could not decode QR: {path}")
    return content


def json_value(path: Path, instructions: Path) -> tuple[str, str]:
    text = instructions.read_text(encoding="utf-8")
    match = re.search(r"`(casefile\.[^`]+)`", text)
    if not match:
        raise ValueError(f"No JSON path in {instructions}")
    key_path = match.group(1)
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in key_path.split("."):
        data = data[key]
    if not isinstance(data, str):
        raise TypeError(f"Expected text at {key_path}")
    return key_path, data


def solve(root: Path) -> str:
    if not (root / "band1_file_signatures").is_dir():
        raise FileNotFoundError(f"Not a player pack root: {root}")

    # Puzzles 1-5: deliberately incorrect extensions and real file contents.
    band1 = root / "band1_file_signatures"
    cover = band1 / "01_cover.txt"  # actually PNG
    with Image.open(cover) as picture:
        current = next_label(picture.info["Message"])
    print(f"[01] 01_cover.txt (PNG metadata) -> {current}")

    pdf = band1 / f"{current}.dat"  # actually PDF
    pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf)).pages)
    current = next_label(pdf_text)
    print(f"[02] {pdf.name} (PDF text) -> {current}")

    archive = band1 / f"{current}.bin"  # actually ZIP
    with zipfile.ZipFile(archive) as zf:
        archive_note = zf.read("readme.txt").decode("utf-8")
    current = next_label(archive_note)
    print(f"[03] {archive.name} (ZIP readme) -> {current}")

    animated = band1 / f"{current}.pdf"  # actually GIF
    with Image.open(animated) as animation:
        comment = animation.info["comment"].decode("utf-8")
    current = next_label(comment)
    print(f"[04] {animated.name} (GIF comment) -> {current}")

    drawing = band1 / f"{current}.data"  # actually SVG
    svg_text = " ".join(ET.parse(drawing).getroot().itertext())
    match = re.search(r"Band 1 fragment:\s*([a-z0-9]+)", svg_text)
    if not match:
        raise ValueError("Could not locate Band 1 fragment")
    fragment1 = match.group(1)
    print(f"[05] {drawing.name} (SVG text) -> {fragment1}")

    # Puzzles 6-10: BF outputs name the next program, then the QR desk.
    band2 = root / "band2_brainfuck"
    current = fragment1
    for number in range(6, 11):
        bf_file = band2 / f"{current}.bf"
        next_value = bf_run(bf_file.read_text(encoding="utf-8"))
        print(f"[{number:02}] {bf_file.name} -> {next_value}")
        current = next_value
    fragment2 = current

    # Puzzles 11-15: local QR images and the 10-letter ambiguity rule.
    band3 = root / "band3_qr"
    for number in range(11, 15):
        qr_file = band3 / current / "slip.png"
        next_value = qr_decode(qr_file)
        print(f"[{number:02}] {current}/slip.png -> {next_value}")
        current = next_value

    choices = {}
    for name in ("envelope_A.png", "envelope_B.png"):
        choices[name] = qr_decode(band3 / current / name)
    valid = [v for v in choices.values() if len(v) == 10 and v.isalpha() and v.islower()]
    if len(valid) != 1:
        raise ValueError(f"QR finale must have one ten-letter locator: {choices}")
    locator = valid[0]
    print(f"[15] {current}/ envelope A={choices['envelope_A.png']!r}, "
          f"B={choices['envelope_B.png']!r} -> {locator}")

    # Puzzles 16-20: path files specify exactly which nested JSON property.
    band4 = root / "band4_nested_json"
    current = locator
    fragment4 = None
    for number in range(16, 21):
        source = band4 / f"{current}.json"
        instruction = band4 / f"{current}.path.txt"
        path, result = json_value(source, instruction)
        print(f"[{number:02}] {source.name} [{path}] -> {result}")
        if path == "casefile.evidence.flag_fragment":
            fragment4 = result
            if number != 20:
                raise ValueError("Fragment was not found on the final JSON step")
            break
        current = result
    if fragment4 is None:
        raise ValueError("Missing Band 4 fragment")

    # Puzzles 21-25: concatenate, Base64, SHA-256, index, local verification.
    last = root / "finale" / locator
    if not last.is_dir():
        raise FileNotFoundError(f"Finale folder missing: {last}")
    payload = fragment1 + fragment2 + fragment4
    if not (len(payload) == 25 and payload.isascii() and payload.islower()):
        raise ValueError(f"Bad assembly: {payload!r}")
    print(f"[21] Assembly -> {payload}")

    encoded = base64.b64encode(payload.encode("ascii")).decode("ascii")
    print(f"[22] Base64 -> {encoded}")

    digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    checksum_instructions = (last / "23_checksum.txt").read_text(encoding="utf-8")
    match = re.search(r"expected_sha256=([a-f0-9]{64})", checksum_instructions)
    if not match or digest != match.group(1):
        raise ValueError(f"Checksum mismatch: {digest}")
    prefix = digest[:12]
    print(f"[23] SHA-256 -> {digest} (prefix {prefix})")

    seal_index = json.loads((last / "24_seal_index.json").read_text(encoding="utf-8"))
    seal = seal_index["seal_index"][prefix]["seal"]
    print(f"[24] Seal index -> {seal}")

    # Execute the authentic bundled final verifier, with supplied arguments.
    cmd = [sys.executable, str(last / "25_reveal.py"), encoded, seal]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    flag = result.stdout.strip()
    if flag != f"flag{{{payload}}}":
        raise ValueError(f"Unexpected verifier output: {flag!r}")
    print(f"[25] Original verifier -> {flag}")
    return flag


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 Warm_Up_Puzzles_Solver.py <player_pack.zip | extracted_directory>")
        return 2
    target = Path(sys.argv[1]).expanduser().resolve()
    if target.is_dir():
        solve(target)
    elif target.is_file() and zipfile.is_zipfile(target):
        with tempfile.TemporaryDirectory(prefix="warm_up_puzzles_") as temp:
            with zipfile.ZipFile(target) as zf:
                root = Path(temp).resolve()
                for member in zf.infolist():
                    destination = (root / member.filename).resolve()
                    if not destination.is_relative_to(root):
                        raise ValueError(f"Unsafe path inside ZIP: {member.filename}")
                zf.extractall(root)
            solve(root)
    else:
        raise SystemExit(f"Not a ZIP file or extracted directory: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
