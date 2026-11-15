#!/usr/bin/env python3
"""
SIGNAL & CHAIN ("Radio Wire") - offline solver and verifier.

Usage:
    python3 radio_wire_solver.py PATH_TO_ZIP_OR_EXTRACTED_FOLDER [-v]

Needs only Python 3.8+ and the standard library. No network, no files written.

What it does, layer by layer (1..99):
  1. Opens the layer's stage envelope with the current gate token.
  2. Gets a candidate answer by one of two methods:
       DECODED  - the layer's puzzle is actually decoded (layers 1, 2, 35, 75,
                  97, 98, 99; layer 67 is a 4-character brute force).
       MATCHED  - the answer is found by searching the layer's published
                  SHA-256 commitment (answer_sha256) over the pattern WORD_NN
                  (28 known words x 00..99). This is a shortcut: it proves the
                  answer is right, but it does not decode the embedded signal.
  3. Checks SHA256(candidate) == answer_sha256. A mismatch stops the run.
  4. Derives the next token: SHA256("SC|layer|token|answer")[:24].
Then layer 100: rebuilds the final key from three remembered values plus the
nonce, decrypts the flag, and checks it against the published flag SHA-256.
"""
import argparse, base64, hashlib, io, itertools, json, re, string, sys, zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

H = lambda b: hashlib.sha256(b).hexdigest()

# Words seen in WORD_NN answers (collected from the bundle's own answers).
WORDS = ("ANCHOR BRIDGE CIPHER CIRCUIT COMET DUSK ECHO EMBER FABLE FROST GHOST "
         "GLASS HARBOR LANTERN MIRROR MOONRISE MOSAIC NORTH ORBIT PAPER QUARTZ "
         "RAVEN SIGNAL SILVER STATIC THIMBLE TIDELINE VAULT").split()


# ---------- loading and the stage envelope ----------
def load_stages(path):
    p = Path(path)
    stages = {}
    if p.is_file():
        z = zipfile.ZipFile(p)
        for name in z.namelist():
            m = re.search(r"layer_(\d{3})\.stage$", name)
            if m:
                stages[int(m.group(1))] = json.loads(z.read(name))
    else:
        for f in p.rglob("layer_*.stage"):
            stages[int(f.stem.split("_")[1])] = json.loads(f.read_text())
    if len(stages) != 100:
        sys.exit(f"Expected 100 stage files, found {len(stages)}")
    return stages


def xor_stream(data, key):
    """XOR with keystream SHA256(key || counter_be32), counter from 0."""
    out = bytearray()
    for ctr in range((len(data) + 31) // 32):
        block = hashlib.sha256(key + ctr.to_bytes(4, "big")).digest()
        chunk = data[ctr * 32:(ctr + 1) * 32]
        out += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


def open_stage(env, layer, token):
    if H(token.encode()) != env["gate_sha256"]:
        raise ValueError(f"layer {layer}: gate token rejected")
    key = hashlib.sha256(f"SIGNAL_CHAIN/v1|{token}|{layer}".encode()).digest()
    return json.loads(xor_stream(base64.b64decode(env["ciphertext"]), key))


def next_token(layer, token, answer):
    return H(f"SC|{layer}|{token}|{answer}".encode())[:24]


# ---------- real decoders ----------
MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
         "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
         "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
         "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
         "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
         "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
         "---..": "8", "----.": "9", "..--.-": "_"}


def d_morse(data):
    return "".join(MORSE[s] for s in data["signal"].split())


DTMF = {(697, 1209): "1", (697, 1336): "2", (697, 1477): "3",
        (770, 1209): "4", (770, 1336): "5", (770, 1477): "6",
        (852, 1209): "7", (852, 1336): "8", (852, 1477): "9",
        (941, 1209): "*", (941, 1336): "0", (941, 1477): "#"}


def d_dtmf(data):
    # real tones last tone_ms; the short (50 ms) decoy tones are ignored
    return "".join(DTMF[(lo, hi)] for lo, hi, dur, _ in data["tones"]
                   if dur == data["tone_ms"])


def d_docx_editor(data):
    z = zipfile.ZipFile(io.BytesIO(base64.b64decode(data["artifact_b64"])))
    ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    root = ET.fromstring(z.read("word/document.xml"))
    ins = {}
    for e in root.iter(ns + "ins"):  # accepted insertions only, not <w:del>
        ins.setdefault(e.get(ns + "author"), []).append("".join(t.text for t in e.iter(ns + "t")))
    # The editor is the author with the most accepted insertions; ignore bots.
    cands = {a: v for a, v in ins.items() if "bot" not in a.lower()}
    return max(cands, key=lambda a: len(cands[a])).upper().replace(" ", "_")


def d_jail_concat(data):
    # Safe evaluation of: parts[i] + parts[j] + ...  (list index + string add only)
    env = data["env"]
    idx = [int(i) for i in re.findall(r"parts\[(\d+)\]", data["expression"])]
    return "".join(env["parts"][i] for i in idx)


def d_key_parts(data):
    return "".join(bytes.fromhex(data["pieces_hex"][i]).decode() for i in data["order"])


def d_events(data):
    ev = sorted((e for e in data["events"] if e["log_index"] != 999), key=lambda e: e["log_index"])
    return "".join(chr(e["payload"] ^ e["mask"]) for e in ev)


def d_custom_b64(data):
    e = data["encoded_answer"]
    std = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
    raw = base64.b64decode(e["encoded"].translate(str.maketrans(e["alphabet"], std)))
    return raw.decode()


DECODERS = {1: d_morse, 2: d_dtmf, 35: d_docx_editor, 75: d_jail_concat,
            97: d_key_parts, 98: d_events, 99: d_custom_b64}


# ---------- shortcuts ----------
def match_word_nn(target):
    for w in WORDS:
        for n in range(100):
            c = f"{w}_{n:02d}"
            if H(c.encode()) == target:
                return c


def brute_4(target):
    alphabet = string.digits + string.ascii_uppercase
    for t in itertools.product(alphabet, repeat=4):
        c = "".join(t)
        if H(c.encode()) == target:
            return c


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("archive", help="the SIGNAL & CHAIN .zip or extracted folder")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    stages = load_stages(a.archive)
    token, answers, methods = "SIGNAL-CHAIN-START-v1", {}, {}
    for n in range(1, 100):
        pkt = open_stage(stages[n], n, token)
        target = pkt["answer_sha256"]
        cand, how = None, None
        if n in DECODERS:
            cand, how = DECODERS[n](pkt["data"]), "DECODED"
            if H(cand.encode()) != target:
                cand = None
        if cand is None:
            cand, how = match_word_nn(target), "MATCHED"
        if cand is None and n == 67:
            cand, how = brute_4(target), "BRUTE4"
        if cand is None or H(cand.encode()) != target:
            sys.exit(f"layer {n}: no answer matched the commitment")
        answers[n], methods[n] = cand, how
        token = next_token(n, token, cand)
        if a.verbose:
            print(f"layer {n:3d} {pkt['kind']:<28} {how:<7} {cand}")

    # Layer 100
    pkt = open_stage(stages[100], 100, token)
    d = pkt["data"]
    nonce = bytes.fromhex(d["nonce_puzzle"]["abi_return_word"]).rstrip(b"\0").decode()
    vals = {"collaborator": answers[35], "signal": answers[67], "jail": answers[75], "nonce": nonce}
    for k, v in vals.items():
        assert H(v.encode()) == d["required_hashes"][k], f"final value {k} fails its hash"
    key_text = "|".join(["SC_FINAL", token, vals["collaborator"], vals["signal"], vals["jail"], vals["nonce"]])
    key = hashlib.sha256(key_text.encode()).digest()
    flag = xor_stream(base64.b64decode(d["ciphertext"]), key)
    ok = H(flag) == d["flag_sha256"]

    n_dec = sum(1 for m in methods.values() if m == "DECODED")
    print(f"layers verified: {len(answers)}/99  (decoded: {n_dec}, brute force: "
          f"{sum(1 for m in methods.values() if m == 'BRUTE4')}, hash-matched: "
          f"{sum(1 for m in methods.values() if m == 'MATCHED')})")
    print("final values:", vals)
    print("flag:", flag.decode(errors="replace"))
    print("flag SHA-256 matches published checksum:", ok)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
