#!/usr/bin/env python3
"""Player-file CTF solver: The Forger's Gallery (50-layer chain).

Usage:
    python solve_forgers_gallery.py The_Forgers_Gallery_Player.zip
    python solve_forgers_gallery.py /path/to/player/carriers

Requires gallery_extractors.py in the same directory, Pillow, NumPy,
PyMuPDF and ffmpeg installed. Extraction-method order was established
from the supplied author writeup; no author manifest or plaintext flag
is used by this script.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from pathlib import Path
import re
import tempfile
import zipfile

import gallery_extractors as g

START_ACCESSION = 'P72C4ECF'
START_SEAL = b'g4ll3ry!'
METHODS = (
    'appended_png',  # 01: P72C4ECF__ledger_of_dust.png
    'jpeg_exif',  # 02: J4C713BC__the_last_portrait.jpg
    'bmp_green_lsb',  # 03: BBE915AE__verdigris_study.bmp
    'wav_delta',  # 04: W6896B58__roomtone_04.wav
    'png_custom_chunk',  # 05: PAAFAD51__not_the_signature.png
    'jpeg_appended',  # 06: J6E9FAA9__unfinished_masterpiece.jpg
    'bmp_2bit',  # 07: BF99B630__blue_underpainting.bmp
    'wav_fsk',  # 08: WDC2E9E1__the_quiet_room.wav
    'txt_zerowidth',  # 09: TA161F16__restoration_memo.txt
    'png_alpha',  # 10: P9F9F8FF__transparent_verdict.png
    'gif_palette_order',  # 11: G266F850__the_green_room.gif
    'bmp_region_lsb',  # 12: B22749B2__blue_square.bmp
    'jpeg_xmp',  # 13: J35E9AF7__artist_statement.jpg
    'bmp_blue_bit2',  # 14: BFC59906__a_faint_hum.bmp
    'zip_comment',  # 15: Z95B5295__estate_receipts.zip
    'png_histogram',  # 16: P7A7286E__the_gray_catalog.png
    'jpeg_dqt',  # 17: JC0D15FA__rough_cut.jpg
    'txt_whitespace',  # 18: T2B7AB47__catalogue_final.txt
    'gif_transparency',  # 19: GF2391DE__the_empty_frame.gif
    'png_channel_relation',  # 20: P28320EB__two_blues_one_truth.png
    'bmp_row_padding',  # 21: B33DF77C__the_narrow_canvas.bmp
    'png_ztxt',  # 22: P3D05871__old_restorer_notes.png
    'bmp_blue_bit2',  # 23: BDE9E40D__right_plane_study.bmp
    'zip_extra',  # 24: ZA5E033C__the_repair_kit.zip
    'png_palette_order',  # 25: PF441E10__the_painterly_key.png
    'jpeg_com',  # 26: JAB94C39__a_comment_not_a_clue.jpg
    'txt_acrostic',  # 27: T3DBA148__appraiser_observations.txt
    'gif_transparency',  # 28: GD453D1C__out_of_phase.gif
    'bmp_dct',  # 29: BD6D5C03__the_frequency_canvas.bmp
    'png_alpha',  # 30: P5E7B085__the_ghost_layer.png
    'pdf_subject',  # 31: DB3C13D1__appraisal_summary.pdf
    'png_histogram',  # 32: P8617E32__two_samples_apart.png
    'txt_variation',  # 33: TC08ADD6__letters_that_do_not_show.txt
    'bmp_blue_bit2',  # 34: B51CBC9C__blue_wash.bmp
    'wav_lsb',  # 35: W40A62CB__needle_in_the_tone.wav
    'zip_extra',  # 36: ZF95F53E__archive_with_no_story.zip
    'wav_fsk',  # 37: W1774632__the_frequency_note.wav
    'jpeg_app2',  # 38: J81C4A14__swatch_without_paint.jpg
    'video_frame_lsb',  # 39: V5B41325__stripe_study.avi
    'txt_bidi',  # 40: T2109BC7__a_sentence_facing_backwards.txt
    'zip_nested',  # 41: Z8A2247B__estate_box.zip
    'png_index_parity',  # 42: PB84F45D__the_numbered_swatches.png
    'jpeg_app13',  # 43: JCBDA29C__the_photoshop_receipt.jpg
    'wav_stereo_ratio',  # 44: WD6DC67A__two_mics_one_room.wav
    'txt_wordcount',  # 45: T8FC96DE__the_long_appraisal.txt
    'bmp_rb_order',  # 46: B4940269__fourth_colour.bmp
    'png_alpha',  # 47: P3A14455__a_painting_without_ink.png
    'wav_silence_gate',  # 48: W03FA38C__almost_silent.wav
    'jpeg_zip_polyglot',  # 49: J3AA44D6__the_final_receipt.jpg
    'png_final_alpha',  # 50: PDCAEE1F__the_real_canvas.png
)


def find_carriers(path: Path) -> Path:
    matches = [p for p in path.rglob('P72C4ECF__*') if p.is_file()]
    if len(matches) != 1:
        raise RuntimeError(f'Expected one starting carrier beneath {path}; found {len(matches)}')
    return matches[0].parent


def solve(carriers: Path, quiet: bool = False) -> str:
    accession = START_ACCESSION
    key = START_SEAL
    seals: dict[int, str] = {}
    for layer, method in enumerate(METHODS, 1):
        files = list(carriers.glob(f'{accession}__*'))
        if len(files) != 1:
            raise RuntimeError(f'Layer {layer}: expected one file with accession {accession}, got {len(files)}')
        carrier = files[0]
        if layer < 50:
            ciphertext = g.extract_layer(method, carrier, 16)
            if len(ciphertext) != 16:
                raise RuntimeError(f'Layer {layer}: expected 16 ciphertext bytes, got {len(ciphertext)}')
            message = g.xor_repeat(ciphertext, key).decode('ascii')
            seal, next_accession = message[:8], message[8:]
            if not re.fullmatch(r'[a-z2-7]{8}', seal):
                raise RuntimeError(f'Layer {layer}: invalid seal {seal!r}')
            if not re.fullmatch(r'[PJBWTGZDV][A-F0-9]{7}', next_accession):
                raise RuntimeError(f'Layer {layer}: invalid accession {next_accession!r}')
            seals[layer] = seal
            if not quiet:
                print(f'{layer:02d} {carrier.name} [{method}]')
                print(f'   ciphertext={ciphertext.hex()}')
                print(f'   seal={seal}  next={next_accession}')
            accession, key = next_accession, seal.encode('ascii')
        else:
            # Final mnemonic on PNG: LAST SEAL + PALETTE + GHOST + TONE
            # These correspond respectively to layers 49, 25, 30 and 35.
            ciphertext = g.extract_layer(method, carrier, 29)
            composite = (seals[49]+seals[25]+seals[30]+seals[35]).encode('ascii')
            flag = g.xor_repeat(ciphertext, composite).decode('ascii')
            if not re.fullmatch(r'flag\{[a-zA-Z0-9_]+\}', flag):
                raise RuntimeError(f'Final decoded result is not a flag: {flag!r}')
            if not quiet:
                print(f'{layer:02d} {carrier.name} [{method}]')
                print(f'   ciphertext={ciphertext.hex()}')
                print(f'   XOR-key={composite.decode("ascii")}')
            print('FLAG:', flag)
            print('CHECK: successfully traversed all 50 carriers')
            return flag
    raise RuntimeError('Impossible: 50th stage was not reached')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('player', type=Path, help='player ZIP or extracted player folder')
    parser.add_argument('--quiet', action='store_true', help='show only final result')
    args = parser.parse_args()
    if not args.player.exists():
        parser.error(f'Missing input: {args.player}')
    with ExitStack() as stack:
        if args.player.is_file():
            if not zipfile.is_zipfile(args.player):
                parser.error('Input must be a ZIP or an extracted player folder')
            temp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='gallery_player_')))
            with zipfile.ZipFile(args.player) as archive:
                for item in archive.infolist():
                    destination = (temp / item.filename).resolve()
                    if not destination.is_relative_to(temp.resolve()):
                        raise ValueError(f'Unsafe archive path: {item.filename}')
                    archive.extract(item, temp)
            carriers = find_carriers(temp)
        else:
            carriers = find_carriers(args.player)
        solve(carriers, quiet=args.quiet)


if __name__ == '__main__':
    main()
