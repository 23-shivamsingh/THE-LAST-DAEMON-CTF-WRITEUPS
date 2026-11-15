#!/usr/bin/env python3
"""UNWRAPD Hidden Layers solver v2: signature-search based."""
import hashlib, json, os, re, struct, sys, zipfile, tarfile, io, base64
import numpy as np
from numpy.lib.stride_tricks import sliding_window_view
from PIL import Image

# Usage: python3 solve.py [start] [end] [challenge_dir]
# challenge_dir = folder containing carriers/ (the unzipped challenge). Default: ./chal
BASE = os.path.dirname(os.path.abspath(__file__))
CHAL = sys.argv[3] if len(sys.argv) > 3 else os.path.join(BASE, 'chal')
CDIR = os.path.join(CHAL, 'carriers')
STATE = os.path.join(BASE, 'state.json')
BLOCK = 768
KNOWN = b'{"artifact":"'

def derive_key(prev_token, mem):
    s = "unwrapd|" + prev_token + "|" + "|".join(mem)
    return hashlib.sha256(s.encode()).digest()

def keystream(key, n=BLOCK):
    out = b''
    c = 0
    while len(out) < n:
        out += hashlib.sha256(key + c.to_bytes(4, 'big')).digest()
        c += 1
    return out[:n]

def try_block(block, ks, expect_layer):
    if len(block) < BLOCK:
        return None
    dec = bytes(b ^ k for b, k in zip(block[:BLOCK], ks))
    L = int.from_bytes(dec[:2], 'big')
    if L < 10 or L > 740 or dec[2:3] != b'{':
        return None
    try:
        j = json.loads(dec[2:2+L].decode('utf-8'))
    except Exception:
        return None
    if isinstance(j, dict) and j.get('layer') == expect_layer:
        return j
    return None

def bits_to_bytes(bits, msb=True, prepacked=False):
    bits = np.asarray(bits, dtype=np.uint8)
    n = (len(bits)//8)*8
    bits = bits[:n].reshape(-1, 8)
    w = np.array([128,64,32,16,8,4,2,1], dtype=np.uint8) if msb else np.array([1,2,4,8,16,32,64,128], dtype=np.uint8)
    return (bits*w).sum(axis=1).astype(np.uint8).tobytes()

def sig_search_bits(bits, sig_bits):
    n = len(bits) - len(sig_bits) + 1
    if n <= 0:
        return []
    win = sliding_window_view(bits, len(sig_bits))
    return np.where((win == sig_bits).all(axis=1))[0]

def image_streams(path, ext, data):
    """yield (name, uint8 array) byte streams whose bit planes may carry the block."""
    out = []
    if ext in ('png','gif','bmp','tif','tiff','jpg','jpeg'):
        try:
            im = Image.open(path); im.load()
            a = np.array(im)
            if a.ndim == 3:
                h, w, c = a.shape
                out.append(('pil_flat', a.flatten()))
                for ch in range(c):
                    out.append((f'pil_ch{ch}', a[:,:,ch].flatten()))
                    out.append((f'pil_chT{ch}', a[:,:,ch].T.flatten()))
                if c == 4:
                    al = a[:,:,3].flatten()
                    pix = a.reshape(-1, 4)
                    for mval in np.unique(al):
                        sel = pix[al == mval]
                        if len(sel) * 3 >= BLOCK * 8:
                            out.append((f'mask{int(mval)}_rgb', sel[:,:3].flatten()))
                            for ch in range(3):
                                out.append((f'mask{int(mval)}_ch{ch}', sel[:,ch].flatten()))
                if c in (3, 4):
                    import itertools as _it
                    for perm in _it.permutations(range(c)):
                        if perm == tuple(range(c)):
                            continue
                        out.append((f'perm{"".join(map(str,perm))}', a[:,:,perm].flatten()))
            else:
                out.append(('pil_gray', a.flatten()))
        except Exception as e:
            print('  img err', e)
    if ext == 'bmp':
        pix = np.frombuffer(data[54:], dtype=np.uint8)
        wrow = len(pix)//128 if len(pix) % 128 == 0 else None
        out.append(('file', pix))
        rows = pix.reshape(-1, len(pix)//128) if len(pix) % 128 == 0 else None
        if rows is not None:
            out.append(('topdown', rows[::-1].flatten()))
            for off in range(3):
                out.append((f'fchan{off}', pix[off::3]))
                out.append((f'tchan{off}', rows[::-1].flatten()[off::3]))
    if ext == 'wav':
        import wave
        try:
            w = wave.open(path, 'rb')
            frames = w.readframes(w.getnframes())
            a = np.frombuffer(frames, dtype=np.uint8)
            out.append(('wav_all', a))
            out.append(('wav_lo', a[0::2]))
            out.append(('wav_hi', a[1::2]))
            nch = w.getnchannels()
            sw = w.getsampwidth()
            if nch == 2 and sw == 2:
                s = np.frombuffer(frames, dtype='<i2')
                lb = np.frombuffer(s[0::2].tobytes(), dtype=np.uint8)
                rb = np.frombuffer(s[1::2].tobytes(), dtype=np.uint8)
                out.append(('wavL_lo', lb[0::2])); out.append(('wavL_hi', lb[1::2]))
                out.append(('wavR_lo', rb[0::2])); out.append(('wavR_hi', rb[1::2]))
        except Exception as e:
            print('  wav err', e)
    if ext == 'avi':
        try:
            import subprocess
            raw = subprocess.run(['ffmpeg','-v','error','-i',path,'-f','rawvideo','-pix_fmt','rgb24','-'], capture_output=True, check=True).stdout
            a = np.frombuffer(raw, dtype=np.uint8)
            out.append(('avi_all', a))
            for ch in range(3):
                out.append((f'avi_ch{ch}', a[ch::3]))
            i = data.find(b'strf')
            if i >= 0:
                wv = struct.unpack('<i', data[i+12:i+16])[0]
                hv = struct.unpack('<i', data[i+16:i+20])[0]
                fsz = abs(wv*hv)*3
                if fsz and len(a) % fsz == 0:
                    for f in range(len(a)//fsz):
                        out.append((f'avi_f{f}', a[f*fsz:(f+1)*fsz]))
                # pixel-major across frames per channel (true bgra decode)
                try:
                    raw4 = subprocess.run(['ffmpeg','-v','error','-i',path,'-f','rawvideo','-pix_fmt','bgra','-'], capture_output=True, check=True).stdout
                    a4 = np.frombuffer(raw4, dtype=np.uint8)
                    wv2 = struct.unpack('<i', data[i+8+4:i+8+8])[0]
                    hv2 = abs(struct.unpack('<i', data[i+8+8:i+8+12])[0])
                    fsz4 = wv2*hv2*4
                    if fsz4 and len(a4) % fsz4 == 0:
                        fr = a4.reshape(-1, hv2, wv2, 4)
                        for ch in range(4):
                            out.append((f'avi4_ch{ch}', fr[:,:,:,ch].flatten()))
                            out.append((f'avi4_pixmajor_ch{ch}', fr[:,:,:,ch].transpose(1,2,0).flatten()))
                            out.append((f'avi4_pixmajorT_ch{ch}', fr[:,:,:,ch].transpose(2,1,0).flatten()))
                except Exception as e:
                    print('  avi4 err', e)
        except Exception as e:
            print('  avi err', e)
    return out

def solve_layer(n, fname, prev, mem):
    path = os.path.join(CDIR, fname)
    ext = fname.rsplit('.', 1)[-1].lower()
    data = open(path, 'rb').read()
    key = derive_key(prev, mem)
    ks = keystream(key)
    sig_bytes = bytes(ks[2+i] ^ KNOWN[i] for i in range(len(KNOWN)))
    sig_bits = np.array([(b >> (7-k)) & 1 for b in sig_bytes for k in range(8)], dtype=np.uint8)
    cands = []  # (name, block)

    # 1. appended / container content
    if ext == 'png':
        i = data.find(b'IEND'); app = data[i+8:]
        for off in range(0, max(0, len(app)-BLOCK+1)):
            cands.append((f'append@{off}', app[off:off+BLOCK]))
        # text chunks
        pos = 8
        while pos < len(data):
            ln = struct.unpack('>I', data[pos:pos+4])[0]
            typ = data[pos+4:pos+8]
            body = data[pos+8:pos+8+ln]
            if typ in (b'tEXt', b'iTXt', b'zTXt'):
                for b64 in re.findall(rb'[A-Za-z0-9+/]{200,}={0,2}', body):
                    try:
                        cands.append((f'textchunk:{typ.decode()}', base64.b64decode(b64)))
                    except Exception:
                        pass
            pos += 12+ln
            if typ == b'IEND':
                break
    if ext == 'png':
        # Layer 105: procedure shipped in layer 104's JSON ("script"): channel order
        # [2,0,1] (B,R,G), column-major pixel order, 1 LSB per sample, bits MSB-first.
        try:
            arr = np.array(Image.open(path).convert('RGB'))
            pixels = arr.transpose(1, 0, 2).reshape(-1, 3)
            bits = np.stack([pixels[:, 2], pixels[:, 0], pixels[:, 1]], axis=1).flatten() & 1
            cands.append(('l104script_col_BRG', bits_to_bytes(bits[:BLOCK*8], True)))
        except Exception as e:
            print('  l104 script err', e)
    if ext in ('jpg','jpeg'):
        i = data.rfind(b'\xff\xd9'); app = data[i+2:]
        for off in range(0, max(0, len(app)-BLOCK+1)):
            cands.append((f'append@{off}', app[off:off+BLOCK]))
        if not app:
            try:
                from jpegdct import decode_coefficients
                r = decode_coefficients(path)
                for cid, b in r.items():
                    for ci in range(64):
                        cands.append((f'dct_ci{ci}', bits_to_bytes(np.abs(b[:,ci]) & 1, True)))
                    ac = b[:,1:].flatten()
                    cands.append(('dct_acnz', bits_to_bytes(np.abs(ac[ac!=0]) & 1, True)))
                    cands.append(('dct_acgt1', bits_to_bytes(np.abs(ac[np.abs(ac)>1]) & 1, True)))
            except Exception as e:
                print('  dct err', e)
    if ext == 'wav':
        import wave
        try:
            w = wave.open(path, 'rb')
            frames = w.readframes(w.getnframes())
            for nm, arrb in [('wavbytes', np.frombuffer(frames, dtype=np.uint8)), ('wavlow', np.frombuffer(frames, dtype=np.uint8)[0::2]), ('wavhigh', np.frombuffer(frames, dtype=np.uint8)[1::2])]:
                for plane in range(2):
                    bits = (arrb >> plane) & 1
                    for msb in (True, False):
                        cands.append((f'{nm}_p{plane}_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
            if w.getnchannels() == 1 and w.getsampwidth() == 2:
                sr16 = np.frombuffer(frames, dtype='<i2')
                # binary on/off signal with pulse-gap encoding
                uvals = np.unique(sr16)
                if len(uvals) <= 4 and sr16.min() == 0:
                    b = (sr16 > 0).astype(np.uint8)
                    changes = np.where(np.diff(b) != 0)[0]
                    runs = np.diff(np.concatenate([[-1], changes, [len(b)-1]]))
                    vals = b[np.concatenate([[0], changes+1])]
                    gaplens = sorted(set(runs[vals==0].tolist()))
                    if len(gaplens) == 2:
                        bits = np.array([1 if runs[i] == gaplens[1] else 0 for i in range(len(runs)) if vals[i] == 0], dtype=np.uint8)
                        for nm, bb in [('gap', bits), ('gapinv', bits^1)]:
                            for msb in (True, False):
                                cands.append((f'pulsegap_{nm}_{"msb" if msb else "lsb"}', bits_to_bytes(bb, msb)))
                s = np.frombuffer(frames, dtype='<i2').astype(np.float64)
                sr = w.getframerate()
                s = np.frombuffer(frames, dtype='<i2').astype(np.float64)
                sr = w.getframerate()
                seg = s[:65536]
                sp = np.abs(np.fft.rfft(seg))
                binhz = sr/len(seg)
                top = np.argsort(sp)[-24:]
                cand_f = sorted(set(round(tb*binhz/250)*250.0 for tb in top if tb > 100))
                tone_sets = []
                if len(cand_f) >= 2:
                    tone_sets.append(cand_f[-2:])
                if len(cand_f) >= 4:
                    tone_sets.append(cand_f[-4:])
                import itertools
                for N in (32, 64, 128):
                    nw = len(s)//N
                    if nw < BLOCK*8//2:
                        continue
                    t = np.arange(N)/sr
                    wins = s[:nw*N].reshape(nw, N)
                    for tones in tone_sets:
                        if max(tones) >= sr/2:
                            continue
                        E = np.stack([np.abs(wins @ np.exp(-2j*np.pi*f*t)) for f in tones], axis=1)
                        dom = np.argmax(E, axis=1)
                        symsets = [dom]
                        if len(dom) % 2 == 0 and (dom[1::2] == dom[::2]).mean() > 0.99:
                            symsets.append(dom[::2])
                        if len(tones) == 2:
                            for ss in symsets:
                                for inv in (0, 1):
                                    bits = ss.astype(np.uint8) ^ inv
                                    for msb in (True, False):
                                        cands.append((f'fsk{N}_2t_inv{inv}_{"msb" if msb else "lsb"}{"_dd" if len(ss)!=len(dom) else ""}', bits_to_bytes(bits, msb)))
                        else:
                            for ss in symsets:
                                for perm in itertools.permutations(range(len(tones))):
                                    bits = []
                                    for d in ss:
                                        v = perm[d]
                                        bits += [(v>>1)&1, v&1]
                                    bits = np.array(bits, dtype=np.uint8)
                                    for msb in (True, False):
                                        cands.append((f'fsk{N}_4t_{perm}_{"msb" if msb else "lsb"}{"_dd" if len(ss)!=len(dom) else ""}', bits_to_bytes(bits, msb)))
            if w.getnchannels() == 2 and w.getsampwidth() == 2:
                s = np.frombuffer(frames, dtype='<i2')
                diff = s[0::2].astype(np.int32) - s[1::2].astype(np.int32)
                for nm, bits in [('LRgt', (diff>0).astype(np.uint8)), ('LRlt', (diff<0).astype(np.uint8))]:
                    for msb in (True, False):
                        cands.append((f'wavdiff_{nm}_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
        except Exception as e:
            print('  wav err', e)
    if ext == 'zip':
        try:
            z = zipfile.ZipFile(path)
            if z.comment:
                cands.append(('zipcomment', z.comment))
            for info in z.infolist():
                if info.file_size >= BLOCK or info.flag_bits & 1:
                    for pw in (None, hashlib.sha256(prev.encode()).hexdigest()[:12].encode()):
                        try:
                            cands.append((f'member:{info.filename}:{"pw" if pw else "plain"}', z.read(info.filename, pwd=pw)))
                            break
                        except RuntimeError:
                            continue
                        except Exception:
                            break
        except Exception as e:
            print('  zip err', e)
    if ext == 'tar':
        for start in range(0, len(data)-BLOCK+1, 512):
            cands.append((f'tar@{start}', data[start:start+BLOCK]))
    if ext == 'pdf':
        try:
            import pymupdf
            doc = pymupdf.open(path)
            for nm in doc.embfile_names():
                cands.append((f'emb:{nm}', doc.embfile_get(nm)))
            txt = ''.join(doc[p].get_text() for p in range(doc.page_count))
            hexes = re.findall(r'[0-9a-f]{64}', txt)
            if len(hexes) * 32 >= BLOCK:
                cands.append(('pdfhex', bytes.fromhex(''.join(hexes))))
                cands.append(('pdfhex_rev', bytes.fromhex(''.join(hexes[::-1]))))
            for x in range(1, doc.xref_length()):
                try:
                    obj = doc.xref_object(x)
                except Exception:
                    continue
                for b64 in re.findall(r'\(([^)]{600,})\)', obj, re.S):
                    try:
                        cands.append((f'xref{x}b64', base64.b64decode(b64)))
                    except Exception:
                        pass
            doc.close()
        except Exception as e:
            print('  pdf err', e)
        i = data.rfind(b'%%EOF'); app = data[i+5:]
        if app.startswith(b'PK'):
            try:
                z = zipfile.ZipFile(io.BytesIO(app))
                for info in z.infolist():
                    for pw in (None, hashlib.sha256(prev.encode()).hexdigest()[:12].encode()):
                        try:
                            cands.append((f'pdfzip:{info.filename}', z.read(info.filename, pwd=pw)))
                            break
                        except RuntimeError:
                            continue
                        except Exception:
                            break
            except Exception as e:
                print('  pdfzip err', e)
        else:
            for off in range(0, max(0, len(app)-BLOCK+1)):
                cands.append((f'pdfapp@{off}', app[off:off+BLOCK]))
    if ext in ('html','svg'):
        for i, b64 in enumerate(re.findall(rb'[A-Za-z0-9+/]{200,}={0,2}', data)):
            try:
                cands.append((f'b64_{i}', base64.b64decode(b64)))
            except Exception:
                pass
    if ext == 'py':
        m = re.search(rb'RESOURCE-PADDING-BEGIN\n(.*?)# RESOURCE-PADDING-END', data, re.S)
        if m:
            bloblines = [l[2:] for l in m.group(1).splitlines() if l.startswith(b'# ') and len(l) > 100]
            for blob in bloblines:
                for nm, fn in [('b85', base64.b85decode), ('a85', base64.a85decode)]:
                    try:
                        cands.append((nm, fn(blob)))
                    except Exception:
                        pass
    if ext == 'json':
        txt = data.decode()
        bits = [1 if mm.group(1) == '\t' else 0 for mm in re.finditer(r'0( |\t),', txt)]
        if bits:
            for msb in (True, False):
                cands.append((f'jsonws_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
    if ext == 'log':
        lines = data.decode().splitlines()
        from datetime import datetime
        tt = [datetime.fromisoformat(re.match(r'\[(.*?)\]', l).group(1)) for l in lines]
        deltas = [(tt[i+1]-tt[i]).total_seconds() for i in range(len(tt)-1)]
        for hi in set(deltas):
            bits = [1 if d == hi else 0 for d in deltas]
            for msb in (True, False):
                cands.append((f'logd{hi}_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
    if ext == 'txt':
        txt = data.decode()
        zw = [c for c in txt if c in '​‌']
        if len(zw) >= 8:
            for a, b in [('​','‌'), ('‌','​')]:
                bits = [0 if c == a else 1 for c in zw]
                for msb in (True, False):
                    cands.append((f'zw_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
        body = txt.split('-- margin records begin --', 1)
        if len(body) == 2:
            for tabval in (1, 0):
                bits = []
                for line in body[1].splitlines():
                    for ch in line:
                        if ch == '\t': bits.append(tabval)
                        elif ch == ' ': bits.append(1-tabval)
                for msb in (True, False):
                    cands.append((f'txtws{tabval}_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
    if ext == 'md':
        txt = data.decode()
        lines = txt.splitlines()
        # find a repeated template with one varying word
        import itertools, collections
        best = None
        for l in lines:
            mm = re.match(r'^(.*\()?(\w+)(\).*|\s.*)$', l)
        # generic: group lines by template with one word slot
        templates = collections.defaultdict(list)
        for l in lines:
            ws = l.split(' ')
            for i in range(len(ws)):
                key = ' '.join(ws[:i]) + ' <W> ' + ' '.join(ws[i+1:])
                templates[key].append(ws[i])
        for key, words in templates.items():
            if len(words) >= BLOCK*8//2:
                uniq = sorted(set(words))
                if len(uniq) == 2:
                    for w0 in uniq:
                        bits = np.array([1 if w == w0 else 0 for w in words], dtype=np.uint8)
                        for msb in (True, False):
                            cands.append((f'md2_{w0}_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
                elif len(uniq) == 4:
                    for perm in itertools.permutations(uniq):
                        mp = {w: i for i, w in enumerate(perm)}
                        bits = []
                        for w in words:
                            v = mp[w]
                            bits += [(v>>1)&1, v&1]
                        bits = np.array(bits, dtype=np.uint8)
                        for msb in (True, False):
                            cands.append((f'md4_{perm}_{"msb" if msb else "lsb"}', bits_to_bytes(bits, msb)))
                if cands:
                    break
        if cands:
            pass

    # 1b. generic base64 blob scan over the whole file (long runs only, allowing newlines)
    for i, b64 in enumerate(re.findall(rb'[A-Za-z0-9+/\s]{1024,}={0,2}', data)):
        try:
            cands.append((f'fileb64_{i}', base64.b64decode(re.sub(rb'\s', b'', b64))))
        except Exception:
            pass

    # 2. direct candidate tests
    hits = []
    for nm, blk in cands:
        j = try_block(blk, ks, n)
        if j:
            hits.append((nm, j))
    if hits:
        return hits

    # 3. signature search over image/audio bit streams
    for nm, s in image_streams(path, ext, data):
        for plane in range(3):
            bits = (s >> plane) & 1
            for m in sig_search_bits(bits, sig_bits):
                bitpos = int(m) - 16
                if bitpos < 0:
                    continue
                for msb in (True, False):
                    blk = bits_to_bytes(bits[bitpos:], msb)
                    j = try_block(blk, ks, n)
                    if j:
                        return [(f'sig:{nm}:p{plane}:{"msb" if msb else "lsb"}@{bitpos}', j)]
    # 4. raw file signature scan
    pos = data.find(sig_bytes)
    while pos >= 0:
        j = try_block(data[pos-2:pos-2+BLOCK], ks, n)
        if j:
            return [(f'rawsig@{pos-2}', j)]
        pos = data.find(sig_bytes, pos+1)
    return []

def zw_decode(field):
    """U+200B = 0, U+200C = 1, 8 bits per character, MSB first."""
    bits = ''.join('0' if c == '\u200b' else '1' for c in field if c in '\u200b\u200c')
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) // 8 * 8, 8)).decode()

def memory_candidates(n, st):
    """Ordered guesses for the memory values of layer n, derived from the notes
    found in earlier layers (the packet is only accepted if its JSON framing and
    layer number validate, so a wrong guess simply fails)."""
    L, art = st['layers'], st['artifacts']
    cands = []
    prev = L.get(str(n - 1), {})
    if n == 76:
        cands.append([L['75']['checkpoint']])            # L75 checkpoint = key material
    if 'next_memory_note' in prev:                         # L91 -> 92 (art 25), L107 -> 108 (art 50)
        m = re.search(r'layer (\d+)', prev['next_memory_note'])
        if m and m.group(1) in L:
            ref = L[m.group(1)]
            if 'identification' in prev['next_memory_note'] or 'identification' in prev['next_memory_note'].lower() or 'carrier identification' in prev['next_memory_note']:
                cands.append([ref['identification']])   # L120 -> 121 (L100 carrier identification)
            cands.append([art[m.group(1)]])
    if 'handoff_zwsp' in prev:                             # L117 -> 118 (hidden zero-width value)
        cands.append([zw_decode(prev['handoff_zwsp'])])
    if n >= 136 and all(k in L for k in ('75', '100', '125')):   # finale ledger
        cands.append([art['1'], art['25'], art['50'], L['75']['checkpoint'],
                      L['100']['identification'], art['125']])
    cands.append([])
    out = []
    for c in cands:
        if c not in out:
            out.append(c)
    return out

def solve(start=1, end=150):
    if os.path.exists(STATE):
        st = json.load(open(STATE))
    else:
        st = {'token': 'paper-window-53', 'artifacts': {}, 'layers': {}}
    files = {int(f.split('_')[0]): f for f in os.listdir(CDIR) if f[:3].isdigit()}
    for n in range(start, end + 1):
        fname = files[n]
        hits = []
        for mem in memory_candidates(n, st):
            hits = solve_layer(n, fname, st['token'], mem)
            if hits:
                break
        if not hits:
            print(f'L{n} {fname}: NO HIT')
            return st, n
        nm, j = hits[0]
        extra = {k: v for k, v in j.items() if k not in ('layer', 'token', 'artifact', 'digest')}
        print(f'L{n} {fname}: OK via {nm} token={j.get("token")} art={j.get("artifact")} mem={mem} extra={list(extra)}')
        st['layers'][str(n)] = j
        st['token'] = j.get('token', st['token'])
        if j.get('artifact'):
            st['artifacts'][str(n)] = j['artifact']
        json.dump(st, open(STATE, 'w'), indent=1)
    return st, None

if __name__ == '__main__':
    s = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    e = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    st, fail = solve(s, e)
    print('DONE' if fail is None else f'STOPPED at {fail}')
    if fail is None and '150' in st['layers']:
        print('FINAL FLAG:', st['layers']['150'].get('flag'))
