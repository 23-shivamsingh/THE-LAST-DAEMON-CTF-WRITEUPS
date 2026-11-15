#!/usr/bin/env python3
"""Baseline JPEG DCT coefficient extractor (grayscale / multi-component)."""
import numpy as np

class BitReader:
    def __init__(self, data):
        self.d = data
        self.pos = 0
        self.buf = 0
        self.n = 0
    def bit(self):
        if self.n == 0:
            b = self.d[self.pos]
            self.pos += 1
            if b == 0xFF:
                nb = self.d[self.pos]
                if nb == 0x00:
                    self.pos += 1
                elif 0xD0 <= nb <= 0xD7:
                    self.pos += 1  # restart marker: realign
                    self.buf = 0; self.n = 0
                    return self.bit()
                else:
                    raise EOFError('marker')
            self.buf = b
            self.n = 8
        self.n -= 1
        return (self.buf >> self.n) & 1
    def bits(self, k):
        v = 0
        for _ in range(k):
            v = (v << 1) | self.bit()
        return v

def build_huff(lengths, symbols):
    table = {}
    code = 0
    k = 0
    for l in range(1, 17):
        for _ in range(lengths[l-1]):
            table[(l, code)] = symbols[k]
            code += 1
            k += 1
        code <<= 1
    return table

def huff_decode(br, table):
    code = 0
    for l in range(1, 17):
        code = (code << 1) | br.bit()
        if (l, code) in table:
            return table[(l, code)]
    raise ValueError('bad huffman')

def receive_extend(br, s):
    if s == 0:
        return 0
    v = br.bits(s)
    if v < (1 << (s-1)):
        v -= (1 << s) - 1
    return v

def parse_jpeg(path):
    d = open(path, 'rb').read()
    i = 2
    dqt = {}
    dht = {}
    comps = []
    width = height = 0
    scan_data = None
    while i < len(d)-1:
        if d[i] != 0xFF:
            i += 1
            continue
        m = d[i+1]
        if m in (0xD8,) or (0xD0 <= m <= 0xD7):
            i += 2
            continue
        ln = int.from_bytes(d[i+2:i+4], 'big')
        body = d[i+4:i+2+ln]
        if m == 0xDB:
            j = 0
            while j < len(body):
                pq, tq = body[j] >> 4, body[j] & 15
                j += 1
                vals = list(body[j:j+64])
                dqt[tq] = vals
                j += 64
        elif m == 0xC4:
            j = 0
            while j < len(body):
                tc, th = body[j] >> 4, body[j] & 15
                j += 1
                lengths = list(body[j:j+16])
                j += 16
                ns = sum(lengths)
                symbols = list(body[j:j+ns])
                j += ns
                dht[(tc, th)] = build_huff(lengths, symbols)
        elif m in (0xC0, 0xC1):
            height = int.from_bytes(body[1:3], 'big')
            width = int.from_bytes(body[3:5], 'big')
            nc = body[5]
            for k in range(nc):
                cid, hv, tq = body[6+3*k], body[7+3*k], body[8+3*k]
                comps.append({'id': cid, 'h': hv >> 4, 'v': hv & 15, 'tq': tq})
        elif m == 0xDA:
            ns = body[0]
            scan_comps = []
            for k in range(ns):
                cs, tt = body[1+2*k], body[2+2*k]
                scan_comps.append({'id': cs, 'dc': tt >> 4, 'ac': tt & 15})
            scan_data = d[i+2+ln:]
            # trim to EOI
            eoi = scan_data.rfind(b'\xff\xd9')
            if eoi >= 0:
                scan_data = scan_data[:eoi]
            break
        elif m == 0xD9:
            break
        i += 2 + ln
    return {'dqt': dqt, 'dht': dht, 'comps': comps, 'scan_comps': scan_comps,
            'w': width, 'h': height, 'scan': scan_data}

def decode_coefficients(path):
    """Returns dict comp_id -> array (num_blocks, 64) of quantized DCT coefficients (zigzag order)."""
    p = parse_jpeg(path)
    br = BitReader(p['scan'])
    result = {}
    # assume single scan, no subsampling beyond stored (supports h,v sampling factors 1 for simplicity; if 2x2, handle MCUs)
    ncomp = len(p['scan_comps'])
    if ncomp == 1:
        c = p['comps'][0]
        sc = p['scan_comps'][0]
        nx = (p['w'] + 7)//8
        ny = (p['h'] + 7)//8
        dc_pred = 0
        blocks = []
        for _ in range(nx*ny):
            s = huff_decode(br, p['dht'][(0, sc['dc'])])
            diff = receive_extend(br, s)
            dc_pred += diff
            block = [0]*64
            block[0] = dc_pred
            k = 1
            while k < 64:
                rs = huff_decode(br, p['dht'][(1, sc['ac'])])
                r, sz = rs >> 4, rs & 15
                if sz == 0:
                    if r == 15:
                        k += 16
                        continue
                    break  # EOB
                k += r
                if k >= 64:
                    break
                block[k] = receive_extend(br, sz)
                k += 1
            blocks.append(block)
        result[c['id']] = np.array(blocks, dtype=np.int32)
    else:
        # interleaved multi-component with sampling factors
        maxh = max(c['h'] for c in p['comps'])
        maxv = max(c['v'] for c in p['comps'])
        mcux = (p['w'] + 8*maxh - 1)//(8*maxh)
        mcuy = (p['h'] + 8*maxv - 1)//(8*maxv)
        dc_pred = {c['id']: 0 for c in p['comps']}
        blocks = {c['id']: [] for c in p['comps']}
        compmap = {c['id']: c for c in p['comps']}
        for _ in range(mcux*mcuy):
            for sc in p['scan_comps']:
                c = compmap[sc['id']]
                for _ in range(c['h']*c['v']):
                    s = huff_decode(br, p['dht'][(0, sc['dc'])])
                    diff = receive_extend(br, s)
                    dc_pred[sc['id']] += diff
                    block = [0]*64
                    block[0] = dc_pred[sc['id']]
                    k = 1
                    while k < 64:
                        rs = huff_decode(br, p['dht'][(1, sc['ac'])])
                        r, sz = rs >> 4, rs & 15
                        if sz == 0:
                            if r == 15:
                                k += 16
                                continue
                            break
                        k += r
                        if k >= 64:
                            break
                        block[k] = receive_extend(br, sz)
                        k += 1
                    blocks[sc['id']].append(block)
        for cid in blocks:
            result[cid] = np.array(blocks[cid], dtype=np.int32)
    return result

if __name__ == '__main__':
    import sys
    r = decode_coefficients(sys.argv[1])
    for cid, b in r.items():
        print('comp', cid, 'blocks', b.shape, 'nonzero ac', (b[:,1:] != 0).sum())
