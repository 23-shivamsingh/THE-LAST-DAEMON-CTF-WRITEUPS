#!/usr/bin/env python3
"""Extraction functions from the supplied Forger's Gallery author package.

This file contains only the parser/stego decoders and their supporting helpers.
It deliberately excludes author seed, embedded answer, and carrier generation.
"""
from __future__ import annotations
import argparse, base64, hashlib, hmac, io, json, math, os, random, shutil, struct, subprocess, tempfile, wave, zipfile, zlib
from pathlib import Path
from typing import Callable
import numpy as np
from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
import fitz


def xor_repeat(data: bytes, key: bytes) -> bytes:
    if not key: raise ValueError("empty XOR key")
    return bytes(b ^ key[i % len(key)] for i,b in enumerate(data))

def bytes_from_bits(bits: list[int]) -> bytes:
    if len(bits) % 8: raise ValueError(f"bit count {len(bits)} is not a multiple of 8")
    out=bytearray()
    for i in range(0,len(bits),8):
        v=0
        for bit in bits[i:i+8]: v=(v<<1)|int(bit)
        out.append(v)
    return bytes(out)

def png_chunks(data: bytes):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"): raise ValueError("not PNG")
    pos=8
    while pos+12<=len(data):
        length=struct.unpack(">I",data[pos:pos+4])[0]
        typ=data[pos+4:pos+8]; payload=data[pos+8:pos+8+length]
        yield pos,typ,payload,pos+12+length
        pos+=12+length
        if typ==b"IEND": break

def extract_png_chunk(data: bytes, typ: bytes) -> bytes:
    for _,t,p,_ in png_chunks(data):
        if t==typ:return p
    raise ValueError(f"PNG chunk {typ!r} not found")

def jpeg_segments(data: bytes):
    if not data.startswith(b"\xff\xd8"): raise ValueError("not JPEG")
    pos=2
    while pos+4<=len(data):
        if data[pos]!=0xff: # entropy stream; skip stuffed bytes until next marker
            pos+=1; continue
        while pos<len(data) and data[pos]==0xff: pos+=1
        if pos>=len(data): break
        marker=data[pos]; pos+=1
        if marker in (0xd9,0xda):
            if marker==0xda:
                # SOS found; enough for the marker inventory in this challenge.
                yield marker,b"",pos-2
            break
        if marker in range(0xd0,0xd8) or marker==0x01: continue
        if pos+2>len(data): break
        ln=struct.unpack(">H",data[pos:pos+2])[0]
        if ln<2 or pos+ln>len(data): break
        payload=data[pos+2:pos+ln]
        yield marker,payload,pos-2
        pos+=ln

def extract_green_lsb(path,nbytes):
    a=np.array(Image.open(path).convert("RGB")); flat=a.reshape(-1,3)
    return bytes_from_bits([int(flat[i,1])&1 for i in range(nbytes*8)])

def extract_bmp_2bit(path,nbytes):
    a=np.array(Image.open(path).convert("RGB")).reshape(-1)
    vals=[int(x)&3 for x in a[:nbytes*4]]
    bits=[]
    for v in vals: bits.extend([(v>>1)&1,v&1])
    return bytes_from_bits(bits[:nbytes*8])

def wav_read_samples(path):
    with wave.open(str(path),"rb") as w:
        params=(w.getnchannels(),w.getsampwidth(),w.getframerate(),w.getnframes(),w.getcomptype())
        frames=w.readframes(w.getnframes())
    if params[1]!=2: raise ValueError("challenge WAV expected 16-bit PCM")
    vals=np.frombuffer(frames,dtype="<i2").astype(np.int32)
    if params[0]>1: vals=vals.reshape(-1,params[0])
    return params,vals

def extract_wav_lsb(path,nbytes,channel=0):
    params,vals=wav_read_samples(path); flat=vals[:,channel] if params[0]>1 else vals
    return bytes_from_bits([int(v)&1 for v in flat[:nbytes*8]])

def extract_wav_delta(path,nbytes):
    params,vals=wav_read_samples(path); a=vals.reshape(-1); bits=[]
    for i in range(nbytes*8): bits.append((int(a[2*i+1])-int(a[2*i]))&1)
    return bytes_from_bits(bits)

def extract_wav_fsk(path,nbytes,fs_expected=8000,bit_duration=0.02):
    params,vals=wav_read_samples(path); fs=params[2]; a=np.asarray(vals).reshape(-1)
    nper=int(fs*bit_duration); bits=[]
    for i in range(nbytes*8):
        seg=a[i*nper:(i+1)*nper].astype(float)
        if len(seg)!=nper: raise ValueError("FSK segment truncated")
        spec=np.abs(np.fft.rfft(seg*np.hanning(len(seg))))
        freq=np.fft.rfftfreq(len(seg),1/fs)
        e0=spec[(freq>500)&(freq<1000)].sum(); e1=spec[(freq>1500)&(freq<2100)].sum()
        bits.append(1 if e1>e0 else 0)
    return bytes_from_bits(bits)

def extract_wav_phase(path,nbytes,fs=8000,bit_duration=0.02):
    params,vals=wav_read_samples(path);a=np.asarray(vals).reshape(-1); nper=int(fs*bit_duration); bits=[]
    for i in range(nbytes*8):
        seg=a[i*nper:(i+1)*nper].astype(float); t=np.arange(len(seg))/fs; ref=np.sin(2*np.pi*440*t)
        bits.append(1 if np.dot(seg,ref)<0 else 0)
    return bytes_from_bits(bits)

def extract_wav_stereo_ratio(path,nbytes,bit_duration=0.04):
    params,vals=wav_read_samples(path);nper=int(params[2]*bit_duration);bits=[]
    for i in range(nbytes*8):
        seg=vals[i*nper:(i+1)*nper,:].astype(float)
        el=np.mean(np.abs(seg[:,0])); er=np.mean(np.abs(seg[:,1]));bits.append(0 if el>er else 1)
    return bytes_from_bits(bits)

def extract_wav_silence_gate(path,nbytes,bit_duration=0.04):
    params,vals=wav_read_samples(path);a=np.asarray(vals).reshape(-1);nper=int(params[2]*bit_duration);bits=[]
    for i in range(nbytes*8):bits.append(1 if np.sqrt(np.mean(a[i*nper:(i+1)*nper].astype(float)**2))>80 else 0)
    return bytes_from_bits(bits)

def extract_txt_zerowidth(path,nbytes):
    s=Path(path).read_text(encoding="utf-8"); region=s.split("[BEGIN RESTORATION MARKS]",1)[1].split("[END RESTORATION MARKS]",1)[0]
    bits=[0 if c=='\u200b' else 1 for c in region if c in ('\u200b','\u200c')]
    return bytes_from_bits(bits[:nbytes*8])

def extract_png_alpha(path,nbytes):
    a=np.array(Image.open(path).convert("RGBA"));alpha=a[:,:,3].reshape(-1)
    return bytes_from_bits([int(v)&1 for v in alpha[:nbytes*8]])

def extract_palette_order(path,nbytes):
    img=Image.open(path); pal=img.getpalette();bits=[]
    for j in range(nbytes*8):
        r1=pal[(2*j)*3];r2=pal[(2*j+1)*3];bits.append(1 if r1>r2 else 0)
    return bytes_from_bits(bits)

def extract_bmp_region(path,nbytes):
    a=np.array(Image.open(path).convert("RGB"));coords=[(x,y) for y in range(20,36) for x in range(24,40)]
    return bytes_from_bits([int(a[y,x,1])&1 for x,y in coords[:nbytes*8]])

def extract_jpeg_xmp(path,nbytes):
    data=Path(path).read_bytes()
    for marker,payload,_ in jpeg_segments(data):
        if marker==0xe1 and payload.startswith(b'http://ns.adobe.com/xap/1.0/\x00'):
            import re
            m=re.search(rb'g:seal="([0-9a-f]+)"',payload)
            if m:return bytes.fromhex(m.group(1).decode())
    raise ValueError("XMP seal not found")

def extract_riff_chunk(path):
    b=Path(path).read_bytes()
    if b[:4]!=b'RIFF' or b[8:12]!=b'WAVE':raise ValueError('not RIFF/WAVE')
    p=12
    while p+8<=len(b):
        cid=b[p:p+4];n=struct.unpack('<I',b[p+4:p+8])[0];data=b[p+8:p+8+n]
        if cid==b'sTeG':return data
        p+=8+n+(n%2)
    raise ValueError('RIFF chunk missing')

def extract_png_histogram(path,nbytes):
    a=np.array(Image.open(path).convert('L')).reshape(-1);hist=np.bincount(a,minlength=256);bits=[]
    for i in range(nbytes*8):bits.append(0 if hist[2*i]>hist[2*i+1] else 1)
    return bytes_from_bits(bits)

def jpeg_dqt_ranges(data: bytes):
    # Return [(byte offset to quant values, precision, count)] over all DQT tables, before SOS.
    res=[]
    if not data.startswith(b'\xff\xd8'):raise ValueError('not JPEG')
    pos=2
    while pos+4<=len(data):
        if data[pos]!=0xff: pos+=1; continue
        while pos<len(data) and data[pos]==0xff:pos+=1
        if pos>=len(data):break
        marker=data[pos];pos+=1
        if marker in (0xda,0xd9):break
        if marker in range(0xd0,0xd8) or marker==0x01:continue
        ln=struct.unpack('>H',data[pos:pos+2])[0];start=pos+2;end=pos+ln
        if marker==0xdb:
            q=start
            while q<end:
                info=data[q];q+=1;prec=info>>4;cnt=64*(2 if prec else 1)
                res.append((q,prec,cnt));q+=cnt
        pos=end
    return res

def extract_jpeg_dqt(path,nbytes):
    b=Path(path).read_bytes();bits=[]
    for off,prec,count in jpeg_dqt_ranges(b):
        unit=2 if prec else 1
        for j in range(count):
            p=off+j*unit
            q=struct.unpack('>H',b[p:p+2])[0] if prec else b[p]
            bits.append(q&1)
            if len(bits)>=nbytes*8:return bytes_from_bits(bits)
    raise ValueError('insufficient DQT capacity')

def extract_txt_whitespace(path,nbytes):
    lines=Path(path).read_text(encoding='utf-8').splitlines()
    line=lines[-1];bits=[0 if c==' ' else 1 for c in line if c in (' ','\t')]
    return bytes_from_bits(bits[:nbytes*8])

def extract_gif_transparency(path,nbytes):
    img=Image.open(path);p=list(img.getdata());return bytes_from_bits([1 if p[i]==1 else 0 for i in range(nbytes*8)])

def extract_png_channel_relation(path,nbytes):
    a=np.array(Image.open(path).convert('RGB')).reshape(-1,3)
    return bytes_from_bits([(int(a[i,0])^int(a[i,2]))&1 for i in range(nbytes*8)])

def extract_bmp_row_padding(path,nbytes):
    b=Path(path).read_bytes();off=struct.unpack_from('<I',b,10)[0];w=struct.unpack_from('<I',b,18)[0];h=struct.unpack_from('<I',b,22)[0];bpp=struct.unpack_from('<H',b,28)[0]
    row=((w*bpp+31)//32)*4;raw=(w*bpp)//8;pad=row-raw;bits=[]
    for rowi in range(h):
        for j in range(pad):
            bits.append(b[off+rowi*row+raw+j]&1)
            if len(bits)>=nbytes*8:return bytes_from_bits(bits)
    raise ValueError('padding bits too short')

def extract_png_ztxt(path,nbytes):
    return bytes.fromhex(Image.open(path).info['RestorerNote'])

def extract_zip_comment(path):
    with zipfile.ZipFile(path,'r') as z:
        c=z.comment
    if not c.startswith(b'GALLERY:'):raise ValueError('archive comment missing')
    return bytes.fromhex(c.split(b':',1)[1].decode())

def extract_zip_extra(path):
    with zipfile.ZipFile(path,'r') as z:
        extra=z.infolist()[0].extra;p=0
        while p+4<=len(extra):
            tag,n=struct.unpack_from('<HH',extra,p);p+=4;val=extra[p:p+n];p+=n
            if tag==0xcafe:return val
    raise ValueError('CAFE extra field not found')

def extract_jpeg_com(path,nbytes):
    for marker,payload,_ in jpeg_segments(Path(path).read_bytes()):
        if marker==0xfe and payload.startswith(b'Gallery note:'):
            return bytes.fromhex(payload.split(b':',1)[1].decode())
    raise ValueError('COM payload missing')

def extract_txt_acrostic(path,nbytes):
    lines=Path(path).read_text(encoding='utf-8').splitlines()[1:];v=set('AEIOU')
    bits=[]
    for line in lines[:nbytes*8]:
        first=next((c.upper() for c in line if c.isalpha()),'B');bits.append(0 if first in v else 1)
    return bytes_from_bits(bits)

def extract_bmp_dct(path,nbytes):
    import math
    N=8;C=np.zeros((N,N),float)
    for u in range(N):
        alpha=math.sqrt(1/N) if u==0 else math.sqrt(2/N)
        for x in range(N):C[u,x]=alpha*math.cos(math.pi*(2*x+1)*u/(2*N))
    a=np.array(Image.open(path).convert('L'),dtype=float);bits=[]
    for i in range(nbytes*8):
        by,bx=divmod(i,12);blk=a[by*N:(by+1)*N,bx*N:(bx+1)*N]-128;coef=C@blk@C.T
        bits.append(1 if coef[3,2]>60 else 0)
    return bytes_from_bits(bits)

def extract_pdf_subject(path,nbytes):
    doc=fitz.open(path);sub=doc.metadata.get('subject','');doc.close();return bytes.fromhex(sub.split('Record=',1)[1])

def extract_txt_variation(path,nbytes):
    s=Path(path).read_text(encoding='utf-8');r=s.split('[margin]',1)[1].split('[/margin]',1)[0]
    return bytes_from_bits([0 if c=='\ufe0e' else 1 for c in r if c in ('\ufe0e','\ufe0f')][:nbytes*8])

def extract_bmp_blue_bit2(path,nbytes):
    a=np.array(Image.open(path).convert('RGB')).reshape(-1,3)
    return bytes_from_bits([(int(a[i,2])>>2)&1 for i in range(nbytes*8)])

def extract_jpeg_app2(path,nbytes):
    for marker,payload,_ in jpeg_segments(Path(path).read_bytes()):
        if marker==0xe2 and payload.startswith(b'GALLERY-SWATCH\x00'):return bytes.fromhex(payload.split(b'\x00',1)[1].decode())
    raise ValueError('APP2 swatch missing')

def extract_bmp_runlength(path,nbytes):
    a=np.array(Image.open(path).convert('L'))[0];runs=[];prev=int(a[0]);n=0
    for v in a:
        v=int(v)
        if v==prev:n+=1
        else:runs.append(n);prev=v;n=1
    runs.append(n);bits=[]
    for run in runs[:nbytes*8]:
        if run not in (4,5):raise ValueError(f'unexpected run size {run}')
        bits.append(1 if run==5 else 0)
    return bytes_from_bits(bits)

def extract_txt_bidi(path,nbytes):
    s=Path(path).read_text(encoding='utf-8');r=s.split('[margin]',1)[1].split('[/margin]',1)[0]
    return bytes_from_bits([0 if c=='\u202a' else 1 for c in r if c in ('\u202a','\u202e')][:nbytes*8])

def extract_zip_nested(path):
    with zipfile.ZipFile(path) as z:raw=z.read('sleeve.zip')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:return z.read('restorer.note')

def extract_png_index_parity(path,nbytes):
    img=Image.open(path).convert('P');p=list(img.getdata());return bytes_from_bits([int(p[i])&1 for i in range(nbytes*8)])

def extract_jpeg_app13(path,nbytes):
    for marker,payload,_ in jpeg_segments(Path(path).read_bytes()):
        if marker==0xed and payload.startswith(b'Photoshop 3.0\x00'):
            m=payload.find(b'GallerySeal')
            if m!=-1:
                # after Pascal name length + name + optional padding comes a 4-byte data size
                pos=m+len(b'GallerySeal');
                if pos%2:pos+=1
                if pos+4>len(payload):continue
                n=struct.unpack('>I',payload[pos:pos+4])[0];val=payload[pos+4:pos+4+n]
                return bytes.fromhex(val.decode())
    raise ValueError('APP13 resource missing')

def extract_txt_wordcount(path,nbytes):
    lines=Path(path).read_text(encoding='utf-8').splitlines()[1:];bits=[]
    for line in lines[:nbytes*8]:bits.append(len(line.split())%2)
    return bytes_from_bits(bits)

def extract_bmp_rb_order(path,nbytes):
    a=np.array(Image.open(path).convert('RGB')).reshape(-1,3)
    return bytes_from_bits([1 if int(a[i,0])>int(a[i,2]) else 0 for i in range(nbytes*8)])

def extract_bmp_reserved_alpha(path,nbytes):
    b=Path(path).read_bytes();off=struct.unpack_from('<I',b,10)[0];w=struct.unpack_from('<I',b,18)[0];h=struct.unpack_from('<I',b,22)[0];bpp=struct.unpack_from('<H',b,28)[0]
    if bpp!=32:raise ValueError('expected 32-bit BMP')
    stride=((w*bpp+31)//32)*4;bits=[]
    for y in range(h):
        for x in range(w):
            bits.append(b[off+y*stride+x*4+3]&1)
            if len(bits)>=nbytes*8:return bytes_from_bits(bits)

def extract_jpeg_zip_polyglot(path):
    b=Path(path).read_bytes()
    with zipfile.ZipFile(io.BytesIO(b)) as z:
        c=z.comment
    if not c.startswith(b'LASTSEAL:'):raise ValueError('polyglot seal missing')
    return bytes.fromhex(c.split(b':',1)[1].decode())

def extract_video_frame_lsb(path,nbytes):
    with tempfile.TemporaryDirectory(prefix="gallery_extract_") as td:
        out=Path(td)/"frame.png"
        cmd=["ffmpeg","-v","error","-y","-i",str(path),"-vf",r"select=eq(n\,7)","-vsync","0","-frames:v","1",str(out)]
        subprocess.run(cmd,check=True,capture_output=True)
        return extract_green_lsb(out,nbytes)

def extract_layer(method,path,nbytes):
    p=Path(path)
    if method=='appended_png':
        b=p.read_bytes();end=None
        for _,t,_,e in png_chunks(b):
            if t==b'IEND':end=e;break
        if end is None:raise ValueError('PNG IEND not found')
        return b[end:end+nbytes]
    if method=='jpeg_exif':
        ex=Image.open(p).getexif();v=ex.get(270,'');return bytes.fromhex(v.split('Inventory ',1)[1])
    if method=='bmp_green_lsb':return extract_green_lsb(p,nbytes)
    if method=='wav_delta':return extract_wav_delta(p,nbytes)
    if method=='png_custom_chunk':return extract_png_chunk(p.read_bytes(),b'stEg')
    if method=='jpeg_appended':
        b=p.read_bytes();idx=b.rfind(b'\xff\xd9')
        if idx<0:raise ValueError('JPEG EOI missing')
        return b[idx+2:idx+2+nbytes]
    if method=='bmp_2bit':return extract_bmp_2bit(p,nbytes)
    if method=='wav_fsk':return extract_wav_fsk(p,nbytes)
    if method=='txt_zerowidth':return extract_txt_zerowidth(p,nbytes)
    if method in ('png_alpha','png_final_alpha'):return extract_png_alpha(p,nbytes)
    if method=='gif_palette_order':return extract_palette_order(p,nbytes)
    if method=='bmp_region_lsb':return extract_bmp_region(p,nbytes)
    if method=='jpeg_xmp':return extract_jpeg_xmp(p,nbytes)
    if method=='wav_riff_chunk':return extract_riff_chunk(p)
    if method=='zip_comment':return extract_zip_comment(p)
    if method=='png_histogram':return extract_png_histogram(p,nbytes)
    if method=='jpeg_dqt':return extract_jpeg_dqt(p,nbytes)
    if method=='txt_whitespace':return extract_txt_whitespace(p,nbytes)
    if method=='gif_transparency':return extract_gif_transparency(p,nbytes)
    if method=='png_channel_relation':return extract_png_channel_relation(p,nbytes)
    if method=='bmp_row_padding':return extract_bmp_row_padding(p,nbytes)
    if method=='png_ztxt':return extract_png_ztxt(p,nbytes)
    if method=='wav_right_lsb':return extract_wav_lsb(p,nbytes,channel=1)
    if method=='zip_extra':return extract_zip_extra(p)
    if method=='png_palette_order':return extract_palette_order(p,nbytes)
    if method=='jpeg_com':return extract_jpeg_com(p,nbytes)
    if method=='txt_acrostic':return extract_txt_acrostic(p,nbytes)
    if method=='wav_phase':return extract_wav_phase(p,nbytes)
    if method=='bmp_dct':return extract_bmp_dct(p,nbytes)
    if method=='pdf_subject':return extract_pdf_subject(p,nbytes)
    if method=='txt_variation':return extract_txt_variation(p,nbytes)
    if method=='bmp_blue_bit2':return extract_bmp_blue_bit2(p,nbytes)
    if method=='wav_lsb':return extract_wav_lsb(p,nbytes)
    if method=='jpeg_app2':return extract_jpeg_app2(p,nbytes)
    if method=='bmp_runlength':return extract_bmp_runlength(p,nbytes)
    if method=='txt_bidi':return extract_txt_bidi(p,nbytes)
    if method=='zip_nested':return extract_zip_nested(p)
    if method=='png_index_parity':return extract_png_index_parity(p,nbytes)
    if method=='jpeg_app13':return extract_jpeg_app13(p,nbytes)
    if method=='wav_stereo_ratio':return extract_wav_stereo_ratio(p,nbytes)
    if method=='txt_wordcount':return extract_txt_wordcount(p,nbytes)
    if method=='bmp_reserved_alpha':return extract_bmp_reserved_alpha(p,nbytes)
    if method=='bmp_rb_order':return extract_bmp_rb_order(p,nbytes)
    if method=='wav_silence_gate':return extract_wav_silence_gate(p,nbytes)
    if method=='jpeg_zip_polyglot':return extract_jpeg_zip_polyglot(p)
    if method=='video_frame_lsb':return extract_video_frame_lsb(p,nbytes)
    raise ValueError('no extractor for '+method)
