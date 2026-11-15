"""My own PKZIP traditional (ZipCrypto) decryption + minimal ZIP member reader."""
import struct, zlib, binascii

CRCTAB = [0]*256
for n in range(256):
    c = n
    for _ in range(8):
        c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    CRCTAB[n] = c

def _crc32_update(crc, b):
    return ((crc >> 8) ^ CRCTAB[(crc ^ b) & 0xFF]) & 0xFFFFFFFF

class ZipCrypto:
    def __init__(self, password: bytes):
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for b in password:
            self._update(b)

    def _update(self, b):
        self.k[0] = _crc32_update(self.k[0], b)
        self.k[1] = ((self.k[1] + (self.k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k[2] = _crc32_update(self.k[2], (self.k[1] >> 24) & 0xFF)

    def decrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for c in data:
            t = (self.k[2] | 2) & 0xFFFF
            p = c ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            self._update(p)
            out.append(p)
        return bytes(out)

def open_encrypted_zip(zip_bytes: bytes, password: str):
    """returns dict {name: content}; supports stored/deflate members, ZipCrypto."""
    # locate End of Central Directory
    eocd = zip_bytes.rfind(b'PK\x05\x06')
    assert eocd >= 0, 'not a zip'
    count = struct.unpack_from('<H', zip_bytes, eocd + 10)[0]
    cd_off = struct.unpack_from('<I', zip_bytes, eocd + 16)[0]
    files = {}
    p = cd_off
    for _ in range(count):
        assert zip_bytes[p:p+4] == b'PK\x01\x02'
        (method, flags, crc, csize, usize, nlen, elen, clen, lho) = (
            struct.unpack_from('<H', zip_bytes, p+10)[0],
            struct.unpack_from('<H', zip_bytes, p+8)[0],
            struct.unpack_from('<I', zip_bytes, p+16)[0],
            struct.unpack_from('<I', zip_bytes, p+20)[0],
            struct.unpack_from('<I', zip_bytes, p+24)[0],
            struct.unpack_from('<H', zip_bytes, p+28)[0],
            struct.unpack_from('<H', zip_bytes, p+30)[0],
            struct.unpack_from('<H', zip_bytes, p+32)[0],
            struct.unpack_from('<I', zip_bytes, p+42)[0],
        )
        name = zip_bytes[p+46:p+46+nlen].decode()
        lnlen = struct.unpack_from('<H', zip_bytes, lho+26)[0]
        lelen = struct.unpack_from('<H', zip_bytes, lho+28)[0]
        data_start = lho + 30 + lnlen + lelen
        raw = zip_bytes[data_start:data_start+csize]
        if flags & 0x01:
            zc = ZipCrypto(password.encode())
            plain = zc.decrypt(raw)
            header, comp = plain[:12], plain[12:]
            check_byte = (crc >> 24) & 0xFF if not (flags & 0x08) else (struct.unpack_from('<H', zip_bytes, lho+10)[0] >> 8) & 0xFF
            assert header[11] == check_byte, f'password check failed for {name}'
        else:
            comp = raw
        if method == 0:
            content = comp
        elif method == 8:
            content = zlib.decompress(comp, -15)
        else:
            raise ValueError(f'method {method}')
        assert len(content) == usize and binascii.crc32(content) & 0xFFFFFFFF == crc, f'crc fail {name}'
        files[name] = content
        p += 46 + nlen + elen + clen
    return files
