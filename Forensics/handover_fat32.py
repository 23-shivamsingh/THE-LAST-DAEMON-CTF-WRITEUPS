"""My own minimal read-only FAT32 reader for evidence.img (1 sector/cluster)."""
import struct

class Fat32:
    def __init__(self, path, part_sector=2048):
        self.data = open(path, 'rb').read()
        off = part_sector * 512
        bpb = self.data[off:off+512]
        self.bps = struct.unpack_from('<H', bpb, 11)[0]
        self.spc = bpb[13]
        reserved = struct.unpack_from('<H', bpb, 14)[0]
        nfats = bpb[16]
        fatsz = struct.unpack_from('<I', bpb, 36)[0]
        self.root = struct.unpack_from('<I', bpb, 44)[0]
        self.fat_off = off + reserved * self.bps
        self.data_off = self.fat_off + nfats * fatsz * self.bps

    def _clus_off(self, c):
        return self.data_off + (c - 2) * self.spc * self.bps

    def _fat(self, c):
        return struct.unpack_from('<I', self.data, self.fat_off + c * 4)[0] & 0x0FFFFFFF

    def chain(self, c):
        out = []
        while 2 <= c < 0x0FFFFFF8:
            out.append(c)
            c = self._fat(c)
        return out

    def read_chain(self, c):
        return b''.join(self.data[self._clus_off(x):self._clus_off(x)+self.spc*self.bps] for x in self.chain(c))

    def dir_entries(self, clus):
        """yields dicts with lfn name, attr, cluster, size, deleted; parses LFN records."""
        raw = self.read_chain(clus)
        lfn_parts = []
        for i in range(0, len(raw), 32):
            e = raw[i:i+32]
            if e[0] == 0x00:
                break
            attr = e[11]
            if attr == 0x0F:
                seq = e[0] & 0x1F
                name = e[1:11] + e[14:26] + e[28:32]
                lfn_parts.append((seq, name.decode('utf-16-le', 'replace').rstrip('\x00\uffff')))
                continue
            deleted = e[0] == 0xE5
            short = ('_' if deleted else '') + e[1:11].decode('ascii', 'replace')
            lfn_parts.sort()
            long_name = ''.join(p for _, p in lfn_parts) if lfn_parts else None
            lfn_parts = []
            if short.lstrip('_.').strip() in ('', '.', '..') or e[0:1] == b'.':
                continue
            yield {
                'name': long_name or short.strip(),
                'attr': attr,
                'cluster': struct.unpack_from('<H', e, 26)[0] | (struct.unpack_from('<H', e, 20)[0] << 16),
                'size': struct.unpack_from('<I', e, 28)[0],
                'deleted': deleted,
                'raw': e,
            }

    def find(self, path):
        clus = self.root
        parts = [p for p in path.strip('/').split('/') if p]
        entry = None
        for part in parts:
            entry = next((x for x in self.dir_entries(clus) if x['name'].lower() == part.lower()), None)
            if entry is None:
                raise FileNotFoundError(part)
            clus = entry['cluster']
        return entry

    def read_file(self, path):
        e = self.find(path)
        return self.read_chain(e['cluster'])[:e['size']]
