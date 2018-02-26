import tags
import struct

class ExifParseError(Exception):
    def __init__(self, message):
        self.message = message


def carve(f, start, end):
    data = b''
    offset = 0
    while offset <= start:
        chunk = f.read(256)
        offset += 256
        if offset >= start:
            if end - start < 256:
                data = chunk[(start % 256):((end % 256) + 1)]
            else:
                data += chunk[(start % 256):256]
                while offset <= end:
                    chunk = f.read(256)
                    offset += 256
                    if offset >= end:
                        data += chunk[0:((end % 256) + 1)]
                    else:
                        data += chunk
    return data


def find_jfif(f, max_length=None):
    offsets = []
    offset = 0
    chunk = b''
    while True:
        chunk = f.read(256)
        if chunk == b'': break
        end = ((len(chunk) - 1) % 256) + 1
        for i in range(0, end):
            first_byte = hex(chunk[i])
            if first_byte == '0xff' and i + 1 < end:
                next_byte = hex(chunk[i + 1])
                if next_byte == '0xd8':
                    offsets += [(offset, next_byte)]
                elif next_byte == '0xd9':
                    offsets += [(offset + 1, next_byte)]
            elif first_byte == '0xff' and i + 1 == end:
                seek = f.read(1)
                offset += 1
                if seek != b'':
                    next_byte = hex(seek[0])
                    if next_byte == '0xd8':
                        offsets += [(offset, next_byte)]
                    elif next_byte == '0xd9':
                        offsets += [(offset + 1, next_byte)]
            offset += 1
    results = []
    offsets_length = len(offsets)
    if max_length != None:
        for i in range(0, offsets_length):
            soi = offsets[i]
            if soi[1] == '0xd8' and i + 1 <= offsets_length:
                for j in range(i + 1, offsets_length):
                    eoi = offsets[j]
                    if eoi[1] == '0xd9' and eoi[0] - soi[0] < max_length:
                        results += [(soi[0], eoi[0])]
                    elif eoi[1] == '0xd9' and eoi[0] - soi[0] >= max_length:
                        break
    else:
        for i in range(0, offsets_length):
            soi = offsets[i]
            if soi[1] == '0xd8' and i + 1 <= offsets_length:
                for j in range(i + 1, offsets_length):
                    eoi = offsets[j]
                    if eoi[1] == '0xd9':
                        results += [(soi[0], eoi[0])]
    return results


def parse_exif(f):
    exif = {}
    if f.read(2) == b'\xff\xd8':
        while f.read(2) != b'\xff\xe1':
            if f.read(2) == b'': break
            f.seek(-2, 1)
        size = f.read(2)
        if size == b'': raise ExifParseError("Invalid Exif")
        size = struct.unpack(">H", size[0:2])[0]
        if f.read(6) != b'\x45\x78\x69\x66\x00\x00': raise ExifParseError("Invalid Exif")
        endianness = f.read(2)
        if endianness != b'MM' and endianness != b'II': raise ExifParseError("Invalid Exif")
        elif endianness == b'MM':
            if f.read(2) != b'\x00\x2a': raise ExifParseError("Invalid Exif")
            if f.read(4) == b'': raise ExifParseError("Invalid Exif")
            while True:
                entries = f.read(2)
                if entries == b'': raise ExifParseError("Invalid Exif")
                entries = struct.unpack(">H", entries[0:2])[0]
                print(entries)
                for entry in range(0, entries):
                    skip = False
                    name = struct.unpack(">H", f.read(2)[0:2])[0]
                    print(entry + 1, end="\t")
                    print(hex(name), end="\t")
                    print(name in tags.TAGS.keys(), end='\t')
                    if name in tags.TAGS.keys(): name = tags.TAGS[name]
                    else: skip = True
                    type_format = f.read(2)
                    if type_format == b'': raise ExifParseError("Invalid Exif")
                    type_format = struct.unpack(">h", type_format[0:2])[0]
                    if type_format not in range(1, 13) and not skip: raise ExifParseError("Invalid Exif")
                    components = f.read(4)
                    if components == b'': raise ExifParseError("Invalid Exif")
                    components = struct.unpack(">L", components[0:4])[0]
                    data = f.read(4)
                    if components != 0 and type_format not in (6, 8, 9, 10, 11, 12) and not skip:
                        if type_format == 1:
                            data = struct.unpack(">B", data[3:4])
                        elif type_format == 2:
                            if components > 4:
                                offset = struct.unpack(">L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(offset, 0)
                                data = bytes.decode(f.read(components)[0:components], 'UTF-16BE', 'replace')
                            else: data = bytes.decode(data[0:components], 'UTF-16BE', 'replace')
                        elif type_format == 3:
                            if components > 2: 
                                offset = struct.unpack(">L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(offset, 0)
                                data = struct.unpack(">%dH" % components, f.read(components * 2)[0:components * 2])
                                f.seek(pos, 0)
                            else: data = list(struct.unpack(">%dH" % components, data[0:components * 2]))
                        elif type_format == 4:
                            data = struct.unpack(">L", data[0:4])
                        elif type_format == 5:
                            offset = struct.unpack(">L", data[0:4])[0]
                            pos = f.tell()
                            f.seek(offset, 0)
                            (numerator, denominator) = struct.unpack(">LL", f.read(8)[0:8])
                            data = "%s/%s" % (numerator, denominator)
                            f.seek(pos, 0)
                        elif type_format == 7:
                            if components > 4:
                                offset = struct.unpack(">L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(offset, 0)
                                data = struct.unpack(">%dB" % components, f.read(components)[0:components])
                                data = "".join("%.2x" % x for x in data)
                                f.seek(pos, 0)
                            else:
                                data = struct.unpack(">%dB" % components, data[0:components]) 
                                data = "".join("%.2x" % x for x in data)
                    else: data = None
                    exif[name] = data
                    print(type_format, end='\t')
                    print(data)
                next_ifd = f.read(4)
                if next_ifd == b'': raise ExifParseError("Invalid Exif")
                elif struct.unpack(">L", next_ifd[0:4])[0] == 0x0: break
                f.seek(-4, 1)
        elif endianness == b'II':
            if f.read(2) != b'\x2a\x00': raise ExifParseError("Invalid Exif")
            offset = f.read(4).decode('UTF-16LE')
            if offset == b'': raise ExifParseError("Invalid Exif")
            offset =ord(offset)
            while True:
                entries = f.read(2).decode('UTF-16LE')
                if entries == b'': raise ExifParseError("Invalid Exif")
                entries = ord(entries)
                add = True
                for entry in range(0, entries):
                    name = f.read(2).decode('UTF-16LE')
                    if name not in tags.TAGS.keys(): raise ExifParseError("Invalid Exif")
                    name  = tags.Tags[name]
                    type_format = f.read(2).decode('UTF-16LE')
                    if type_format == b'': raise ExifParseError("Invalid Exif")
                    type_format = ord(type_format)
                    if type_format not in range(1, 8): add = False
                    components = f.read(4).decode('UTF-16LE')
                    if components == b'': raise ExifParseError("Invalid Exif")
                    components = ord(components)
                    data = b''
                    if type_format == 1:
                        data = f.read(1).decode('UTF-16LE') * components
                    elif type_format == 2:
                        data = f.read(1).decode('UTF-16LE') * components
                    elif type_format == 3:
                        data = f.read(2).decode('UTF-16LE') * components
                    elif type_format == 4:
                        data = f.read(4).decode('UTF-16LE') * components
                    elif type_format == 5:
                        for i in range(0, components):
                            numerator = f.read(4).decode('UTF-16LE')
                            if numerator == b'': raise ExifParseError("Invalid Exif")
                            numerator = ord(numerator)
                            denominator = f.read(4).decode('UTF-16LE')
                            if denominator == b'': raise ExifParseError("Invalid Exif")
                            denominator = ord(denominator)
                            data = numerator / denominator
                    elif type_format == 6: f.read(1)
                    elif type_format == 7:
                        data = f.read(1).decode('UTF-16LE')
                    elif type_format == 8: f.read(2) * components
                    elif type_format == 9: f.read(4) * components
                    elif type_format == 10: f.read(8) * components
                    elif type_format == 11: f.read(4) * components
                    elif type_format == 12: f.read(8) * components
                    if add == True: exif[name] = data
                next_ifd = f.read(4).decode('UTF-16LE')
                if next_ifd == b'': raise ExifParseError("Invalid Exif")
                elif ord(next_ifd) == 0x0: break
                f.seek(-4, 1)
    else:
        raise ExifParseError("Invalid Exif")
    f.close()
    #print(exif)



def main():
    parse_exif(open("gore-superman.jpg", 'rb'))


if __name__ == '__main__':
    main()