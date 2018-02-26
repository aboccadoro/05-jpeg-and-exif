import tags
import struct

class ExifParseError(Exception):
    def __init__(self, message):
        self.message = message


def carve(f, start, end):
    #im stupid -> f.seek(start) f.read(end - start)
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
        exif_offset = f.tell()
        endianness = f.read(2)
        if endianness != b'MM' and endianness != b'II': raise ExifParseError("Invalid Exif")
        elif endianness == b'MM':
            if f.read(2) != b'\x00\x2a': raise ExifParseError("Invalid Exif")
            if f.read(4) == b'': raise ExifParseError("Invalid Exif")
            next_ifd = 1
            more = False
            while next_ifd != 0:
                if more == True: 
                    more = False
                    f.seek(exif_offset + next_ifd, 0)
                entries = f.read(2)
                if entries == b'': raise ExifParseError("Invalid Exif")
                entries = struct.unpack(">H", entries[0:2])[0]
                for entry in range(0, entries):
                    skip = False
                    name = struct.unpack(">H", f.read(2)[0:2])[0]
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
                            data = struct.unpack(">B", data[3:4])[0]
                            exif[name] = [data]
                        elif type_format == 2:
                            if components > 4:
                                offset = struct.unpack(">L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(exif_offset + offset, 0)
                                data = bytes.decode(f.read(components)[0:components])
                                f.seek(pos, 0)
                            else: data = bytes.decode(data[0:components])
                            data = data[:-1]
                            exif[name] = [data]
                        elif type_format == 3:
                            if components > 2: 
                                offset = struct.unpack(">L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(exif_offset + offset, 0)
                                data = list(struct.unpack(">%dH" % components, f.read(components * 2)[0:components * 2]))
                                f.seek(pos, 0)
                            else: data = list(struct.unpack(">%dH" % components, data[0:components * 2]))
                            exif[name] = data
                        elif type_format == 4:
                            data = struct.unpack(">L", data[0:4])[0]
                            exif[name] = [data]
                        elif type_format == 5:
                            offset = struct.unpack(">L", data[0:4])[0]
                            pos = f.tell()
                            f.seek(exif_offset + offset, 0)
                            (numerator, denominator) = struct.unpack(">%dL%dL" % (components, components), f.read(components * 8)[0:components * 8])
                            data = "%s/%s" % (numerator, denominator)
                            f.seek(pos, 0)
                            exif[name] = [data[0:(len(numerator) + len(denominator))]]
                        elif type_format == 7:
                            if components > 4:
                                offset = struct.unpack(">L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(exif_offset + offset, 0)
                                data = struct.unpack(">%dB" % components, f.read(components)[0:components])
                                data = "".join("%.2x" % x for x in data)
                                f.seek(pos, 0)
                            else:
                                data = struct.unpack(">%dB" % components, data[0:components])
                                data = "".join("%.2x" % x for x in data)
                            exif[name] = [data]
                    else: 
                        data = None
                        exif[name] = [data]
                next_ifd = f.read(4)
                if next_ifd == b'': raise ExifParseError("Invalid Exif")
                else: 
                    next_ifd = struct.unpack(">L", next_ifd[0:4])[0]
                    more = True
        elif endianness == b'II':
            if f.read(2) != b'\x2a\x00': raise ExifParseError("Invalid Exif")
            if f.read(4) == b'': raise ExifParseError("Invalid Exif")
            next_ifd = 1
            more = False
            while next_ifd != 0:
                if more == True: 
                    more = False
                    f.seek(exif_offset + next_ifd, 0)
                entries = f.read(2)
                if entries == b'': raise ExifParseError("Invalid Exif")
                entries = struct.unpack("<H", entries[0:2])[0]
                for entry in range(0, entries):
                    skip = False
                    name = struct.unpack("<H", f.read(2)[0:2])[0]
                    if name in tags.TAGS.keys(): name = tags.TAGS[name]
                    else: skip = True
                    type_format = f.read(2)
                    if type_format == b'': raise ExifParseError("Invalid Exif")
                    type_format = struct.unpack("<h", type_format[0:2])[0]
                    if type_format not in range(1, 13) and not skip: raise ExifParseError("Invalid Exif")
                    components = f.read(4)
                    if components == b'': raise ExifParseError("Invalid Exif")
                    components = struct.unpack("<L", components[0:4])[0]
                    data = f.read(4)
                    if components != 0 and type_format not in (6, 8, 9, 10, 11, 12) and not skip:
                        if type_format == 1:
                            data = struct.unpack("<B", data[0:1])[0]
                            exif[name] = [data]
                        elif type_format == 2:
                            if components > 4:
                                offset = struct.unpack("<L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(exif_offset + offset, 0)
                                data = bytes.decode(f.read(components)[0:components])
                                f.seek(pos, 0)
                            else: data = bytes.decode(data[0:components])
                            data = data[:-1]
                            exif[name] = [data]
                        elif type_format == 3:
                            if components > 2: 
                                offset = struct.unpack("<L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(exif_offset + offset, 0)
                                data = list(struct.unpack("<%dH" % components, f.read(components * 2)[0:components * 2]))
                                f.seek(pos, 0)
                            else: data = list(struct.unpack("<%dH" % components, data[0:components * 2]))
                            exif[name] = data
                        elif type_format == 4:
                            data = struct.unpack("<L", data[0:4])[0]
                            exif[name] = [data]
                        elif type_format == 5:
                            offset = struct.unpack("<L", data[0:4])[0]
                            pos = f.tell()
                            f.seek(exif_offset + offset, 0)
                            (numerator, denominator) = struct.unpack("<%dL%dL" % (components, components), f.read(components * 8)[0:components * 8])
                            data = "%s/%s" % (numerator, denominator)
                            f.seek(pos, 0)
                            exif[name] = [data[0:(len(numerator) + len(denominator))]]
                        elif type_format == 7:
                            if components > 4:
                                offset = struct.unpack("<L", data[0:4])[0]
                                pos = f.tell()
                                f.seek(exif_offset + offset, 0)
                                data = struct.unpack("<%dB" % components, f.read(components)[0:components])
                                data = "".join("%.2x" % x for x in data)
                                f.seek(pos, 0)
                            else:
                                data = struct.unpack("<%dB" % components, data[0:components]) 
                                data = "".join("%.2x" % x for x in data)
                            exif[name] = [data]
                    else: 
                        data = None
                        exif[name] = data
                next_ifd = f.read(4)
                if next_ifd == b'': raise ExifParseError("Invalid Exif")
                else: 
                    next_ifd = struct.unpack("<L", next_ifd[0:4])[0]
                    more = True
    else:
        raise ExifParseError("Invalid Exif")
    f.close()
    return exif