import tags

class ExifParseError(Exception):
    def init(__self__):
        pass


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
    # do it!

    # ...

    # Don't hardcode the answer! Return your computed dictionary.
    return {'Make':['Apple']}

def main():
    find_jfif(open("Designs.doc", 'rb'))

if __name__ == '__main__':
    main()