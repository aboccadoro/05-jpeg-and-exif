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
                data = chunk[(start % 256):((end % 256)+1)]
            else:
                data += chunk
                while offset <= end:
                    chunk = f.read(256)
                    offset += 256
                    if offset >= end:
                        data += chunk[0:((end % 256)+1)]
                    else:
                        data += chunk
    return data


def find_jfif(f, max_length=None):
    # do some stuff

    # then return a possibly-empty sequence of pairs

    # here's an example that just returns the start and end of the file without parsing
    chunk = f.read()
    last_byte = len(chunk)
    return [(0, last_byte)]


def parse_exif(f):
    # do it!

    # ...

    # Don't hardcode the answer! Return your computed dictionary.
    return {'Make':['Apple']}