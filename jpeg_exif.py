import tags

class ExifParseError(Exception):
    def init(__self__):
        pass


def carve(f, start, end):
    # return the bytes

    # here is an example that just returns the entire range of bytes:
    return f.read()


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