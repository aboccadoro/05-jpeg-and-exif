import unittest


import jpeg_exif


class TestParseExifLittleEndian(unittest.TestCase):
    def test_leaves(self):
        with open('leaves.jpg', 'rb') as f:
            self.assertEqual({'Make': ['EASTMAN KODAK COMPANY'],
                              'Model': ['KODAK EASYSHARE C195 Digital Camera'],
                              'Orientation': [1, 1],
                              'XResolution': ['480/1', '72/1'],
                              'YResolution': ['480/1', '72/1'],
                              'ResolutionUnit': [2, 2],
                              'DateTime': ['2015:11:09 11:59:11'],
                              'YCbCrPositioning': [1],
                              'ExifIFDPointer': [14248],
                              'Compression': [6],
                              'JPEGInterchangeFormat': [35652],
                              'JPEGInterchangeFormatLength': [3459]},
                             jpeg_exif.parse_exif(f))


if __name__ == '__main__':
    unittest.main()