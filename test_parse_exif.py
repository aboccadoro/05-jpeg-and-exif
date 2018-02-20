import unittest

import jpeg_exif


class TestParseExif(unittest.TestCase):
    def test_fullsizerender(self):
        with open('FullSizeRender.jpg', 'rb') as f:
            self.assertEqual({'Make': ['Apple'],
                              'Model': ['iPhone 5'],
                              'XResolution': ['72/1'],
                              'YResolution': ['72/1'],
                              'ResolutionUnit': [2],
                              'Software': ['8.1.2'],
                              'DateTime': ['2015:01:10 16:18:44'],
                              'ExifIFDPointer': [180],
                              'GPSInfoIFDPointer': [978]},
                             jpeg_exif.parse_exif(f))

    def test_goresuperman(self):
        with open('gore-superman.jpg', 'rb') as f:
            self.assertEqual({'Orientation': [1],
                              'XResolution': ['72/1', '72/1'],
                              'YResolution': ['72/1', '72/1'],
                              'ResolutionUnit': [2, 2],
                              'Software': ['Adobe Photoshop Elements 2.0'],
                              'DateTime': ['2006:06:06 21:02:57'],
                              'ExifIFDPointer': [164],
                              'Compression': [6],
                              'JPEGInterchangeFormat': [302],
                              'JPEGInterchangeFormatLength': [4814]},
                             jpeg_exif.parse_exif(f))


if __name__ == '__main__':
    unittest.main()