import unittest
from utils import checkNullBytes
from struct import pack


class TestNullBytesCheck(unittest.TestCase):

    def test_null_bytes_valid(self):
        """Test bitstreams that should return True (no null bytes found)."""
        valid_cases = [
            b"\x0b\x03\x41\x41",  # Should not be flagged
            b"\x41\x42\x43\x44",  # Standard ASCII 'ABCD'
            b"\x03\x41\x41",  # Odd length, no double nulls
            b"\x3a\x20\x4f\x46"
        ]

        for data in valid_cases:
            with self.subTest(data=data):
                self.assertTrue(checkNullBytes(data), f"False positive: {data} was incorrectly flagged as having null bytes.")

    def test_null_bytes_invalid(self):
        """Test bitstreams that should return False (null bytes detected)."""
        invalid_cases = [
            b"\x00\x00\x03\xc2",  # Starts with double nulls
            b"\x41\x42\x00\x00",  # Ends with double nulls
            b"\x01\x00\x00\x02",  # Contains double nulls overlapping in the middle
        ]

        for data in invalid_cases:
            with self.subTest(data=data):
                self.assertFalse(checkNullBytes(data), f"False negative: {data} contains null bytes but was not flagged.")

    def test_packed_bitstream_alignment(self):
        """Test edge cases involving packed structures."""
        packed_data = pack(">H B", 0x0341, 0x41)  # Results in b'\x03\x41\x41'
        self.assertTrue(checkNullBytes(packed_data))


if __name__ == "__main__":
    unittest.main()
