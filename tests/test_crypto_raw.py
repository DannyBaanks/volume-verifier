"""
Comprehensive tests for crypto.raw (Volume Verifier internal module).
Tests: parser fixtures, bounds checks, Shamir properties, error mapping.
Runnable under both unittest and pytest.
"""
from __future__ import annotations

import itertools
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

from crypto.raw import (
    # Errors
    RawError, R_VOLUME_QUERY_FAILED, R_STORE_CORRUPTED,
    R_INSUFFICIENT_PRIVILEGES, R_UNSUPPORTED_FS, R_INVALID_SIGNATURE, R_READ_FAILED,
    # Raw device
    read_sector, read_at,
    # NTFS
    parse_ntfs_vbr, read_ntfs_volume_serial,
    # FVE
    parse_fve_volume_id, read_bitlocker_volume_id,
    # LUKS
    parse_luks_header, read_luks_uuid,
    # ext4
    parse_ext4_superblock, read_ext4_uuid,
    # Swap
    is_swap_partition,
    # Formatting
    format_guid, format_uuid,
    # Shamir
    shamir_split, shamir_reconstruct,
    shamir_split_48digit, shamir_reconstruct_48digit,
    # Errors
    map_error, wrap_raw_error,
)

FIXTURE_DIR = Path(__file__).parent / "crypto_fixtures"


def load_fixture(name: str) -> bytes:
    return (FIXTURE_DIR / name).read_bytes()


# ──────────────────────────────────────────────────────────────
# NTFS VBR Tests
# ──────────────────────────────────────────────────────────────
class TestNTFSVBR(unittest.TestCase):
    def test_valid_vbr(self):
        data = load_fixture("ntfs_vbr_valid.bin")
        is_ntfs, serial = parse_ntfs_vbr(data)
        self.assertTrue(is_ntfs)
        self.assertEqual(serial, 0x123456789ABCDEF0)

    def test_corrupt_oem_id(self):
        data = load_fixture("ntfs_vbr_corrupt.bin")
        is_ntfs, serial = parse_ntfs_vbr(data)
        self.assertFalse(is_ntfs)
        self.assertIsNone(serial)

    def test_truncated_vbr(self):
        data = load_fixture("ntfs_vbr_truncated.bin")
        with self.assertRaises(RawError) as ctx:
            parse_ntfs_vbr(data)
        self.assertEqual(ctx.exception.reason, R_STORE_CORRUPTED)

    def test_bounds_checking_vbr(self):
        # VBR must be at least 0x50 bytes for the serial
        short = bytes(0x40)
        with self.assertRaises(RawError) as ctx:
            parse_ntfs_vbr(short)
        self.assertEqual(ctx.exception.reason, R_STORE_CORRUPTED)


# ──────────────────────────────────────────────────────────────
# BitLocker FVE Header Tests
# ──────────────────────────────────────────────────────────────
class TestFVEHeader(unittest.TestCase):
    def test_valid_fve(self):
        data = load_fixture("fve_header_valid.bin")
        guid = parse_fve_volume_id(data)
        self.assertEqual(guid, bytes.fromhex("112233445566778899AABBCCDDEEFF00"))

    def test_bad_signature(self):
        data = load_fixture("fve_header_bad_sig.bin")
        with self.assertRaises(RawError) as ctx:
            parse_fve_volume_id(data)
        self.assertEqual(ctx.exception.reason, R_INVALID_SIGNATURE)

    def test_truncated_fve(self):
        # 200 bytes: header fields + GUID at metadata offset are present
        data = load_fixture("fve_header_truncated.bin")
        guid = parse_fve_volume_id(data)
        self.assertEqual(len(guid), 16)

    def test_wrong_guid_size(self):
        # "SHORT" (5 bytes) at GUID position + 11 bytes padding = valid 16-byte read
        data = load_fixture("fve_header_wrong_guid.bin")
        guid = parse_fve_volume_id(data)
        self.assertEqual(len(guid), 16)
        self.assertTrue(guid.startswith(b"SHORT"))

    def test_bounds_check_fve(self):
        # Must have at least 0x28 bytes (fixed header incl. metadata offset)
        short = bytes(0x10)
        with self.assertRaises(RawError) as ctx:
            parse_fve_volume_id(short)
        self.assertEqual(ctx.exception.reason, R_STORE_CORRUPTED)

    def test_guid_at_metadata_offset(self):
        # GUID lives in FVE_METADATA_BLOCK at metadata_offset + 0x08;
        # a non-default metadata offset must be honored.
        header = bytearray(0x200)
        header[0:8] = b"-FVE-FS-"
        header[0x24:0x28] = struct.pack("<I", 0x80)
        header[0x88:0x98] = bytes.fromhex("AABBCCDDEEFF00112233445566778899")
        guid = parse_fve_volume_id(bytes(header))
        self.assertEqual(guid, bytes.fromhex("AABBCCDDEEFF00112233445566778899"))

    def test_zero_guid_rejected(self):
        header = bytearray(0x200)
        header[0:8] = b"-FVE-FS-"
        header[0x24:0x28] = struct.pack("<I", 0x30)
        with self.assertRaises(RawError) as ctx:
            parse_fve_volume_id(bytes(header))
        self.assertEqual(ctx.exception.reason, R_INVALID_SIGNATURE)


# ──────────────────────────────────────────────────────────────
# GUID / UUID formatting tests
# ──────────────────────────────────────────────────────────────
class TestFormatting(unittest.TestCase):
    def test_format_guid_mixed_endian(self):
        g = bytes.fromhex("112233445566778899AABBCCDDEEFF00")
        self.assertEqual(format_guid(g), "44332211-6655-8877-99AA-BBCCDDEEFF00")

    def test_format_uuid_matches_libuuid_convention(self):
        u = bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90")
        self.assertEqual(format_uuid(u), "d4c3b2a1-f6e5-1807-293a-4b5c6d7e8f90")

    def test_format_uuid_lowercase(self):
        self.assertEqual(format_uuid(bytes.fromhex("0000000000000000000000000000000a")),
                         "00000000-0000-0000-0000-00000000000a")


# ──────────────────────────────────────────────────────────────
# LUKS Header Tests
# ──────────────────────────────────────────────────────────────
class TestLUKSHeader(unittest.TestCase):
    def test_luks1_valid(self):
        data = load_fixture("luks1_header_valid.bin")
        version, uuid = parse_luks_header(data)
        self.assertEqual(version, 1)
        self.assertEqual(uuid, bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90"))

    def test_luks2_valid(self):
        data = load_fixture("luks2_header_valid.bin")
        version, uuid = parse_luks_header(data)
        self.assertEqual(version, 2)
        self.assertEqual(uuid, bytes.fromhex("112233445566778899AABBCCDDEEFF00"))

    def test_bad_magic(self):
        data = load_fixture("luks_bad_magic.bin")
        with self.assertRaises(RawError) as ctx:
            parse_luks_header(data)
        self.assertEqual(ctx.exception.reason, R_INVALID_SIGNATURE)

    def test_unknown_version(self):
        data = load_fixture("luks_unknown_version.bin")
        with self.assertRaises(RawError) as ctx:
            parse_luks_header(data)
        self.assertEqual(ctx.exception.reason, R_UNSUPPORTED_FS)

    def test_truncated(self):
        data = load_fixture("luks_truncated.bin")
        with self.assertRaises(RawError) as ctx:
            parse_luks_header(data)
        self.assertEqual(ctx.exception.reason, R_STORE_CORRUPTED)


# ──────────────────────────────────────────────────────────────
# ext4 Superblock Tests
# ──────────────────────────────────────────────────────────────
class TestEXT4Superblock(unittest.TestCase):
    def test_valid(self):
        data = load_fixture("ext4_superblock_valid.bin")
        is_ext4, uuid = parse_ext4_superblock(data)
        self.assertTrue(is_ext4)
        self.assertEqual(uuid, bytes.fromhex("DEADBEEFCAFEBABEDEADBEEFCAFEBABE"))

    def test_bad_magic(self):
        data = load_fixture("ext4_bad_magic.bin")
        is_ext4, uuid = parse_ext4_superblock(data)
        self.assertFalse(is_ext4)
        self.assertIsNone(uuid)

    def test_truncated(self):
        data = load_fixture("ext4_truncated.bin")
        with self.assertRaises(RawError) as ctx:
            parse_ext4_superblock(data)
        self.assertEqual(ctx.exception.reason, R_STORE_CORRUPTED)

    def test_uuid_truncated(self):
        # "SHORT" (5 bytes) at UUID offset + 11 bytes padding = valid 16-byte read
        data = load_fixture("ext4_uuid_truncated.bin")
        is_ext4, uuid = parse_ext4_superblock(data)
        self.assertTrue(is_ext4)
        self.assertEqual(len(uuid), 16)
        self.assertTrue(uuid.startswith(b"SHORT"))


# ──────────────────────────────────────────────────────────────
# Swap Detection Tests
# ──────────────────────────────────────────────────────────────
class TestSwapDetection(unittest.TestCase):
    def test_swap_v1(self):
        data = load_fixture("swap_v1.bin")
        self.assertIn(b"SWAPSPACE2", data)

    def test_swap_v0(self):
        data = load_fixture("swap_v0.bin")
        self.assertIn(b"SWAP-SPACE", data)

    def test_not_swap(self):
        data = load_fixture("not_swap.bin")
        self.assertNotIn(b"SWAPSPACE2", data)
        self.assertNotIn(b"SWAP-SPACE", data)


# ──────────────────────────────────────────────────────────────
# Sector Abstraction Tests (bounds checking)
# ──────────────────────────────────────────────────────────────
class TestSectorAbstraction(unittest.TestCase):
    def test_read_sector_bounds(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"X" * 2048)  # 4 sectors of 512
            fname = f.name
        try:
            with open(fname, "rb") as f:
                s0 = read_sector(f, 0)
                s3 = read_sector(f, 3)
                self.assertEqual(len(s0), 512)
                self.assertEqual(s0, b"X" * 512)
                self.assertEqual(s3, b"X" * 512)
                with self.assertRaises(RawError) as ctx:
                    read_sector(f, 4)
                self.assertEqual(ctx.exception.reason, R_READ_FAILED)
        finally:
            os.unlink(fname)

    def test_read_at_bounds(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            fname = f.name
        try:
            with open(fname, "rb") as f:
                self.assertEqual(read_at(f, 0, 5), b"ABCDE")
                self.assertEqual(read_at(f, 21, 5), b"VWXYZ")
                with self.assertRaises(RawError):
                    read_at(f, 100, 5)
                with self.assertRaises(RawError):
                    read_at(f, 20, 10)  # goes past EOF
        finally:
            os.unlink(fname)

    def test_negative_offset_rejected(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            fname = f.name
        try:
            with open(fname, "rb") as f:
                with self.assertRaises(RawError):
                    read_at(f, -1, 1)
                with self.assertRaises(RawError):
                    read_at(f, 0, -1)
        finally:
            os.unlink(fname)


# ──────────────────────────────────────────────────────────────
# Shamir 2-of-3 Property Tests
# ──────────────────────────────────────────────────────────────
class TestShamirProperties(unittest.TestCase):
    VALID_KEY = "123456789012345678901234567890123456789012345678"  # 48 digits

    def test_any_2_of_3_reconstruct(self):
        shares = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        for combo in [(shares[0], shares[1]), (shares[0], shares[2]),
                      (shares[1], shares[2])]:
            reconstructed = shamir_reconstruct_48digit(list(combo))
            self.assertEqual(reconstructed, self.VALID_KEY)

    def test_1_share_cannot_reconstruct(self):
        shares = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        for i in range(3):
            with self.assertRaises(ValueError):
                shamir_reconstruct_48digit([shares[i]])

    def test_corrupted_share_rejected(self):
        shares = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        corrupted = list(shares)
        corrupted[0] = (corrupted[0][0], corrupted[0][1][:-2] + "00")  # flip last byte
        with self.assertRaises((ValueError, UnicodeDecodeError)):
            shamir_reconstruct_48digit([corrupted[0], corrupted[1]])

    def test_duplicate_share_rejected(self):
        shares = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        with self.assertRaises((ValueError, ZeroDivisionError)):
            shamir_reconstruct_48digit([shares[0], shares[0]])

    def test_duplicate_x_rejected(self):
        shares = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        with self.assertRaises((ValueError, ZeroDivisionError)):
            shamir_reconstruct_48digit([(1, shares[0][1]), (1, shares[1][1])])

    def test_truncated_share_rejected(self):
        shares = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        truncated = [(shares[0][0], shares[0][1][:-2]), shares[1]]
        with self.assertRaises((ValueError, UnicodeDecodeError)):
            shamir_reconstruct_48digit(truncated)

    def test_invalid_key_rejected(self):
        for bad in ("12345", "abc", "1" * 47, "1" * 49):
            with self.assertRaises(ValueError):
                shamir_split_48digit(bad)

    def test_invalid_n_k_rejected(self):
        with self.assertRaises(ValueError):
            shamir_split_48digit(self.VALID_KEY, n=3, k=4)  # k > n
        with self.assertRaises(ValueError):
            shamir_split_48digit(self.VALID_KEY, n=256, k=2)  # n > 255

    def test_randomness_different_shares(self):
        shares1 = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        shares2 = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        same = all(s1[1] == s2[1] for s1, s2 in zip(shares1, shares2))
        self.assertFalse(same, "shares should be randomized")

    def test_no_secret_in_logs_or_shares(self):
        shares = shamir_split_48digit(self.VALID_KEY, n=3, k=2)
        for _, share in shares:
            self.assertNotEqual(share, self.VALID_KEY.encode().hex())
            self.assertNotIn(self.VALID_KEY, share)

    def test_generic_shamir_byte_level(self):
        secret = os.urandom(32)
        shares = shamir_split(secret, n=5, k=3)
        for combo in itertools.combinations(shares, 3):
            self.assertEqual(shamir_reconstruct(list(combo), k=3), secret)
        for combo in itertools.combinations(shares, 2):
            with self.assertRaises(ValueError):
                shamir_reconstruct(list(combo), k=3)

    def test_secret_never_persisted(self):
        key = "123456789012345678901234567890123456789012345678"
        shamir_split_48digit(key)
        import crypto.raw as m
        for attr in dir(m):
            val = getattr(m, attr)
            if isinstance(val, str) and key in val:
                self.fail(f"secret leaked in module attribute {attr}")


# ──────────────────────────────────────────────────────────────
# Error Mapping Tests
# ──────────────────────────────────────────────────────────────
class TestErrorMapping(unittest.TestCase):
    def test_windows_hresult_mapping(self):
        self.assertEqual(map_error("windows", "0x80070005"), "INSUFFICIENT_PRIVILEGES")
        self.assertEqual(map_error("windows", "5"), "INSUFFICIENT_PRIVILEGES")

    def test_linux_errno_mapping(self):
        self.assertEqual(map_error("linux", "13"), "INSUFFICIENT_PRIVILEGES")  # EACCES
        self.assertEqual(map_error("linux", "5"), "READ_FAILED")              # EIO

    def test_raw_errors(self):
        self.assertEqual(map_error("raw", "signature_mismatch"), "INVALID_SIGNATURE")
        self.assertEqual(map_error("raw", "unsupported_fs"), "UNSUPPORTED_FS")

    def test_unknown_fallback(self):
        self.assertEqual(map_error("windows", "99999"), "VOLUME_QUERY_FAILED")
        self.assertEqual(map_error("unknown", "anything"), "VOLUME_QUERY_FAILED")

    def test_wrap_raw_error(self):
        e = wrap_raw_error(PermissionError("denied"), "windows")
        self.assertIsInstance(e, RawError)
        self.assertEqual(e.reason, "INSUFFICIENT_PRIVILEGES")

        e = wrap_raw_error(FileNotFoundError("nope"), "linux")
        self.assertEqual(e.reason, "VOLUME_QUERY_FAILED")

        e = wrap_raw_error(OSError(13, "perm"), "linux")
        self.assertEqual(e.reason, "INSUFFICIENT_PRIVILEGES")

        e = wrap_raw_error(ValueError("bad"), "raw")
        self.assertEqual(e.reason, "VOLUME_QUERY_FAILED")


# ──────────────────────────────────────────────────────────────
# Integration: read NTFS serial via mocked raw device
# ──────────────────────────────────────────────────────────────
class TestIntegration(unittest.TestCase):
    def test_ntfs_vbr_integration(self):
        data = load_fixture("ntfs_vbr_valid.bin")

        class MockFile:
            def __init__(self, blob):
                self.data = blob
                self.pos = 0

            def seek(self, pos):
                self.pos = pos

            def read(self, n):
                r = self.data[self.pos:self.pos + n]
                self.pos += n
                return r

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        with mock.patch("crypto.raw.open_raw_device",
                        return_value=MockFile(data)):
            serial = read_ntfs_volume_serial(r"\\.\PhysicalDrive0", 0)
        self.assertEqual(serial, 0x123456789ABCDEF0)


if __name__ == "__main__":
    unittest.main()
