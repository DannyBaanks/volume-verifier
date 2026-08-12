"""
Volume Verifier Crypto Raw — Sector-level parsing & threshold crypto.
Pure stdlib. Zero deps. Internal capability for Volume Verifier.
"""
from __future__ import annotations

import os
import struct
import hashlib
import hmac
import math
from typing import BinaryIO, Tuple, List, Optional, Dict, Any

# ──────────────────────────────────────────────────────────────
# Error codes (abstract, platform-agnostic)
# ──────────────────────────────────────────────────────────────
class RawError(Exception):
    """Base error with abstract reason code."""
    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")

# Abstract reason codes (match Volume Verifier)
R_VOLUME_QUERY_FAILED   = "VOLUME_QUERY_FAILED"
R_STORE_CORRUPTED       = "STORE_CORRUPTED"
R_INSUFFICIENT_PRIVILEGES = "INSUFFICIENT_PRIVILEGES"
R_UNSUPPORTED_FS        = "UNSUPPORTED_FS"
R_INVALID_SIGNATURE     = "INVALID_SIGNATURE"
R_READ_FAILED           = "READ_FAILED"
R_INVALID_OFFSET        = "INVALID_OFFSET"

# ──────────────────────────────────────────────────────────────
# Raw device access (platform-agnostic file-like)
# ──────────────────────────────────────────────────────────────
def open_raw_device(device_path: str, readonly: bool = True) -> BinaryIO:
    """
    Open a raw block device for binary reading.
    Windows: r"\\.\PhysicalDrive0" or r"\\.\C:"
    Linux:   "/dev/sda" or "/dev/nvme0n1"
    """
    mode = "rb" if readonly else "r+b"
    try:
        return open(device_path, mode, buffering=0)
    except PermissionError:
        raise RawError(R_INSUFFICIENT_PRIVILEGES, f"cannot open {device_path}")
    except FileNotFoundError:
        raise RawError(R_VOLUME_QUERY_FAILED, f"device not found: {device_path}")
    except OSError as e:
        raise RawError(R_READ_FAILED, f"{e}")

def read_sector(f: BinaryIO, sector: int, sector_size: int = 512) -> bytes:
    """Read one logical sector."""
    try:
        f.seek(sector * sector_size)
        data = f.read(sector_size)
        if len(data) != sector_size:
            raise RawError(R_READ_FAILED, f"short read at sector {sector}")
        return data
    except OSError as e:
        raise RawError(R_READ_FAILED, f"sector {sector}: {e}")

def read_at(f: BinaryIO, offset: int, length: int) -> bytes:
    """Read arbitrary byte range."""
    try:
        f.seek(offset)
        data = f.read(length)
        if len(data) != length:
            raise RawError(R_READ_FAILED, f"short read at offset {offset} (got {len(data)}/{length})")
        return data
    except OSError as e:
        raise RawError(R_READ_FAILED, f"offset {offset}: {e}")

# ──────────────────────────────────────────────────────────────
# NTFS VBR parsing (Volume Serial Number)
# ──────────────────────────────────────────────────────────────
# NTFS VBR layout (sector 0 of partition):
#   0x00-0x02: JMP instruction
#   0x03-0x0A: OEM ID "NTFS    "
#   0x0B-0x14: BIOS Parameter Block (BPB)
#   0x15-0x23: Extended BPB
#   0x24-0x27: Volume Serial Number (4 bytes LE) — LITTLE ENDIAN DWORD
#   Actually: Volume Serial is at offset 0x48 (72) in standard NTFS VBR
#   8 bytes: 64-bit volume serial (little endian)

NTFS_VBR_SIGNATURE = b"NTFS    "
NTFS_VBR_OEM_OFFSET = 3
NTFS_VOLUME_SERIAL_OFFSET = 0x48  # 72 bytes from VBR start
NTFS_VOLUME_SERIAL_SIZE = 8       # 64-bit

def parse_ntfs_vbr(sector_data: bytes) -> Tuple[bool, Optional[int]]:
    """
    Parse NTFS VBR sector (512 bytes).
    Returns (is_ntfs, volume_serial) where volume_serial is 64-bit int or None.
    Raises RawError(R_STORE_CORRUPTED) if sector too small for claimed fields.
    """
    if len(sector_data) < 512:
        raise RawError(R_STORE_CORRUPTED, "VBR sector smaller than 512 bytes")
    if sector_data[NTFS_VBR_OEM_OFFSET:NTFS_VBR_OEM_OFFSET+8] != NTFS_VBR_SIGNATURE:
        return False, None
    if len(sector_data) < NTFS_VOLUME_SERIAL_OFFSET + NTFS_VOLUME_SERIAL_SIZE:
        raise RawError(R_STORE_CORRUPTED, "VBR too small for volume serial")
    serial_bytes = sector_data[NTFS_VOLUME_SERIAL_OFFSET:NTFS_VOLUME_SERIAL_OFFSET+8]
    volume_serial = struct.unpack("<Q", serial_bytes)[0]  # little-endian 64-bit
    return True, volume_serial

def read_ntfs_volume_serial(device_path: str, partition_offset_sectors: int = 0) -> int:
    """
    Read NTFS Volume Serial from raw device.
    partition_offset_sectors: sector offset from device start to partition start.
    """
    with open_raw_device(device_path) as f:
        sector = read_sector(f, partition_offset_sectors)
        is_ntfs, serial = parse_ntfs_vbr(sector)
        if not is_ntfs:
            raise RawError(R_UNSUPPORTED_FS, "not an NTFS volume")
        if serial is None:
            raise RawError(R_STORE_CORRUPTED, "volume serial not found in VBR")
        return serial

# ──────────────────────────────────────────────────────────────
# BitLocker FVE header parsing (Volume ID / GUID)
# ──────────────────────────────────────────────────────────────
# BitLocker volume layout (libbde-documented; on-disk, in the clear):
#   FVE_VOLUME_HEADER (48 bytes at the partition start):
#     0x00  signature[8]   "-FVE-FS-"
#     0x08  volume_header_size (LE32)        = 0x30
#     0x0C  version (LE16)
#     0x0E  current_state (LE16)
#     0x10  size_of_metadata_area (LE32)
#     0x14  flags (LE32)
#     0x18  volume_size (LE64)
#     0x20  encryption_type (LE32)
#     0x24  metadata_offset (LE32)           <- start of FVE_METADATA_BLOCK
#     0x28  metadata_length (LE32)
#     0x2C  sector_size (LE32)
#     0x30  number_of_sectors (LE32)
#   FVE_METADATA_BLOCK (at metadata_offset):
#     0x00  signature[4]   "FVE\0"
#     0x04  size (LE32)
#     0x08  volume_identifier[16]            <- the GUID manage-bde prints
#             as "Volume ID:" (the canonical BitLocker volume identity)
# The volume identifier GUID is NOT in the fixed header; it lives in the
# metadata block. manage-bde "Volume ID:" reads this same GUID, which makes
# it a genuine cross-channel corroboration target.

FVE_SIGNATURE = b"-FVE-FS-"
FVE_METADATA_OFFSET_FIELD = 0x24  # LE32 in the fixed volume header
FVE_METADATA_MIN = 0x30           # headers with offset 0 default to 0x30
FVE_METADATA_GUID_OFFSET = 0x08   # within FVE_METADATA_BLOCK
FVE_GUID_SIZE = 16                # 128-bit GUID


def format_guid(guid_bytes: bytes) -> str:
    """Format 16 raw GUID bytes as canonical 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'.
    GUID storage: first three fields little-endian, last two big-endian (MS-DTYP).
    """
    d1 = struct.unpack("<I", guid_bytes[0:4])[0]
    d2 = struct.unpack("<H", guid_bytes[4:6])[0]
    d3 = struct.unpack("<H", guid_bytes[6:8])[0]
    d4 = guid_bytes[8:10].hex().upper()
    d5 = guid_bytes[10:16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"


def find_fve_header(
    device_path: str,
    partition_offset_sectors: int = 0,
    max_search_sectors: int = 64,
) -> Tuple[int, bytes]:
    """
    Scan the first N sectors (from partition start) for the FVE signature.
    Returns (absolute_sector_index, sector_data) where the signature was found.
    """
    with open_raw_device(device_path) as f:
        start = partition_offset_sectors
        for sector in range(start, start + max_search_sectors):
            data = read_sector(f, sector)
            if FVE_SIGNATURE in data:
                idx = data.index(FVE_SIGNATURE)
                aligned = data[idx:]
                if len(aligned) >= 512:
                    return sector, aligned[:512]
                next_sector = read_sector(f, sector + 1)
                return sector, (aligned + next_sector)[:512]
    raise RawError(R_VOLUME_QUERY_FAILED, "FVE header not found")

def parse_fve_volume_id(fve_header: bytes) -> bytes:
    """
    Extract the 16-byte Volume ID (GUID) from a BitLocker FVE header.
    The GUID lives in the FVE_METADATA_BLOCK at metadata_offset + 0x08.
    Raises RawError(R_STORE_CORRUPTED) if the header is truncated.
    Raises RawError(R_INVALID_SIGNATURE) if the signature or GUID is invalid.
    """
    if len(fve_header) < FVE_METADATA_OFFSET_FIELD + 4:
        raise RawError(R_STORE_CORRUPTED, "FVE header too small for metadata offset")
    if fve_header[0:8] != FVE_SIGNATURE:
        raise RawError(R_INVALID_SIGNATURE, "not a valid FVE header")
    metadata_offset = struct.unpack(
        "<I", fve_header[FVE_METADATA_OFFSET_FIELD:FVE_METADATA_OFFSET_FIELD + 4]
    )[0]
    if metadata_offset < FVE_METADATA_MIN:
        metadata_offset = FVE_METADATA_MIN
    guid_pos = metadata_offset + FVE_METADATA_GUID_OFFSET
    if len(fve_header) < guid_pos + FVE_GUID_SIZE:
        raise RawError(R_STORE_CORRUPTED, "FVE header too small for volume ID")
    guid = fve_header[guid_pos:guid_pos + FVE_GUID_SIZE]
    if guid == b"\x00" * FVE_GUID_SIZE:
        raise RawError(R_INVALID_SIGNATURE, "FVE volume ID is all zeros")
    return guid

def read_bitlocker_volume_id(device_path: str, partition_offset_sectors: int = 0) -> str:
    """
    Read the BitLocker Volume ID (GUID) from a raw device at the partition start.
    Returns the canonical GUID string manage-bde prints as 'Volume ID:'.
    """
    sector, header = find_fve_header(device_path, partition_offset_sectors)
    guid_bytes = parse_fve_volume_id(header)
    return format_guid(guid_bytes)

# ──────────────────────────────────────────────────────────────
# LUKS header parsing (UUID)
# ──────────────────────────────────────────────────────────────
# LUKS1 header (version 1):
#   Offset 0x00:  Magic "LUKS\xba\xbe"
#   Offset 0x06:  Version (2 bytes, big-endian) = 0x0001
#   Offset 0x24:  UUID (16 bytes, binary)
#   Offset 0x100: Key slot area starts
# LUKS2 header (version 2):
#   Offset 0x00:  Magic "LUKS\xba\xbe"
#   Offset 0x06:  Version = 0x0002
#   Offset 0x08:  Header size (8 bytes LE)
#   Offset 0x44:  UUID (16 bytes, binary) — actually at offset 0x44 in LUKS2
#   (LUKS2 primary header is 4KB, UUID at offset 0x44)

LUKS_MAGIC = b"LUKS\xba\xbe"
LUKS1_UUID_OFFSET = 0x24
LUKS2_UUID_OFFSET = 0x44
LUKS_UUID_SIZE = 16

def parse_luks_header(header: bytes) -> Tuple[int, bytes]:
    """
    Parse LUKS header, return (version, uuid_bytes).
    version: 1 or 2
    """
    if len(header) < 0x100:
        raise RawError(R_STORE_CORRUPTED, "LUKS header too small")
    if header[0:6] != LUKS_MAGIC:
        raise RawError(R_INVALID_SIGNATURE, "not a LUKS device")
    version = struct.unpack(">H", header[6:8])[0]
    if version == 1:
        uuid_off = LUKS1_UUID_OFFSET
    elif version == 2:
        uuid_off = LUKS2_UUID_OFFSET
    else:
        raise RawError(R_UNSUPPORTED_FS, f"unknown LUKS version {version}")
    if len(header) < uuid_off + LUKS_UUID_SIZE:
        raise RawError(R_STORE_CORRUPTED, "LUKS header truncated")
    return version, header[uuid_off:uuid_off + LUKS_UUID_SIZE]

def format_uuid(uuid_bytes: bytes) -> str:
    """Format 16 raw UUID bytes as canonical 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'.
    UUID binary storage is mixed-endian (first three fields little-endian, last
    two big-endian) — the same convention libuuid's uuid_unparse uses, so the
    string matches cryptsetup luksUUID / lsblk UUID output verbatim.
    """
    d1 = struct.unpack("<I", uuid_bytes[0:4])[0]
    d2 = struct.unpack("<H", uuid_bytes[4:6])[0]
    d3 = struct.unpack("<H", uuid_bytes[6:8])[0]
    d4 = uuid_bytes[8:10].hex()
    d5 = uuid_bytes[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"

def read_luks_uuid(device_path: str) -> str:
    """
    Read LUKS UUID from raw device.
    Returns canonical UUID string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    """
    with open_raw_device(device_path) as f:
        # LUKS header is at start of device/partition
        header = read_at(f, 0, 4096)  # read 4KB to cover LUKS2
    version, uuid_bytes = parse_luks_header(header)
    return format_uuid(uuid_bytes)

# ──────────────────────────────────────────────────────────────
# ext4 superblock UUID (filesystem UUID)
# ──────────────────────────────────────────────────────────────
# ext4 superblock at offset 1024 bytes from partition start (block group 0).
# Offset 0x38 (56) from superblock start: 16-byte UUID (little-endian byte order in disk)
# Superblock magic: 0xEF53 at offset 0x38 (0x38 is UUID, magic is at 0x38? No.
#   Offset 0x00: inode count
#   ...
#   Offset 0x38: UUID (16 bytes)
#   Offset 0x48: volume name (16 bytes)
#   Offset 0x58: last mounted path (64 bytes)
#   Offset 0x98: algorithm bitmap
#   Offset 0x38 (56) is indeed UUID in ext4.
# Wait, ext4 superblock structure:
#   Offset 0x00-0x37: various fields
#   Offset 0x38 (56): uuid[16]
#   Offset 0x48: volume_name[16]
#   Magic 0xEF53 is at offset 0x38 in the *superblock*? No, magic is at offset 0x38 in older ext2.
#   In ext4: magic is at offset 0x38 from superblock start? Let me check.
#   Actually: struct ext4_super_block:
#     __le32 s_inodes_count;                    /* 0x00 */
#     __le32 s_blocks_count_lo;                 /* 0x04 */
#     __le32 s_r_blocks_count_lo;               /* 0x08 */
#     __le32 s_free_blocks_count_lo;            /* 0x0C */
#     __le32 s_free_inodes_count;               /* 0x10 */
#     __le32 s_first_data_block;                /* 0x14 */
#     __le32 s_log_block_size;                  /* 0x18 */
#     __le32 s_log_cluster_size;                /* 0x1C */
#     __le32 s_blocks_per_group;                /* 0x20 */
#     __le32 s_clusters_per_group;              /* 0x24 */
#     __le32 s_inodes_per_group;                /* 0x28 */
#     __le32 s_mtime;                           /* 0x2C */
#     __le32 s_wtime;                           /* 0x30 */
#     __le16 s_mnt_count;                       /* 0x34 */
#     __le16 s_max_mnt_count;                   /* 0x36 */
#     __le16 s_magic;                           /* 0x38 */  <-- 0xEF53
#     __le16 s_state;                           /* 0x3A */
#     __le16 s_errors;                          /* 0x3C */
#     __le16 s_minor_rev_level;                 /* 0x3E */
#     ...
#     __u8 s_uuid[16];                          /* 0x58 */  <-- UUID at 0x58!
#   So UUID is at offset 0x58 (88) from superblock start.
#   Superblock starts at 1024 bytes from partition start (block 1, assuming 1KB blocks? No.
#   Block 0 is boot sector (512 or 4096). Superblock is at block 1 (offset = block_size).
#   Standard: superblock at 1024 bytes (1KB) from partition start for 1KB block size.
#   For 4KB block size: superblock at 4096 bytes.
#   But ext4 always places superblock at offset 1024 (for compatibility).

EXT4_SUPERBLOCK_OFFSET = 1024          # bytes from partition start
EXT4_UUID_OFFSET_IN_SB = 0x58          # 88 bytes from superblock start
EXT4_UUID_SIZE = 16
EXT4_MAGIC = 0xEF53
EXT4_MAGIC_OFFSET_IN_SB = 0x38

def parse_ext4_superblock(superblock: bytes) -> Tuple[bool, Optional[bytes]]:
    """
    Parse ext4 superblock, return (is_ext4, uuid_bytes).
    Raises RawError(R_STORE_CORRUPTED) if superblock too small for magic/UUID.
    """
    if len(superblock) < EXT4_UUID_OFFSET_IN_SB + EXT4_UUID_SIZE:
        raise RawError(R_STORE_CORRUPTED, "superblock too small for UUID")
    if len(superblock) < EXT4_MAGIC_OFFSET_IN_SB + 2:
        raise RawError(R_STORE_CORRUPTED, "superblock too small for magic")
    magic = struct.unpack("<H", superblock[EXT4_MAGIC_OFFSET_IN_SB:EXT4_MAGIC_OFFSET_IN_SB+2])[0]
    if magic != EXT4_MAGIC:
        return False, None
    uuid_bytes = superblock[EXT4_UUID_OFFSET_IN_SB:EXT4_UUID_OFFSET_IN_SB + EXT4_UUID_SIZE]
    return True, uuid_bytes

def read_ext4_uuid(device_path: str, partition_offset: int = 0) -> str:
    """
    Read ext4 filesystem UUID from raw device.
    partition_offset: byte offset from device start to partition start.
    Returns canonical UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    """
    with open_raw_device(device_path) as f:
        sb_offset = partition_offset + EXT4_SUPERBLOCK_OFFSET
        superblock = read_at(f, sb_offset, 1024)  # read 1KB superblock
    is_ext4, uuid_bytes = parse_ext4_superblock(superblock)
    if not is_ext4:
        raise RawError(R_UNSUPPORTED_FS, "not an ext4 filesystem")
    return format_uuid(uuid_bytes)

# ──────────────────────────────────────────────────────────────
# Swap detection (ephemeral volume filter)
# ──────────────────────────────────────────────────────────────
# Swap signature in first 1024 bytes:
#   Linux swap (v1): "SWAPSPACE2" or "SWAP-SPACE" at offset 0x38? Actually:
#   Linux swap header (swapspace):
#     Offset 0x38: "SWAPSPACE2" (10 bytes) or "SWAP-SPACE" (old)
#     Offset 0x40: version
#     Offset 0x100: UUID (16 bytes)
#   But simpler: check for "SWAP" signature in first 1KB.
#   mkswap writes "SWAPSPACE2" at offset 0x38 (56) of the swap area.

SWAP_SIGNATURES = [b"SWAPSPACE2", b"SWAP-SPACE", b"SWAPSPACE"]

def is_swap_partition(device_path: str, partition_offset: int = 0) -> bool:
    """Detect if partition is swap by checking first 1KB for swap signatures."""
    try:
        with open_raw_device(device_path) as f:
            data = read_at(f, partition_offset, 1024)
        for sig in SWAP_SIGNATURES:
            if sig in data:
                return True
    except RawError:
        pass
    return False

# ──────────────────────────────────────────────────────────────
# Shamir's Secret Sharing (2-of-3) for 48-digit recovery key
# ──────────────────────────────────────────────────────────────
# Implementation using finite field GF(2^8) for byte-wise sharing.
# Key: 48 decimal digits = 160 bits ≈ 20 bytes. We'll use 32 bytes (256 bits)
# for simplicity: split 32-byte secret into 3 shares, threshold 2.
# Uses Lagrange interpolation in GF(256) (AES field).

GF256_IRREDUCIBLE = 0x11b  # x^8 + x^4 + x^3 + x + 1 (AES polynomial)

def _gf256_mul(a: int, b: int) -> int:
    """Multiply in GF(256)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= GF256_IRREDUCIBLE
        b >>= 1
    return result & 0xFF

def _gf256_inv(x: int) -> int:
    """Multiplicative inverse in GF(256) using extended Euclid."""
    if x == 0:
        raise ZeroDivisionError
    # Extended Euclidean algorithm for GF(256)
    a, b = x, GF256_IRREDUCIBLE
    u, v = 1, 0
    while b:
        # a = q*b + r
        # Compute q = a // b (polynomial division)
        # Instead, use log/antilog tables for speed — but pure math:
        # Simple method: brute force (256 elements max)
        for i in range(1, 256):
            if _gf256_mul(x, i) == 1:
                return i
        raise ValueError("no inverse")
    return u & 0xFF

def _gf256_div(a: int, b: int) -> int:
    """Divide in GF(256): a / b = a * b^-1."""
    return _gf256_mul(a, _gf256_inv(b))

def shamir_split(secret: bytes, n: int = 3, k: int = 2) -> List[Tuple[int, bytes]]:
    """
    Split secret into n shares, threshold k.
    Returns list of (x, share_bytes) where share_bytes = len(secret).
    Uses GF(256) per-byte independent polynomials.
    """
    if len(secret) == 0:
        raise ValueError("empty secret")
    if k > n:
        raise ValueError("threshold > shares")
    if n > 255:
        raise ValueError("max 255 shares in GF(256)")
    if k < 2:
        raise ValueError("threshold must be at least 2")

    # Generate random polynomial coefficients for each byte
    # For each byte position: coeff[0] = secret_byte, coeff[1..k-1] = random
    coeffs = []
    for _ in range(len(secret)):
        row = [secret[_]] + [os.urandom(1)[0] for _ in range(k - 1)]
        coeffs.append(row)

    shares = []
    for x in range(1, n + 1):  # x = 1, 2, 3...
        share = bytearray(len(secret))
        for i in range(len(secret)):
            # Evaluate polynomial at x: y = sum(coeff[j] * x^j)
            y = 0
            x_pow = 1
            for j in range(k):
                y ^= _gf256_mul(coeffs[i][j], x_pow)
                x_pow = _gf256_mul(x_pow, x)
            share[i] = y
        shares.append((x, bytes(share)))
    return shares

def shamir_reconstruct(shares: List[Tuple[int, bytes]], k: int) -> bytes:
    """
    Reconstruct secret from shares using Lagrange interpolation in GF(256).
    Requires at least k shares (threshold).
    All shares must have same length and distinct x values.
    """
    if len(shares) < k:
        raise ValueError(f"need at least {k} shares, got {len(shares)}")
    share_len = len(shares[0][1])
    for _, s in shares:
        if len(s) != share_len:
            raise ValueError("share length mismatch")
    # Check for duplicate x values
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x values in shares")

    secret = bytearray(share_len)
    xs = [x for x, _ in shares]
    ys = [s for _, s in shares]

    for i in range(share_len):
        # Lagrange interpolation at x=0: secret = sum(y_j * L_j(0))
        # L_j(0) = prod_{m!=j} (0 - x_m) / (x_j - x_m) = prod_{m!=j} (-x_m) / (x_j - x_m)
        secret_byte = 0
        for j in range(len(shares)):
            num = 1
            den = 1
            for m in range(len(shares)):
                if m == j:
                    continue
                num = _gf256_mul(num, xs[m])  # -x_m == x_m in GF(256) (char 2)
                den = _gf256_mul(den, xs[j] ^ xs[m])  # x_j - x_m = x_j + x_m = xor
            lagrange = _gf256_div(num, den)
            secret_byte ^= _gf256_mul(lagrange, ys[j][i])
        secret[i] = secret_byte
    return bytes(secret)

def shamir_split_48digit(key_48digits: str, n: int = 3, k: int = 2) -> List[Tuple[int, str]]:
    """
    Split 48-digit decimal string into n shares (threshold k).
    Returns shares as (x, hex_string).
    Encodes 48 ASCII digits directly as 48 bytes.
    """
    if len(key_48digits) != 48 or not key_48digits.isdigit():
        raise ValueError("key must be exactly 48 decimal digits")
    # Encode 48 ASCII digits directly as bytes (48 bytes)
    key_bytes = key_48digits.encode("ascii")
    shares = shamir_split(key_bytes, n, k)
    return [(x, share.hex()) for x, share in shares]

def shamir_reconstruct_48digit(shares: List[Tuple[int, str]], k: int = 2) -> str:
    """Reconstruct 48-digit key from hex shares. Requires at least k shares."""
    share_tuples = [(x, bytes.fromhex(s)) for x, s in shares]
    key_bytes = shamir_reconstruct(share_tuples, k)
    if len(key_bytes) != 48:
        raise ValueError(f"reconstructed key length mismatch: {len(key_bytes)} != 48")
    try:
        key_str = key_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("reconstructed key is not valid ASCII digits")
    if not key_str.isdigit():
        raise ValueError("reconstructed key contains non-digits")
    return key_str

# ──────────────────────────────────────────────────────────────
# Abstract error mapping matrix
# ──────────────────────────────────────────────────────────────
ERROR_MAP: Dict[Tuple[str, str], str] = {
    # (source, native_code) -> abstract_reason
    ("windows", "0x80070005"): R_INSUFFICIENT_PRIVILEGES,
    ("windows", "5"): R_INSUFFICIENT_PRIVILEGES,           # ERROR_ACCESS_DENIED
    ("windows", "0x8007000E"): R_STORE_CORRUPTED,          # OUT_OF_MEMORY -> treat as corruption
    ("windows", "0x80070057"): R_STORE_CORRUPTED,          # INVALID_PARAMETER
    ("linux", "13"): R_INSUFFICIENT_PRIVILEGES,            # EACCES
    ("linux", "1"): R_STORE_CORRUPTED,                     # EPERM (sometimes)
    ("linux", "5"): R_READ_FAILED,                         # EIO
    ("linux", "28"): R_STORE_CORRUPTED,                    # ENOSPC
    ("raw", "short_read"): R_READ_FAILED,
    ("raw", "signature_mismatch"): R_INVALID_SIGNATURE,
    ("raw", "unsupported_fs"): R_UNSUPPORTED_FS,
}

def map_error(source: str, native_code: str) -> str:
    """Translate native OS error to abstract reason code."""
    return ERROR_MAP.get((source, native_code), R_VOLUME_QUERY_FAILED)

def wrap_raw_error(e: Exception, source: str = "raw") -> RawError:
    """Convert any exception to RawError with abstract reason."""
    if isinstance(e, RawError):
        return e
    if isinstance(e, PermissionError):
        return RawError(R_INSUFFICIENT_PRIVILEGES, str(e))
    if isinstance(e, FileNotFoundError):
        return RawError(R_VOLUME_QUERY_FAILED, str(e))
    if isinstance(e, OSError):
        return RawError(map_error(source, str(e.errno)), str(e))
    return RawError(R_VOLUME_QUERY_FAILED, str(e))

# ──────────────────────────────────────────────────────────────
# High-level capability interface
# ──────────────────────────────────────────────────────────────
def get_volume_identifiers_raw(device_path: str, partition_offset: int = 0) -> Dict[str, Any]:
    """
    Unified raw extraction for a partition.
    Returns dict with available identifiers.
    """
    result = {"device": device_path}
    try:
        result["ntfs_volume_serial"] = read_ntfs_volume_serial(device_path, partition_offset)
    except RawError:
        pass
    try:
        result["bitlocker_volume_id"] = read_bitlocker_volume_id(device_path, partition_offset)
    except RawError:
        pass
    try:
        result["luks_uuid"] = read_luks_uuid(device_path)
    except RawError:
        pass
    try:
        result["ext4_uuid"] = read_ext4_uuid(device_path, partition_offset)
    except RawError:
        pass
    try:
        result["is_swap"] = is_swap_partition(device_path, partition_offset)
    except RawError:
        result["is_swap"] = False
    return result