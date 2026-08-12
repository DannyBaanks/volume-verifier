# volume_verifier.py — Volume Identity Verifier v1.4
#
# PURPOSE
#   Verify continuity of observable volume metadata for a previously
#   registered volume. It does NOT decrypt, unlock, or read volume contents.
#   It does NOT prove physical ownership of hardware.
#
# IDENTITY MODEL
#   A registered identity has an explicit strength:
#     WEAK      - observable volume UniqueId only
#     STANDARD  - UniqueId + BitLocker Volume ID / LUKS UUID
#     RAW       - verification-time upgrade: API evidence confirmed by
#                 independent raw sector reads (--raw). Never stored; the
#                 entry keeps its registered strength.
#   There is intentionally no hardware-backed attestation tier beyond RAW:
#   no hardware-backed attestation exists in this model. A fingerprint is
#   only comparable within the same platform; the store schema carries the
#   platform for that reason.
#
# SECURITY MODEL
#   The identity store is protected at rest with Windows DPAPI (per-user,
#   per-machine) or HMAC_PASSPHRASE, and written atomically. DPAPI prevents
#   casual modification and accidental corruption from being accepted; it
#   does NOT protect against an attacker with the same user's privileges,
#   who could simply re-run --register.
#
# RAW CORROBORATION (--raw)
#   Volume Verifier has two independent evidence channels:
#     API   - OS APIs (Get-Volume, manage-bde, lsblk, cryptsetup)
#     RAW   - direct sector reads (source/crypto/raw): NTFS VBR serial,
#             BitLocker FVE volume identifier, LUKS/ext4 UUIDs
#   --raw is opt-in and requires administrator/root. Both channels must
#   agree: a conflict is DENY EVIDENCE_CONFLICT (never a silent pass), and
#   a confirmed match upgrades the verdict to RAW strength. Failure to
#   acquire raw evidence is an explicit ERROR, never a silent fallback.
#
# NO SILENT FALLBACK
#   Every external query is classified explicitly. A failure to acquire
#   evidence is never converted into a valid identity: it becomes a DENY or
#   an ERROR with a REASON code.
#
# PLATFORM
#   Windows (PowerShell Get-Volume + manage-bde) and Linux (findmnt + lsblk
#   + cryptsetup, no root). Other platforms are rejected with
#   UNSUPPORTED_PLATFORM. Platform-specific evidence sources for macOS are
#   a documented roadmap, not implemented here.
#
# EXIT CODES
#   0 = PASS          1 = DENY         2 = ERROR
#
# Command-line usage:
#   volume-verifier.exe --volume C: [--store <path>] [--register] [--raw]
#   volume-verifier.exe --volume /mnt/data [--store <path>] [--register] [--raw]

import argparse
import base64
import binascii
import ctypes
import hashlib
import hmac
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple
from ctypes import wintypes

from crypto import raw as crypto_raw

VERSION = "1.4.0"
STORE_FORMAT_VERSION = 2
CMD_TIMEOUT = 15
SUPPORTED_PLATFORM = "win32"
KDF_ITERATIONS = 100_000

EXIT_PASS = 0
EXIT_DENY = 1
EXIT_ERROR = 2

# Reason codes
R_UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
R_INVALID_ARGS = "INVALID_ARGS"
R_VOLUME_QUERY_FAILED = "VOLUME_QUERY_FAILED"
R_BITLOCKER_QUERY_FAILED = "BITLOCKER_QUERY_FAILED"
R_INSUFFICIENT_PRIVILEGES = "INSUFFICIENT_PRIVILEGES"
R_BITLOCKER_METADATA_UNAVAILABLE = "BITLOCKER_METADATA_UNAVAILABLE"
R_LUKS_METADATA_UNAVAILABLE = "LUKS_METADATA_UNAVAILABLE"
R_STORE_MISSING = "STORE_MISSING"
R_STORE_CORRUPTED = "STORE_CORRUPTED"
R_STORE_SCHEMA_MISMATCH = "STORE_SCHEMA_MISMATCH"
R_STORE_PROTECTION_UNAVAILABLE = "STORE_PROTECTION_UNAVAILABLE"
R_STORE_PASSPHRASE_REQUIRED = "STORE_PASSPHRASE_REQUIRED"
R_STORE_MAC_MISMATCH = "STORE_MAC_MISMATCH"
R_NOT_REGISTERED = "NOT_REGISTERED"
R_FINGERPRINT_MISMATCH = "FINGERPRINT_MISMATCH"
R_MATCHED = "MATCHED_REGISTERED_IDENTITY"
R_RAW_READ_FAILED = "RAW_READ_FAILED"
R_RAW_INSUFFICIENT_PRIVILEGES = "RAW_INSUFFICIENT_PRIVILEGES"
R_EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"

STRENGTH_WEAK = "WEAK"
STRENGTH_STANDARD = "STANDARD"
STRENGTH_RAW = "RAW"

_ENTRY_FIELDS = {
    "unique_id": (str,),
    "bitlocker_id": (str, type(None)),
    "identity_strength": (str,),
    "platform": (str,),
    "fingerprint": (str,),
    "registered_at": (str,),
}

# Optional evidence fields recorded by --register --raw. Pre-v1.4 entries
# (and stores written without raw capture) legitimately lack them; they are
# validated only when present.
_ENTRY_OPTIONAL_FIELDS = {
    "raw_ntfs_serial": (str, type(None)),
    "raw_fve_guid": (str, type(None)),
    "raw_luks_uuid": (str, type(None)),
    "raw_ext4_uuid": (str, type(None)),
}


class VerifierError(Exception):
    """Operational failure with an explicit reason code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason
        self.message = message


@dataclass
class Verdict:
    """Result of a verification. outcome: PASS | DENY | ERROR."""

    outcome: str
    reason: str
    strength: Optional[str] = None

    @property
    def exit_code(self) -> int:
        if self.outcome == "PASS":
            return EXIT_PASS
        if self.outcome == "DENY":
            return EXIT_DENY
        return EXIT_ERROR

    def format(self) -> str:
        lines = [f"VERDICT: {self.outcome}", f"REASON: {self.reason}"]
        if self.strength:
            lines.append(f"STRENGTH: {self.strength}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Platform seam (local, generic, minimal)
#
# Public-contract view: a platform source produces NORMALIZED observations
# for a volume. Only Windows is functional. Other platforms are explicitly
# UNSUPPORTED (no fake evidence) until equivalent experiments exist.
# This is a product-level abstraction for Volume Verifier only.
# ---------------------------------------------------------------------------

class VolumeObservations:
    """Normalized observable metadata for a volume on one platform."""

    def __init__(
        self,
        platform: str,
        unique_id: str,
        bitlocker_id: Optional[str],
        disk_serial: Optional[str] = None,
    ):
        self.platform = platform
        self.unique_id = unique_id
        self.bitlocker_id = bitlocker_id
        self.disk_serial = disk_serial

    @property
    def identity_strength(self) -> str:
        return STRENGTH_STANDARD if self.bitlocker_id else STRENGTH_WEAK


class PlatformVolumeSource:
    """Base contract. Subclasses produce observations or raise an explicit
    VerifierError. Nothing here touches the OS; subclasses do."""

    platform = "unknown"

    def get_observations(self, volume: str) -> VolumeObservations:
        raise NotImplementedError


class WindowsVolumeSource(PlatformVolumeSource):
    """Windows evidence: PowerShell Get-Volume + manage-bde (read-only)."""

    platform = SUPPORTED_PLATFORM

    def get_observations(self, volume: str) -> VolumeObservations:
        _normalize_volume(volume)  # raises INVALID_ARGS
        unique_id = _query_unique_id(volume)
        bitlocker_id = _query_bitlocker(volume)
        return VolumeObservations(
            platform=self.platform, unique_id=unique_id, bitlocker_id=bitlocker_id
        )


class LinuxVolumeSource(PlatformVolumeSource):
    """Linux evidence: findmnt + lsblk + cryptsetup (read-only, no root).

    Evidence-backed contract (see evidence/linux-identity/EXPERIMENT.md):
    - unique_id    = filesystem UUID of the mounted volume
    - bitlocker_id = LUKS UUID of the container (the BitLocker analog);
      None when the volume is not LUKS-encrypted
    - disk_serial  = SCSI/WWN serial of the parent disk (extra observation,
      recorded in the entry but not part of the canonical fingerprint)
    Device names are never used as identity (sdX is not stable across
    sessions). blkid is never used (requires root here).
    """

    platform = "linux"

    def get_observations(self, volume: str) -> VolumeObservations:
        fs_uuid = _query_linux_fs_uuid(volume)  # raises VOLUME_QUERY_FAILED
        luks_uuid = _query_linux_luks_uuid(volume)
        return VolumeObservations(
            platform=self.platform,
            unique_id=fs_uuid,
            bitlocker_id=luks_uuid,
            disk_serial=_query_linux_disk_serial(volume),
        )


class UnsupportedPlatformSource(PlatformVolumeSource):
    """Explicit rejection for platforms without evidence. No fake data.

    macOS is rejected here: no genuine macOS hardware is available, and a
    macOS .iso inside a VM is malleable (no legitimate evidence). Adding
    macOS requires real hardware first.
    """

    def __init__(self, platform: str):
        self.platform = platform

    def get_observations(self, volume: str) -> VolumeObservations:
        raise VerifierError(
            R_UNSUPPORTED_PLATFORM,
            f"Volume Verifier {VERSION} supports Windows and Linux "
            f"(found '{self.platform}'). macOS is not implemented: no "
            "genuine macOS hardware is available and a VM .iso would not "
            "produce legitimate evidence (see evidence/linux-identity/"
            "EXPERIMENT.md and ARCHITECTURE.md).",
        )


def _platform() -> str:
    """Return the running platform identifier (single dispatch point)."""
    return sys.platform


def _get_source() -> PlatformVolumeSource:
    platform = _platform()
    if platform == SUPPORTED_PLATFORM:
        return WindowsVolumeSource()
    if platform == "linux":
        return LinuxVolumeSource()
    return UnsupportedPlatformSource(platform)


def _normalize_volume(volume: str) -> Tuple[str, str]:
    letter = volume.strip().strip(": \\").upper()
    if not letter or not letter.isalpha():
        raise VerifierError(R_INVALID_ARGS, f"Invalid volume: '{volume}'")
    return letter, f"{letter}:"


def _store_key(volume: str) -> str:
    """Return the store key for a volume, aware of the running platform.

    Windows: drive letter uppercased with colon ("C:").
    Linux: the mountpoint, trailing slash removed ("\\mnt\\data").
    macOS/other: not used (unsupported source rejects first).
    """
    if _platform() == SUPPORTED_PLATFORM:
        _, key = _normalize_volume(volume)
        return key
    return volume.rstrip("/") or "/"


# ---------------------------------------------------------------------------
# Evidence acquisition (Windows). Every failure is explicit; never None-
# swallows into a valid identity.
# ---------------------------------------------------------------------------

def _query_unique_id(volume: str) -> str:
    """Return the volume UniqueId via PowerShell Get-Volume.

    Raises VerifierError(VOLUME_QUERY_FAILED) on any failure.
    """
    letter, _ = _normalize_volume(volume)
    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"(Get-Volume -DriveLetter {letter}).UniqueId",
    ]
    try:
        proc = subprocess.run(
            ps_cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT
        )
    except FileNotFoundError:
        raise VerifierError(R_VOLUME_QUERY_FAILED, "powershell not found") from None
    except subprocess.TimeoutExpired:
        raise VerifierError(R_VOLUME_QUERY_FAILED, "powershell timed out") from None
    guid = (proc.stdout or "").strip()
    if proc.returncode != 0 or not guid:
        raise VerifierError(
            R_VOLUME_QUERY_FAILED,
            "Get-Volume returned no UniqueId "
            f"(drive letter '{letter}' not available?)",
        )
    return guid


def _query_bitlocker(volume: str) -> Optional[str]:
    """Return the BitLocker Volume ID, or None if the volume is not
    BitLocker-protected (manage-bde succeeded but has no Volume ID).

    Raises VerifierError(INSUFFICIENT_PRIVILEGES | BITLOCKER_QUERY_FAILED)
    when the query cannot be performed. A failed query is never treated as
    'not encrypted'.
    """
    letter, _ = _normalize_volume(volume)
    cmd = ["manage-bde", "-status", f"{letter}:"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT
        )
    except FileNotFoundError:
        raise VerifierError(R_BITLOCKER_QUERY_FAILED, "manage-bde not found") from None
    except subprocess.TimeoutExpired:
        raise VerifierError(R_BITLOCKER_QUERY_FAILED, "manage-bde timed out") from None
    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        # Classification is best-effort and never silently falls back:
        #  * 0x80070005 is the documented Win32 HRESULT for
        #    ERROR_ACCESS_DENIED (observed on some Windows builds);
        #  * English text heuristics cover "access denied" output
        #    (localized output may not match and then degrades to
        #    BITLOCKER_QUERY_FAILED, which is still explicit).
        if proc.returncode == 0x80070005:
            raise VerifierError(
                R_INSUFFICIENT_PRIVILEGES,
                "manage-bde requires elevation (run as administrator)",
            )
        if "access denied" in combined.lower() or "permission" in combined.lower():
            raise VerifierError(
                R_INSUFFICIENT_PRIVILEGES,
                "manage-bde requires elevation (run as administrator)",
            )
        raise VerifierError(
            R_BITLOCKER_QUERY_FAILED,
            f"manage-bde exited with code {proc.returncode}",
        )
    return _extract_volume_id(proc.stdout or "")


def _extract_volume_id(status_output: str) -> Optional[str]:
    """Parse the 'Volume ID:' line from manage-bde output."""
    for line in status_output.splitlines():
        if line.strip().lower().startswith("volume id:"):
            _, value = line.split(":", 1)
            return value.strip()
    return None


# ---------------------------------------------------------------------------
# Evidence acquisition (Linux). Read-only; no root; no blkid.
# Every failure is explicit. Device names are never used as identity.
# Evidence basis: evidence/linux-identity/EXPERIMENT.md
# ---------------------------------------------------------------------------

def _run_linux_cmd(cmd: list) -> str:
    """Run a read-only Linux command and return stripped stdout.

    Raises VerifierError(VOLUME_QUERY_FAILED) on any failure.
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT
        )
    except FileNotFoundError:
        raise VerifierError(
            R_VOLUME_QUERY_FAILED, f"{cmd[0]} not found"
        ) from None
    except subprocess.TimeoutExpired:
        raise VerifierError(
            R_VOLUME_QUERY_FAILED, f"{cmd[0]} timed out"
        ) from None
    if proc.returncode != 0:
        raise VerifierError(
            R_VOLUME_QUERY_FAILED,
            f"{cmd[0]} exited with code {proc.returncode}",
        )
    return (proc.stdout or "").strip()


def _linux_resolve_device(volume: str) -> str:
    """Resolve a mountpoint to its block device via findmnt.

    Raises VOLUME_QUERY_FAILED when the mountpoint is not mounted.
    """
    if not volume or not volume.startswith("/"):
        raise VerifierError(R_INVALID_ARGS, f"Invalid Linux mountpoint: '{volume}'")
    device = _run_linux_cmd(["findmnt", "-no", "SOURCE", volume])
    if not device:
        raise VerifierError(
            R_VOLUME_QUERY_FAILED, f"mountpoint '{volume}' has no device"
        )
    return device


def _query_linux_fs_uuid(volume: str) -> str:
    """Filesystem UUID of the mounted volume (lsblk). The Linux analog of
    the Windows NTFS volume UniqueId. Raises VOLUME_QUERY_FAILED if absent.
    """
    device = _linux_resolve_device(volume)
    uuid = _run_linux_cmd(["lsblk", "-no", "UUID", device])
    if not uuid:
        raise VerifierError(
            R_VOLUME_QUERY_FAILED,
            f"volume '{volume}' has no filesystem UUID",
        )
    return uuid


def _linux_backing_device(device: str) -> str:
    """Resolve the backing device for an opened device-mapper target (LUKS).

    `cryptsetup status /dev/mapper/<name>` prints "  device:  /dev/loopN";
    that backing device is where the LUKS header and the filesystem live.
    Plain block devices are returned unchanged.
    """
    if not device.startswith("/dev/mapper/"):
        return device
    status = _linux_cmd_silent(["cryptsetup", "status", device])
    for line in status.splitlines():
        if line.strip().lower().startswith("device:"):
            candidate = line.split(":", 1)[1].strip()
            if candidate.startswith("/dev/"):
                return candidate
    return device


def _query_linux_disk_serial(volume: str) -> Optional[str]:
    """SCSI/WWN serial of the parent disk. Extra observation; not part of
    the canonical fingerprint. Returns None when the disk has no serial
    (e.g. ram disks, loop devices, some virtual disks). Never raises.

    For volumes backed by an opened device-mapper target (e.g. a mounted
    LUKS container at /dev/mapper/<name>), the underlying backing device
    is resolved first (cryptsetup status); otherwise the parent partition
    disk is used.
    """
    try:
        device = _linux_resolve_device(volume)
    except VerifierError:
        return None
    target = _linux_backing_device(device)
    if not target.startswith("/dev/"):
        return None
    name = target[len("/dev/"):]
    while name and name[-1].isdigit():
        name = name[:-1]
    disk = name or target[len("/dev/"):]
    if not disk:
        return None
    try:
        serial = _run_linux_cmd(["lsblk", "-dno", "SERIAL", f"/dev/{disk}"])
    except VerifierError:
        return None
    return serial or None


def _query_linux_luks_uuid(volume: str) -> Optional[str]:
    """LUKS UUID of the container (the BitLocker analog). Returns None when
    the volume is not LUKS-encrypted or the UUID cannot be read (honest:
    the two are not distinguished here). Never raises.

    Evidence note (evidence/linux-identity/raw/11-luks-resolution-correct.txt):
    `cryptsetup luksUUID` on an OPENED mapper (/dev/mapper/<name>) returns
    EMPTY on some cryptsetup builds — it must be queried on the backing
    device. For a mapper we resolve the backing device via
    `cryptsetup status` (which prints "  device:  /dev/loopN"), then run
    `luksUUID` on that backing device. For a plain block device we query
    `luksUUID` directly.
    """
    try:
        device = _linux_resolve_device(volume)
    except VerifierError:
        return None
    target = _linux_backing_device(device)
    try:
        proc = subprocess.run(
            ["cryptsetup", "luksUUID", target],
            capture_output=True, text=True, timeout=CMD_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip() or None


def _linux_cmd_silent(cmd: list) -> str:
    """Run a command ignoring non-zero exit; return stdout (may be '')."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


# ---------------------------------------------------------------------------
# Raw evidence acquisition (--raw corroboration channel)
#
# Independent of the API channel: direct sector reads via crypto.raw.
#   Windows: NTFS VBR serial from \\.\X: ; BitLocker FVE volume identifier
#            from the physical disk at the partition offset (raw sector 0
#            holds the FVE header in the clear, locked or unlocked).
#   Linux:   LUKS UUID and ext4 UUID read from the backing block device.
# Requires administrator/root. Every failure maps to an explicit
# RAW_READ_FAILED / RAW_INSUFFICIENT_PRIVILEGES error; "this filesystem
# type has no such identifier" is honest absence (None), never an error.
# ---------------------------------------------------------------------------

def _raw_to_verifier(e: crypto_raw.RawError, what: str) -> VerifierError:
    """Map a RawError to an explicit RAW_* VerifierError."""
    if e.reason == crypto_raw.R_INSUFFICIENT_PRIVILEGES:
        return VerifierError(
            R_RAW_INSUFFICIENT_PRIVILEGES,
            f"raw {what}: {e.detail or e.reason}",
        )
    return VerifierError(
        R_RAW_READ_FAILED, f"raw {what}: {e.detail or e.reason}"
    )


def _raw_windows_partition(letter: str) -> Tuple[int, int]:
    """Return (disk_number, byte_offset) for a drive letter via Get-Partition.

    Raw reads of the FVE header need the physical disk and the partition
    offset; the volume device only exposes the decrypted view.
    """
    def _field(expr: str) -> str:
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", expr]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            raise VerifierError(
                R_RAW_READ_FAILED, "cannot resolve partition (powershell unavailable)"
            ) from None
        value = (proc.stdout or "").strip()
        if proc.returncode != 0 or not value:
            raise VerifierError(
                R_RAW_READ_FAILED,
                f"cannot resolve partition for '{letter}:' (needs administrator)",
            )
        return value

    disk = _field(f"(Get-Partition -DriveLetter {letter} | Select-Object -ExpandProperty DiskNumber)")
    offset = _field(f"(Get-Partition -DriveLetter {letter} | Select-Object -ExpandProperty Offset)")
    if not disk.isdigit() or not offset.isdigit():
        raise VerifierError(
            R_RAW_READ_FAILED,
            f"cannot resolve partition for '{letter}:' (needs administrator)",
        )
    return int(disk), int(offset)


def _raw_observations_windows(volume: str) -> dict:
    """Capture raw evidence for a Windows volume (requires administrator)."""
    letter, _ = _normalize_volume(volume)

    serial = None
    try:
        serial = crypto_raw.read_ntfs_volume_serial(rf"\\.\{letter}:", 0)
    except crypto_raw.RawError as e:
        if e.reason != crypto_raw.R_UNSUPPORTED_FS:
            raise _raw_to_verifier(e, "NTFS serial") from None

    disk, offset = _raw_windows_partition(letter)
    guid = None
    try:
        guid = crypto_raw.read_bitlocker_volume_id(
            rf"\\.\PhysicalDrive{disk}", offset // 512
        )
    except crypto_raw.RawError as e:
        if e.reason != crypto_raw.R_VOLUME_QUERY_FAILED or "not found" not in e.detail:
            raise _raw_to_verifier(e, "BitLocker volume ID") from None

    return {
        "raw_ntfs_serial": f"{serial:X}" if serial is not None else None,
        "raw_fve_guid": guid,
    }


def _raw_observations_linux(volume: str) -> dict:
    """Capture raw evidence for a Linux volume (requires root)."""
    device = _linux_resolve_device(volume)
    target = _linux_backing_device(device)

    luks_uuid = None
    try:
        luks_uuid = crypto_raw.read_luks_uuid(target)
    except crypto_raw.RawError as e:
        if e.reason != crypto_raw.R_INVALID_SIGNATURE:
            raise _raw_to_verifier(e, "LUKS UUID") from None

    ext4_uuid = None
    try:
        ext4_uuid = crypto_raw.read_ext4_uuid(target, 0)
    except crypto_raw.RawError as e:
        if e.reason != crypto_raw.R_UNSUPPORTED_FS:
            raise _raw_to_verifier(e, "ext4 UUID") from None

    return {"raw_luks_uuid": luks_uuid, "raw_ext4_uuid": ext4_uuid}


def _raw_observations(volume: str) -> dict:
    """Capture raw evidence for the running platform. Raises VerifierError."""
    if _platform() == SUPPORTED_PLATFORM:
        return _raw_observations_windows(volume)
    return _raw_observations_linux(volume)


def _canonical_guid(value: str) -> str:
    """Normalize a GUID string for comparison (braces, hyphens, case)."""
    return value.strip().strip("{}").replace("-", "").upper()


def _corroborate(entry: dict, obs: VolumeObservations, raw_obs: dict) -> Tuple[bool, bool]:
    """Cross-check raw sector evidence against API evidence and the entry.

    Returns (conflict, corroborated):
      conflict      - raw evidence contradicts API evidence or the registered
                      entry (EVIDENCE_CONFLICT)
      corroborated  - at least one independent comparison agreed (RAW strength)

    Registered raw fields are optional: pre-v1.4 entries legitimately lack
    them, and raw-to-API comparison still works for those entries.
    """
    conflict = False
    corroborated = False

    if obs.platform == "win32":
        entry_serial = entry.get("raw_ntfs_serial")
        if entry_serial is not None:
            if raw_obs.get("raw_ntfs_serial") == entry_serial:
                corroborated = True
            else:
                conflict = True
        api_bid = obs.bitlocker_id
        raw_guid = raw_obs.get("raw_fve_guid")
        if api_bid:
            if raw_guid is None:
                conflict = True  # API says BitLocker, no FVE header on disk
            elif _canonical_guid(raw_guid) == _canonical_guid(api_bid):
                corroborated = True
            else:
                conflict = True
        elif raw_guid is not None:
            conflict = True  # API says no BitLocker, FVE header found
        return conflict, corroborated

    api_luks = obs.bitlocker_id
    raw_luks = raw_obs.get("raw_luks_uuid")
    if api_luks:
        if raw_luks is None:
            conflict = True  # API says LUKS, no LUKS header on disk
        elif raw_luks.lower() == api_luks.lower():
            corroborated = True
        else:
            conflict = True
    else:
        api_fs = obs.unique_id
        raw_ext4 = raw_obs.get("raw_ext4_uuid")
        if raw_ext4 is not None:
            if raw_ext4.lower() == api_fs.lower():
                corroborated = True
            else:
                conflict = True
    entry_luks = entry.get("raw_luks_uuid")
    if entry_luks is not None:
        if raw_luks == entry_luks:
            corroborated = True
        else:
            conflict = True
    entry_ext4 = entry.get("raw_ext4_uuid")
    if entry_ext4 is not None:
        if raw_ext4 == entry_ext4:
            corroborated = True
        else:
            conflict = True
    return conflict, corroborated


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

def _fingerprint(unique_id: str) -> str:
    """WEAK: SHA-256 of the canonical UniqueId."""
    return hashlib.sha256(unique_id.lower().encode("utf-8")).hexdigest()


def _fingerprint_standard(unique_id: str, bitlocker_id: str) -> str:
    """STANDARD: SHA-256 of UniqueId + BitLocker Volume ID."""
    return hashlib.sha256(
        (unique_id + bitlocker_id).lower().encode("utf-8")
    ).hexdigest()


# ---------------------------------------------------------------------------
# DPAPI store protection (Windows native)
# ---------------------------------------------------------------------------

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


_CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _dpapi_protect(data: bytes) -> bytes:
    return _dpapi_call(True, data)


def _dpapi_unprotect(data: bytes) -> bytes:
    return _dpapi_call(False, data)


def _dpapi_call(protect: bool, data: bytes) -> bytes:
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
    except AttributeError:
        raise VerifierError(
            R_STORE_PROTECTION_UNAVAILABLE, "DPAPI is only available on Windows"
        ) from None

    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    fn.argtypes = [
        ctypes.POINTER(_DATA_BLOB),  # pDataIn
        wintypes.LPCWSTR,            # szDataDescr
        ctypes.POINTER(_DATA_BLOB),  # pOptionalEntropy
        ctypes.c_void_p,             # pvReserved
        ctypes.c_void_p,             # pPromptStruct
        wintypes.DWORD,              # dwFlags
        ctypes.POINTER(_DATA_BLOB),  # pDataOut
    ]
    fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    in_blob = _DATA_BLOB(len(data), ctypes.cast(
        ctypes.create_string_buffer(data, len(data)),
        ctypes.POINTER(ctypes.c_ubyte),
    ))
    out_blob = _DATA_BLOB()
    ok = fn(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok or not out_blob.pbData:
        raise VerifierError(
            R_STORE_PROTECTION_UNAVAILABLE,
            "CryptProtectData" if protect else "CryptUnprotectData",
        )
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


# ---------------------------------------------------------------------------
# Identity store (schema v2, DPAPI-protected, atomic writes)
# ---------------------------------------------------------------------------

def _hmac_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256 key for store integrity (never a decryption key)."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)


def _store_wrapper_bytes(
    entries: Dict[str, dict], passphrase: Optional[str] = None
) -> bytes:
    """Serialize the store.

    Default protection: DPAPI_USER (encrypted payload, per-user+machine).
    With passphrase: HMAC_PASSPHRASE (integrity only, payload visible).
    """
    payload = json.dumps(entries, indent=2, sort_keys=True).encode("utf-8")
    if passphrase is None:
        wrapper = {
            "format_version": STORE_FORMAT_VERSION,
            "protection": "DPAPI_USER",
            "platform": SUPPORTED_PLATFORM,
            "entries_b64": base64.b64encode(_dpapi_protect(payload)).decode("ascii"),
        }
    else:
        salt = os.urandom(16)
        key = _hmac_key(passphrase, salt)
        mac = hmac.new(key, payload, hashlib.sha256).digest()
        wrapper = {
            "format_version": STORE_FORMAT_VERSION,
            "protection": "HMAC_PASSPHRASE",
            "platform": SUPPORTED_PLATFORM,
            "kdf": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": KDF_ITERATIONS,
                "salt_b64": base64.b64encode(salt).decode("ascii"),
            },
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "mac_b64": base64.b64encode(mac).decode("ascii"),
        }
    return json.dumps(wrapper, indent=2, sort_keys=True).encode("utf-8")


def _load_store(
    path: Path, passphrase: Optional[str] = None
) -> Optional[Dict[str, dict]]:
    """Load and validate the store.

    Returns None if the file does not exist.
    Raises VerifierError(STORE_CORRUPTED | STORE_SCHEMA_MISMATCH |
    STORE_PROTECTION_UNAVAILABLE | STORE_PASSPHRASE_REQUIRED |
    STORE_MAC_MISMATCH) otherwise.

    A MAC mismatch means either a wrong passphrase or a tampered store; the
    two are cryptographically indistinguishable and share one reason code.
    """
    if not path.is_file():
        return None
    try:
        raw = path.read_bytes()
        wrapper = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VerifierError(R_STORE_CORRUPTED, "store is not valid JSON") from None

    if not isinstance(wrapper, dict):
        raise VerifierError(R_STORE_CORRUPTED, "store root is not a JSON object")

    if "format_version" not in wrapper:
        # Legacy v1 stores were a plain dict of entries. Rejected explicitly;
        # --register migrates them.
        raise VerifierError(
            R_STORE_SCHEMA_MISMATCH,
            "store uses legacy format v1; re-register volumes to migrate",
        )
    if wrapper.get("format_version") != STORE_FORMAT_VERSION:
        raise VerifierError(
            R_STORE_SCHEMA_MISMATCH,
            f"unsupported store format_version "
            f"{wrapper.get('format_version')} (expected {STORE_FORMAT_VERSION})",
        )

    protection = wrapper.get("protection")
    if protection == "DPAPI_USER":
        entries_b64 = wrapper.get("entries_b64")
        if not isinstance(entries_b64, str):
            raise VerifierError(R_STORE_CORRUPTED, "store missing entries_b64")
        try:
            payload = _dpapi_unprotect(
                base64.b64decode(entries_b64.encode("ascii"), validate=True)
            )
        except (binascii.Error, ValueError):
            raise VerifierError(R_STORE_CORRUPTED, "store payload is not valid base64") from None
        except VerifierError as e:
            raise VerifierError(
                R_STORE_CORRUPTED, f"store payload cannot be decrypted ({e.reason})"
            ) from None
    elif protection == "HMAC_PASSPHRASE":
        kdf = wrapper.get("kdf")
        payload_b64 = wrapper.get("payload_b64")
        mac_b64 = wrapper.get("mac_b64")
        if not isinstance(kdf, dict) or not isinstance(payload_b64, str) \
                or not isinstance(mac_b64, str):
            raise VerifierError(R_STORE_CORRUPTED, "store missing HMAC fields")
        if passphrase is None:
            raise VerifierError(
                R_STORE_PASSPHRASE_REQUIRED,
                "store uses HMAC_PASSPHRASE protection; provide --passphrase "
                "(or VOLUME_VERIFIER_PASSPHRASE)",
            )
        try:
            salt = base64.b64decode(kdf["salt_b64"].encode("ascii"), validate=True)
            iterations = int(kdf["iterations"])
            stored_mac = base64.b64decode(mac_b64.encode("ascii"), validate=True)
            payload = base64.b64decode(payload_b64.encode("ascii"), validate=True)
        except (KeyError, ValueError, binascii.Error):
            raise VerifierError(R_STORE_CORRUPTED, "store HMAC fields are invalid") from None
        key = _hmac_key(passphrase, salt, iterations)
        if not hmac.compare_digest(
            hmac.new(key, payload, hashlib.sha256).digest(), stored_mac
        ):
            raise VerifierError(
                R_STORE_MAC_MISMATCH,
                "store MAC mismatch: wrong passphrase or tampered store",
            )
    else:
        raise VerifierError(
            R_STORE_SCHEMA_MISMATCH,
            f"unsupported store protection '{protection}'",
        )

    try:
        entries = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise VerifierError(R_STORE_CORRUPTED, "store payload is invalid") from None

    if not isinstance(entries, dict):
        raise VerifierError(R_STORE_CORRUPTED, "store entries are not an object")
    for key, entry in entries.items():
        _validate_entry(key, entry)
    return entries


def _validate_entry(key: str, entry: object) -> None:
    if not isinstance(entry, dict):
        raise VerifierError(R_STORE_CORRUPTED, f"entry '{key}' is not an object")
    for field, types in _ENTRY_FIELDS.items():
        if field not in entry or not isinstance(entry[field], types):
            raise VerifierError(
                R_STORE_CORRUPTED, f"entry '{key}' has invalid field '{field}'"
            )
    for field, types in _ENTRY_OPTIONAL_FIELDS.items():
        if field in entry and not isinstance(entry[field], types):
            raise VerifierError(
                R_STORE_CORRUPTED, f"entry '{key}' has invalid field '{field}'"
            )
    if entry["identity_strength"] not in (STRENGTH_WEAK, STRENGTH_STANDARD):
        raise VerifierError(
            R_STORE_CORRUPTED,
            f"entry '{key}' has invalid identity_strength "
            f"'{entry['identity_strength']}'",
        )
    fp = entry["fingerprint"]
    if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
        raise VerifierError(R_STORE_CORRUPTED, f"entry '{key}' has invalid fingerprint")


def _migrate_legacy_entries(legacy: Dict[str, object], path: Path) -> Dict[str, dict]:
    """Convert a legacy v1 store (plain dict) into schema v2 entries.

    Strength is derived deterministically (BitLocker ID present -> STANDARD)
    and each migrated fingerprint is recomputed and checked against the
    stored value; entries that do not reproduce are skipped.
    """
    migrated: Dict[str, dict] = {}
    for key, value in legacy.items():
        if not isinstance(value, dict):
            continue
        uid = value.get("unique_id")
        bid = value.get("bitlocker_id")
        if not isinstance(uid, str) or not uid:
            continue
        if isinstance(bid, str) and bid:
            strength = STRENGTH_STANDARD
            fp = _fingerprint_standard(uid, bid)
        else:
            strength = STRENGTH_WEAK
            fp = _fingerprint(uid)
        if isinstance(value.get("fingerprint"), str) and value["fingerprint"] != fp:
            continue
        migrated[str(key).upper()] = {
            "unique_id": uid,
            "bitlocker_id": bid if isinstance(bid, str) else None,
            "identity_strength": strength,
            "platform": SUPPORTED_PLATFORM,
            "fingerprint": fp,
            "registered_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
        }
    return migrated


def _save_store(path: Path, entries: Dict[str, dict], passphrase: Optional[str] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _store_wrapper_bytes(entries, passphrase)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_volume(
    volume: str, store_path: Path, passphrase: Optional[str] = None, raw: bool = False
) -> dict:
    """Record the current observable identity of ``volume``.

    Uses the platform source for the running platform (Windows and Linux;
    other platforms are rejected explicitly). A failed BitLocker/LUKS query is
    an error, never a silent WEAK fallback. Legacy v1 stores are migrated in
    place.

    Store protection: DPAPI_USER by default; HMAC_PASSPHRASE when a
    passphrase is provided. Providing a passphrase on a DPAPI store
    deterministically re-protects it (entries preserved). Never stores or
    derives BitLocker keys.

    With ``raw=True`` the entry also records raw sector evidence
    (NTFS serial / FVE GUID on Windows, LUKS / ext4 UUIDs on Linux) for
    later --raw corroboration. Raw capture failure fails the registration.

    Returns the created entry. Raises VerifierError on failure.
    """
    source = _get_source()
    observations = source.get_observations(volume)

    strength = observations.identity_strength
    if strength == STRENGTH_STANDARD:
        fp = _fingerprint_standard(observations.unique_id, observations.bitlocker_id)
    else:
        fp = _fingerprint(observations.unique_id)

    entries = _load_store_for_register(store_path, passphrase)
    key = _store_key(volume)

    entry = {
        "unique_id": observations.unique_id,
        "bitlocker_id": observations.bitlocker_id,
        "identity_strength": strength,
        "platform": observations.platform,
        "fingerprint": fp,
        "disk_serial": observations.disk_serial,
        "registered_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    if raw:
        entry.update(_raw_observations(volume))
    entries[key] = entry
    _save_store(store_path, entries, passphrase)
    return entry


def _load_store_for_register(
    path: Path, passphrase: Optional[str] = None
) -> Dict[str, dict]:
    """Load store for registration, migrating legacy v1 stores."""
    try:
        entries = _load_store(path, passphrase)
    except VerifierError as e:
        if e.reason != R_STORE_SCHEMA_MISMATCH:
            raise
        if not path.is_file():
            raise
        try:
            legacy = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise VerifierError(R_STORE_CORRUPTED, "legacy store is not valid JSON") from None
        if not isinstance(legacy, dict) or "format_version" in legacy:
            raise VerifierError(
                R_STORE_SCHEMA_MISMATCH, "store cannot be migrated automatically"
            )
        return _migrate_legacy_entries(legacy, path)
    if entries is None:
        return {}
    return entries


def verify_volume(
    volume: str,
    store_path: Path,
    passphrase: Optional[str] = None,
    raw: bool = False,
) -> Verdict:
    """Verify ``volume`` against the registered identity.

    With ``raw=True`` the API fingerprint match is additionally cross-checked
    against independent raw sector reads: a confirmed match upgrades the
    verdict to RAW strength, a disagreement is DENY EVIDENCE_CONFLICT, and a
    raw acquisition failure is an explicit ERROR.

    Never raises for operational problems: everything is classified into a
    Verdict (PASS / DENY / ERROR + REASON).
    """
    try:
        source = _get_source()
        if isinstance(source, UnsupportedPlatformSource):
            source.get_observations(volume)  # raises UNSUPPORTED_PLATFORM
        key = _store_key(volume)

        entries = _load_store(store_path, passphrase)
        if entries is None:
            return Verdict("DENY", R_STORE_MISSING)

        entry = entries.get(key)
        if not isinstance(entry, dict):
            return Verdict("DENY", R_NOT_REGISTERED)

        observations = source.get_observations(volume)

        strength = entry["identity_strength"]
        if strength == STRENGTH_STANDARD:
            if observations.bitlocker_id is None:
                missing_reason = (
                    R_LUKS_METADATA_UNAVAILABLE
                    if entry.get("platform") == "linux"
                    else R_BITLOCKER_METADATA_UNAVAILABLE
                )
                return Verdict("DENY", missing_reason)
            current_fp = _fingerprint_standard(
                observations.unique_id, observations.bitlocker_id
            )
        else:
            current_fp = _fingerprint(observations.unique_id)

        if current_fp != entry["fingerprint"]:
            return Verdict("DENY", R_FINGERPRINT_MISMATCH, strength)

        if not raw:
            return Verdict("PASS", R_MATCHED, strength)

        raw_obs = _raw_observations(volume)
        conflict, corroborated = _corroborate(entry, observations, raw_obs)
        if conflict:
            return Verdict("DENY", R_EVIDENCE_CONFLICT, strength)
        if corroborated:
            return Verdict("PASS", R_MATCHED, STRENGTH_RAW)
        return Verdict("PASS", R_MATCHED, strength)
    except VerifierError as e:
        return Verdict("ERROR", e.reason)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Volume Identity Verifier - verifies continuity of observable "
            "volume metadata for a previously registered volume. "
            "Windows and Linux."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument(
        "--volume",
        required=True,
        help="Drive letter (e.g., C:) or Linux mountpoint (e.g., /mnt/data)",
    )
    parser.add_argument(
        "--store",
        default=str(Path.home() / ".volume_verifier" / "identity_store.json"),
        help="Path to the JSON file that stores volume fingerprints.",
    )
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Passphrase for HMAC_PASSPHRASE stores (integrity only, never a "
        "decryption key). Falls back to $env:VOLUME_VERIFIER_PASSPHRASE. "
        "Without it, stores default to DPAPI protection.",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Record the current fingerprint instead of verifying.",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Corroborate evidence with independent raw sector reads "
        "(requires administrator/root). On --register the raw identifiers "
        "are recorded; on verify a confirmed match upgrades the verdict to "
        "RAW strength and a disagreement is DENY EVIDENCE_CONFLICT.",
    )
    return parser.parse_args()


def _resolve_passphrase(args: argparse.Namespace) -> Optional[str]:
    if args.passphrase:
        return args.passphrase
    env = os.environ.get("VOLUME_VERIFIER_PASSPHRASE")
    return env if env else None


def main() -> None:
    args = _parse_args()
    store_path = Path(args.store).expanduser().resolve()
    passphrase = _resolve_passphrase(args)

    if args.register:
        try:
            entry = register_volume(args.volume, store_path, passphrase, raw=args.raw)
            vol_display = args.volume.upper() if entry["platform"] == "win32" else args.volume
            print(
                f"[VERIFIER] Registered {entry['platform']} volume "
                f"{vol_display} "
                f"(identity_strength={entry['identity_strength']})."
            )
            if args.raw:
                print("[VERIFIER] Raw sector evidence recorded for corroboration.")
            sys.exit(EXIT_PASS)
        except VerifierError as e:
            verdict = Verdict("ERROR", e.reason)
            print(verdict.format())
            print(f"MESSAGE: {e.message}")
            sys.exit(verdict.exit_code)
    else:
        verdict = verify_volume(args.volume, store_path, passphrase, raw=args.raw)
        print(verdict.format())
        sys.exit(verdict.exit_code)


if __name__ == "__main__":
    main()
