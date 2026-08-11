import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

import volume_verifier as vv

UID_ORIGINAL = "e61f72b3-1111-4222-8333-444455556666"
UID_COPY = "3c470898-9999-4aaa-8bbb-ccccddddeeee"
BID_ORIGINAL = "{12345678-1234-1234-1234-1234567890AB}"
LINUX_FS_UUID = "985d4e88-aa64-40e5-9b8c-00527c683d68"
LINUX_LUKS_UUID = "2cdf8c67-1ae4-49fe-b57d-ad5a63d13758"
LINUX_DISK_SERIAL = "60022480b6c9acabccdf04bd22304482"
LINUX_MOUNTPOINT = "/mnt/data"


def _make_store_file(entries):
    payload = json.dumps(entries, indent=2, sort_keys=True).encode("utf-8")
    wrapper = {
        "format_version": vv.STORE_FORMAT_VERSION,
        "protection": "DPAPI_USER",
        "platform": "win32",
        "entries_b64": base64.b64encode(vv._dpapi_protect(payload)).decode("ascii"),
    }
    return json.dumps(wrapper, indent=2).encode("utf-8")


class TestExtractVolumeId(unittest.TestCase):
    def test_typical_line(self):
        out = "Volume ID:  {12345678-1234-1234-1234-1234567890AB}"
        self.assertEqual(vv._extract_volume_id(out), BID_ORIGINAL)

    def test_other_case(self):
        out = "volume id: {ABCDEF01-2222-3333-4444-555555555555}"
        self.assertEqual(vv._extract_volume_id(out), "{ABCDEF01-2222-3333-4444-555555555555}")

    def test_missing_line(self):
        self.assertIsNone(vv._extract_volume_id("Conversion Status: Full"))


class TestFingerprint(unittest.TestCase):
    def test_weak_known_value(self):
        expected = hashlib.sha256(b"testguid").hexdigest()
        self.assertEqual(vv._fingerprint("TESTGUID"), expected)

    def test_weak_normalises_to_lowercase(self):
        self.assertEqual(vv._fingerprint("ABCD"), vv._fingerprint("abcd"))

    def test_standard_is_deterministic(self):
        a = vv._fingerprint_standard(UID_ORIGINAL, BID_ORIGINAL)
        b = vv._fingerprint_standard(UID_ORIGINAL, BID_ORIGINAL)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_standard_differs_from_weak(self):
        self.assertNotEqual(
            vv._fingerprint_standard(UID_ORIGINAL, BID_ORIGINAL),
            vv._fingerprint(UID_ORIGINAL),
        )


class TestNormalizeVolume(unittest.TestCase):
    def test_colon(self):
        self.assertEqual(vv._normalize_volume("C:"), ("C", "C:"))

    def test_plain_letter_lowercase(self):
        self.assertEqual(vv._normalize_volume("c"), ("C", "C:"))

    def test_trailing_slash(self):
        self.assertEqual(vv._normalize_volume("c:\\"), ("C", "C:"))

    def test_invalid(self):
        with self.assertRaises(vv.VerifierError):
            vv._normalize_volume("")


class TestPlatformGate(unittest.TestCase):
    @mock.patch("volume_verifier._platform", return_value="darwin")
    def test_unsupported_platform_register(self, _):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(vv.VerifierError) as ctx:
                vv.register_volume("/mnt/x", Path(d) / "store.json")
            self.assertEqual(ctx.exception.reason, "UNSUPPORTED_PLATFORM")

    @mock.patch("volume_verifier._platform", return_value="darwin")
    def test_unsupported_platform_verify(self, _):
        with tempfile.TemporaryDirectory() as d:
            verdict = vv.verify_volume("C:", Path(d) / "store.json")
            self.assertEqual(verdict.outcome, "ERROR")
            self.assertEqual(verdict.reason, "UNSUPPORTED_PLATFORM")
            self.assertEqual(verdict.exit_code, vv.EXIT_ERROR)


class TestStoreSchema(unittest.TestCase):
    def _write(self, d, data):
        p = Path(d) / "store.json"
        if isinstance(data, (bytes, bytearray)):
            p.write_bytes(bytes(data))
        else:
            p.write_text(data, encoding="utf-8")
        return p

    def test_valid_store_loads(self):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": BID_ORIGINAL,
                    "identity_strength": "STANDARD",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint_standard(UID_ORIGINAL, BID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            p = self._write(d, _make_store_file(entries))
            loaded = vv._load_store(p)
            self.assertEqual(loaded["C:"]["unique_id"], UID_ORIGINAL)

    def test_legacy_plaintext_dict_is_schema_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, json.dumps({"C:": {"unique_id": UID_ORIGINAL}}))
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_SCHEMA_MISMATCH")

    def test_wrong_format_version_is_schema_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            wrapper = {"format_version": 1, "entries": {}}
            p = self._write(d, json.dumps(wrapper))
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_SCHEMA_MISMATCH")

    def test_not_a_dict_is_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "[1,2,3]")
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_CORRUPTED")

    def test_invalid_json_is_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, "{ not json !!")
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_CORRUPTED")

    def test_tampered_payload_is_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "WEAK",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint(UID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            raw = bytearray(_make_store_file(entries))
            raw[len(raw) // 2] ^= 0x01
            p = self._write(d, bytes(raw))
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_CORRUPTED")

    def test_entry_missing_fields_is_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, _make_store_file({"C:": {"unique_id": UID_ORIGINAL}}))
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_CORRUPTED")

    def test_bad_fingerprint_hex_is_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "WEAK",
                    "platform": "win32",
                    "fingerprint": "zzzz",
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            p = self._write(d, _make_store_file(entries))
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_CORRUPTED")

    def test_bad_strength_is_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "STRONG",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint(UID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            p = self._write(d, _make_store_file(entries))
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p)
            self.assertEqual(ctx.exception.reason, "STORE_CORRUPTED")


@unittest.skipUnless(sys.platform == "win32", "DPAPI is Windows-only")
class TestDpapi(unittest.TestCase):
    def test_round_trip(self):
        data = b"secret-payload-123"
        self.assertEqual(vv._dpapi_unprotect(vv._dpapi_protect(data)), data)

    def test_unprotect_garbage_raises(self):
        with self.assertRaises(vv.VerifierError) as ctx:
            vv._dpapi_unprotect(b"not-dpapi-data")
        self.assertEqual(ctx.exception.reason, "STORE_PROTECTION_UNAVAILABLE")

    def test_store_is_not_plaintext(self):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "WEAK",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint(UID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            raw = _make_store_file(entries)
            self.assertNotIn(b"unique_id", raw)
            self.assertNotIn(UID_ORIGINAL.encode(), raw)


class TestAtomicWrite(unittest.TestCase):
    def test_save_then_load_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "store.json"
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "WEAK",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint(UID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            vv._save_store(p, entries)
            loaded = vv._load_store(p)
            self.assertEqual(loaded, entries)
            self.assertFalse(Path(str(p) + ".tmp").exists())


class TestVerdicts(unittest.TestCase):
    """T1-T11: mocked evidence acquisition. No real volumes are touched."""

    def _path(self, d):
        return Path(d) / "store.json"

    @mock.patch("volume_verifier._query_bitlocker", return_value=BID_ORIGINAL)
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t01_normal_bitlocker_metadata(self, _uid, _bid):
        with tempfile.TemporaryDirectory() as d:
            entry = vv.register_volume("C:", self._path(d))
            self.assertEqual(entry["identity_strength"], "STANDARD")
            v = vv.verify_volume("C:", self._path(d))
            self.assertEqual(v.outcome, "PASS")
            self.assertEqual(v.reason, "MATCHED_REGISTERED_IDENTITY")
            self.assertEqual(v.strength, "STANDARD")
            self.assertEqual(v.exit_code, vv.EXIT_PASS)

    @mock.patch("volume_verifier._query_bitlocker", return_value=None)
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t02a_weak_register_no_bitlocker(self, _uid, _bid):
        with tempfile.TemporaryDirectory() as d:
            entry = vv.register_volume("C:", self._path(d))
            self.assertEqual(entry["identity_strength"], "WEAK")
            v = vv.verify_volume("C:", self._path(d))
            self.assertEqual(v.outcome, "PASS")
            self.assertEqual(v.strength, "WEAK")

    @mock.patch("volume_verifier._query_bitlocker", side_effect=[
        BID_ORIGINAL,  # register: STANDARD
        None,          # verify: BitLocker metadata gone
    ])
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t02b_standard_metadata_unavailable_is_deny_not_pass(self, _uid, _bid):
        with tempfile.TemporaryDirectory() as d:
            vv.register_volume("C:", self._path(d))
            v = vv.verify_volume("C:", self._path(d))
            self.assertEqual(v.outcome, "DENY")
            self.assertEqual(v.reason, "BITLOCKER_METADATA_UNAVAILABLE")

    @mock.patch("volume_verifier._query_bitlocker", side_effect=vv.VerifierError(
        "BITLOCKER_QUERY_FAILED", "manage-bde exited 1"))
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t03_manage_bde_failure_blocks_register(self, _uid, _bid):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(vv.VerifierError) as ctx:
                vv.register_volume("C:", self._path(d))
            self.assertEqual(ctx.exception.reason, "BITLOCKER_QUERY_FAILED")
            self.assertFalse(self._path(d).exists())

    @mock.patch("volume_verifier._query_bitlocker", side_effect=vv.VerifierError(
        "INSUFFICIENT_PRIVILEGES", "manage-bde requires elevation"))
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t04_insufficient_privileges_is_explicit(self, _uid, _bid):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(vv.VerifierError) as ctx:
                vv.register_volume("C:", self._path(d))
            self.assertEqual(ctx.exception.reason, "INSUFFICIENT_PRIVILEGES")

    def test_t04b_hresult_access_denied_classified(self):
        """manage-bde returns HRESULT 0x80070005 (ERROR_ACCESS_DENIED):
        classification must be deterministic, not text-based."""
        with mock.patch("volume_verifier._normalize_volume", return_value=("C", "C:")):
            with mock.patch("volume_verifier.subprocess.run") as run:
                run.return_value.returncode = 0x80070005
                run.return_value.stdout = ""
                run.return_value.stderr = ""
                with self.assertRaises(vv.VerifierError) as ctx:
                    vv._query_bitlocker("C:")
                self.assertEqual(ctx.exception.reason, "INSUFFICIENT_PRIVILEGES")

    @mock.patch("volume_verifier._query_unique_id", side_effect=vv.VerifierError(
        "VOLUME_QUERY_FAILED", "Get-Volume returned no UniqueId"))
    def test_t05_volume_query_failure_is_error(self, _uid):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "WEAK",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint(UID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            self._path(d).write_bytes(_make_store_file(entries))
            v = vv.verify_volume("C:", self._path(d))
            self.assertEqual(v.outcome, "ERROR")
            self.assertEqual(v.reason, "VOLUME_QUERY_FAILED")
            self.assertEqual(v.exit_code, vv.EXIT_ERROR)

    def test_t06_store_missing_is_deny(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL):
                v = vv.verify_volume("C:", self._path(d))
            self.assertEqual(v.outcome, "DENY")
            self.assertEqual(v.reason, "STORE_MISSING")

    def test_t07_store_corrupted_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._path(d)
            p.write_bytes(b"\x00\x01\x02 garbage")
            v = vv.verify_volume("C:", p)
            self.assertEqual(v.outcome, "ERROR")
            self.assertEqual(v.reason, "STORE_CORRUPTED")

    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t08_modified_store_payload_is_corrupt(self, _uid):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "C:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "WEAK",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint(UID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            raw = bytearray(_make_store_file(entries))
            raw[len(raw) // 2] ^= 0x01
            p = self._path(d)
            p.write_bytes(bytes(raw))
            v = vv.verify_volume("C:", p)
            self.assertEqual(v.outcome, "ERROR")
            self.assertEqual(v.reason, "STORE_CORRUPTED")

    @mock.patch("volume_verifier._query_bitlocker", return_value=BID_ORIGINAL)
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t09_registered_original_passes(self, _uid, _bid):
        with tempfile.TemporaryDirectory() as d:
            vv.register_volume("C:", self._path(d))
            v = vv.verify_volume("C:", self._path(d))
            self.assertEqual(v.outcome, "PASS")

    @mock.patch("volume_verifier._query_bitlocker", side_effect=[BID_ORIGINAL, BID_ORIGINAL])
    @mock.patch("volume_verifier._query_unique_id", side_effect=[UID_ORIGINAL, UID_COPY])
    def test_t10_copied_vhdx_is_deny(self, _uid, _bid):
        """Mirrors the identity-copy experiment: a copy has a different UniqueId."""
        with tempfile.TemporaryDirectory() as d:
            vv.register_volume("T:", self._path(d))
            v = vv.verify_volume("T:", self._path(d))
            self.assertEqual(v.outcome, "DENY")
            self.assertEqual(v.reason, "FINGERPRINT_MISMATCH")

    @mock.patch("volume_verifier._query_bitlocker", side_effect=[BID_ORIGINAL, BID_ORIGINAL])
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_t11_detach_attach_same_identity_passes(self, _uid, _bid):
        """Same UniqueId after detach/attach: identity is continuous."""
        with tempfile.TemporaryDirectory() as d:
            vv.register_volume("T:", self._path(d))
            v = vv.verify_volume("T:", self._path(d))
            self.assertEqual(v.outcome, "PASS")

    @mock.patch("volume_verifier._query_bitlocker", return_value=None)
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_not_registered_is_deny(self, _uid, _bid):
        with tempfile.TemporaryDirectory() as d:
            entries = {
                "D:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": None,
                    "identity_strength": "WEAK",
                    "platform": "win32",
                    "fingerprint": vv._fingerprint(UID_ORIGINAL),
                    "registered_at": "2026-08-11T00:00:00Z",
                }
            }
            self._path(d).write_bytes(_make_store_file(entries))
            v = vv.verify_volume("C:", self._path(d))
            self.assertEqual(v.outcome, "DENY")
            self.assertEqual(v.reason, "NOT_REGISTERED")


class TestLegacyMigration(unittest.TestCase):
    def test_v1_store_migrates_on_register(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "store.json"
            legacy = {
                "T:": {
                    "unique_id": UID_ORIGINAL,
                    "bitlocker_id": BID_ORIGINAL,
                    "fingerprint": vv._fingerprint_standard(UID_ORIGINAL, BID_ORIGINAL),
                }
            }
            p.write_text(json.dumps(legacy, indent=2), encoding="utf-8")
            with mock.patch("volume_verifier._query_bitlocker", return_value=None):
                with mock.patch("volume_verifier._query_unique_id", return_value=UID_COPY):
                    entry = vv.register_volume("U:", p)
            self.assertEqual(entry["identity_strength"], "WEAK")
            raw = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(raw["format_version"], vv.STORE_FORMAT_VERSION)
            migrated = vv._dpapi_unprotect(
                base64.b64decode(raw["entries_b64"].encode("ascii"))
            )
            migrated = json.loads(migrated.decode("utf-8"))
            self.assertEqual(migrated["T:"]["identity_strength"], "STANDARD")
            self.assertEqual(migrated["T:"]["fingerprint"],
                             vv._fingerprint_standard(UID_ORIGINAL, BID_ORIGINAL))
            self.assertEqual(migrated["U:"]["identity_strength"], "WEAK")

    def test_v1_store_rejected_on_verify(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "store.json"
            p.write_text(json.dumps({"T:": {"unique_id": UID_ORIGINAL}}), encoding="utf-8")
            with mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL):
                v = vv.verify_volume("T:", p)
            self.assertEqual(v.outcome, "ERROR")
            self.assertEqual(v.reason, "STORE_SCHEMA_MISMATCH")


class TestSeam(unittest.TestCase):
    @mock.patch("volume_verifier._platform", return_value="win32")
    def test_windows_dispatch(self, _):
        self.assertIsInstance(vv._get_source(), vv.WindowsVolumeSource)

    @mock.patch("volume_verifier._platform", return_value="linux")
    def test_linux_is_supported(self, _):
        source = vv._get_source()
        self.assertIsInstance(source, vv.LinuxVolumeSource)
        self.assertEqual(source.platform, "linux")

    @mock.patch("volume_verifier._platform", return_value="darwin")
    def test_macos_is_unsupported(self, _):
        self.assertIsInstance(vv._get_source(), vv.UnsupportedPlatformSource)

    @mock.patch("volume_verifier._query_bitlocker", return_value=BID_ORIGINAL)
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_windows_source_normalizes_observations(self, _uid, _bid):
        obs = vv.WindowsVolumeSource().get_observations("C:")
        self.assertEqual(obs.platform, "win32")
        self.assertEqual(obs.unique_id, UID_ORIGINAL)
        self.assertEqual(obs.bitlocker_id, BID_ORIGINAL)
        self.assertEqual(obs.identity_strength, "STANDARD")

    @mock.patch("volume_verifier._query_bitlocker", return_value=None)
    @mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL)
    def test_windows_source_weak_strength(self, _uid, _bid):
        obs = vv.WindowsVolumeSource().get_observations("C:")
        self.assertEqual(obs.identity_strength, "WEAK")


class TestHmacStore(unittest.TestCase):
    PASSPHRASE = "la-frase-secreta-de-prueba"

    def _store_path(self, d):
        return Path(d) / "store.json"

    def test_hmac_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            entries = {"C:": {"unique_id": UID_ORIGINAL, "bitlocker_id": None,
                              "identity_strength": "WEAK", "platform": "win32",
                              "fingerprint": vv._fingerprint(UID_ORIGINAL),
                              "registered_at": "2026-08-11T00:00:00Z"}}
            vv._save_store(self._store_path(d), entries, self.PASSPHRASE)
            self.assertEqual(
                vv._load_store(self._store_path(d), self.PASSPHRASE), entries)

    def test_wrong_passphrase_is_mac_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            vv._save_store(self._store_path(d), {"C:": self._weak_entry()}, self.PASSPHRASE)
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(self._store_path(d), "otra-frase")
            self.assertEqual(ctx.exception.reason, "STORE_MAC_MISMATCH")

    def test_tampered_payload_is_mac_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._store_path(d)
            vv._save_store(p, {"C:": self._weak_entry()}, self.PASSPHRASE)
            wrapper = json.loads(p.read_text(encoding="utf-8"))
            payload = bytearray(base64.b64decode(wrapper["payload_b64"]))
            payload[0] ^= 0x01
            wrapper["payload_b64"] = base64.b64encode(bytes(payload)).decode("ascii")
            p.write_text(json.dumps(wrapper), encoding="utf-8")
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(p, self.PASSPHRASE)
            self.assertEqual(ctx.exception.reason, "STORE_MAC_MISMATCH")

    def test_missing_passphrase_is_required_error(self):
        with tempfile.TemporaryDirectory() as d:
            vv._save_store(self._store_path(d), {"C:": self._weak_entry()}, self.PASSPHRASE)
            with self.assertRaises(vv.VerifierError) as ctx:
                vv._load_store(self._store_path(d))
            self.assertEqual(ctx.exception.reason, "STORE_PASSPHRASE_REQUIRED")

    def test_payload_is_visible_integrity_only(self):
        with tempfile.TemporaryDirectory() as d:
            entries = {"C:": self._weak_entry()}
            vv._save_store(self._store_path(d), entries, self.PASSPHRASE)
            wrapper = json.loads(self._store_path(d).read_text(encoding="utf-8"))
            self.assertEqual(wrapper["protection"], "HMAC_PASSPHRASE")
            self.assertEqual(wrapper["kdf"]["algorithm"], "PBKDF2-HMAC-SHA256")
            self.assertGreater(wrapper["kdf"]["iterations"], 0)
            payload = json.loads(base64.b64decode(wrapper["payload_b64"]))
            self.assertEqual(payload, entries)
            self.assertIn("mac_b64", wrapper)

    def test_hmac_register_then_verify(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("volume_verifier._query_bitlocker", return_value=BID_ORIGINAL):
                with mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL):
                    entry = vv.register_volume("C:", self._store_path(d), self.PASSPHRASE)
                    self.assertEqual(entry["identity_strength"], "STANDARD")
                    v = vv.verify_volume("C:", self._store_path(d), self.PASSPHRASE)
            self.assertEqual(v.outcome, "PASS")

    def test_hmac_verify_wrong_passphrase_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("volume_verifier._query_bitlocker", return_value=None):
                with mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL):
                    vv.register_volume("C:", self._store_path(d), self.PASSPHRASE)
                    v = vv.verify_volume("C:", self._store_path(d), "otra-frase")
            self.assertEqual(v.outcome, "ERROR")
            self.assertEqual(v.reason, "STORE_MAC_MISMATCH")

    def test_dpapi_store_migrates_to_hmac_with_passphrase(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._store_path(d)
            with mock.patch("volume_verifier._query_bitlocker", return_value=BID_ORIGINAL):
                with mock.patch("volume_verifier._query_unique_id", return_value=UID_ORIGINAL):
                    vv.register_volume("C:", p)
                    first = json.loads(p.read_text(encoding="utf-8"))
                    self.assertEqual(first["protection"], "DPAPI_USER")
                    vv.register_volume("C:", p, self.PASSPHRASE)
            wrapper = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(wrapper["protection"], "HMAC_PASSPHRASE")
            entries = json.loads(base64.b64decode(wrapper["payload_b64"]))
            self.assertEqual(entries["C:"]["identity_strength"], "STANDARD")

    def _weak_entry(self):
        return {"unique_id": UID_ORIGINAL, "bitlocker_id": None,
                "identity_strength": "WEAK", "platform": "win32",
                "fingerprint": vv._fingerprint(UID_ORIGINAL),
                "registered_at": "2026-08-11T00:00:00Z"}


class TestLinuxSource(unittest.TestCase):
    """Linux evidence source, evidence-backed (see evidence/linux-identity)."""

    def _store_path(self, d):
        return Path(d) / "store.json"

    @mock.patch("volume_verifier._platform", return_value="linux")
    def test_dispatch_returns_linux_source(self, _):
        self.assertIsInstance(vv._get_source(), vv.LinuxVolumeSource)

    @mock.patch("volume_verifier._query_linux_disk_serial", return_value=LINUX_DISK_SERIAL)
    @mock.patch("volume_verifier._query_linux_luks_uuid", return_value=LINUX_LUKS_UUID)
    @mock.patch("volume_verifier._query_linux_fs_uuid", return_value=LINUX_FS_UUID)
    def test_linux_source_standard_strength(self, _u, _b, _s):
        obs = vv.LinuxVolumeSource().get_observations(LINUX_MOUNTPOINT)
        self.assertEqual(obs.platform, "linux")
        self.assertEqual(obs.unique_id, LINUX_FS_UUID)
        self.assertEqual(obs.bitlocker_id, LINUX_LUKS_UUID)
        self.assertEqual(obs.disk_serial, LINUX_DISK_SERIAL)
        self.assertEqual(obs.identity_strength, "STANDARD")

    @mock.patch("volume_verifier._query_linux_disk_serial", return_value=None)
    @mock.patch("volume_verifier._query_linux_luks_uuid", return_value=None)
    @mock.patch("volume_verifier._query_linux_fs_uuid", return_value=LINUX_FS_UUID)
    def test_linux_source_weak_when_no_luks(self, _u, _b, _s):
        obs = vv.LinuxVolumeSource().get_observations(LINUX_MOUNTPOINT)
        self.assertEqual(obs.identity_strength, "WEAK")
        self.assertIsNone(obs.bitlocker_id)

    @mock.patch("volume_verifier._query_linux_fs_uuid",
                side_effect=vv.VerifierError("VOLUME_QUERY_FAILED", "no uuid"))
    def test_linux_source_fs_uuid_failure_raises(self, _u):
        with self.assertRaises(vv.VerifierError) as ctx:
            vv.LinuxVolumeSource().get_observations(LINUX_MOUNTPOINT)
        self.assertEqual(ctx.exception.reason, "VOLUME_QUERY_FAILED")

    @mock.patch("volume_verifier._query_linux_disk_serial", return_value=LINUX_DISK_SERIAL)
    @mock.patch("volume_verifier._query_linux_luks_uuid", return_value=LINUX_LUKS_UUID)
    @mock.patch("volume_verifier._query_linux_fs_uuid", return_value=LINUX_FS_UUID)
    @mock.patch("volume_verifier._platform", return_value="linux")
    def test_linux_register_then_verify_standard(self, _p, _u, _b, _s):
        with tempfile.TemporaryDirectory() as d:
            p = self._store_path(d)
            entry = vv.register_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            self.assertEqual(entry["identity_strength"], "STANDARD")
            self.assertEqual(entry["platform"], "linux")
            self.assertEqual(entry["disk_serial"], LINUX_DISK_SERIAL)
            wrapper = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(wrapper["protection"], "HMAC_PASSPHRASE")
            verdict = vv.verify_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            self.assertEqual(verdict.outcome, "PASS")
            self.assertEqual(verdict.strength, "STANDARD")

    @mock.patch("volume_verifier._query_linux_disk_serial", return_value=None)
    @mock.patch("volume_verifier._query_linux_luks_uuid", return_value=None)
    @mock.patch("volume_verifier._query_linux_fs_uuid", return_value=LINUX_FS_UUID)
    @mock.patch("volume_verifier._platform", return_value="linux")
    def test_linux_register_then_verify_weak(self, _p, _u, _b, _s):
        with tempfile.TemporaryDirectory() as d:
            p = self._store_path(d)
            vv.register_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            verdict = vv.verify_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            self.assertEqual(verdict.outcome, "PASS")
            self.assertEqual(verdict.strength, "WEAK")

    @mock.patch("volume_verifier._query_linux_disk_serial", return_value=LINUX_DISK_SERIAL)
    @mock.patch("volume_verifier._query_linux_luks_uuid", return_value=None)
    @mock.patch("volume_verifier._query_linux_fs_uuid", return_value=LINUX_FS_UUID)
    @mock.patch("volume_verifier._platform", return_value="linux")
    def test_linux_registered_luks_but_now_missing_is_denied(self, _p, _u, _b, _s):
        with tempfile.TemporaryDirectory() as d:
            p = self._store_path(d)
            with mock.patch("volume_verifier._query_linux_luks_uuid",
                            return_value=LINUX_LUKS_UUID):
                vv.register_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            verdict = vv.verify_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            self.assertEqual(verdict.outcome, "DENY")
            self.assertEqual(verdict.reason, "LUKS_METADATA_UNAVAILABLE")

    @mock.patch("volume_verifier._query_linux_disk_serial", return_value=LINUX_DISK_SERIAL)
    @mock.patch("volume_verifier._query_linux_luks_uuid", return_value=LINUX_LUKS_UUID)
    @mock.patch("volume_verifier._query_linux_fs_uuid", return_value="other-fs-uuid")
    @mock.patch("volume_verifier._platform", return_value="linux")
    def test_linux_fingerprint_mismatch_is_denied(self, _p, _u, _b, _s):
        with tempfile.TemporaryDirectory() as d:
            p = self._store_path(d)
            with mock.patch("volume_verifier._query_linux_fs_uuid",
                            return_value=LINUX_FS_UUID):
                vv.register_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            verdict = vv.verify_volume(LINUX_MOUNTPOINT, p, passphrase="k1")
            self.assertEqual(verdict.outcome, "DENY")
            self.assertEqual(verdict.reason, "FINGERPRINT_MISMATCH")


if __name__ == "__main__":
    unittest.main()
