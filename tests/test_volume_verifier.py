import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))

from volume_verifier import (
    _extract_volume_id,
    _fingerprint,
    _load_store,
    _save_store,
    register_volume,
    verify_volume,
)


class TestExtractVolumeId(unittest.TestCase):
    def test_typical_line(self):
        out = "Volume ID:  {12345678-1234-1234-1234-1234567890AB}"
        self.assertEqual(_extract_volume_id(out), "{12345678-1234-1234-1234-1234567890AB}")

    def test_other_case(self):
        out = "volume id: {ABCDEF01-2222-3333-4444-555555555555}"
        self.assertEqual(_extract_volume_id(out), "{ABCDEF01-2222-3333-4444-555555555555}")

    def test_missing_line(self):
        self.assertIsNone(_extract_volume_id("Conversion Status: Full"))


class TestFingerprint(unittest.TestCase):
    def test_known_value(self):
        expected = hashlib.sha256(b"testguid").hexdigest()
        self.assertEqual(_fingerprint("TESTGUID"), expected)

    def test_normalises_to_lowercase(self):
        self.assertEqual(_fingerprint("ABCD"), _fingerprint("abcd"))


class TestStoreRoundTrip(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            store = {"C:": {"unique_id": "x", "bitlocker_id": None, "fingerprint": "abc"}}
            _save_store(path, store)
            loaded = _load_store(path)
            self.assertEqual(loaded["C:"], store["C:"])

    def test_missing_file(self):
        self.assertEqual(_load_store(Path("nope.json")), {})

    def test_corrupt_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            path.write_text("not json {")
            self.assertEqual(_load_store(path), {})

    def test_old_flat_entry_is_rejected_on_verify(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            path.write_text(json.dumps({"C:": "old-style-value"}))
            self.assertFalse(verify_volume("C:", path))


class TestVerificationLogic(unittest.TestCase):
    def test_unregistered_volume_is_deny(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            self.assertFalse(verify_volume("C:", path))

    def test_register_then_verify(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            ok = register_volume("C:", path)
            if not ok:
                self.skipTest("Get-Volume not available in this environment")
            self.assertTrue(verify_volume("C:", path))

    def test_fingerprint_logic_matches_store_entry(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            ok = register_volume("C:", path)
            if not ok:
                self.skipTest("Get-Volume not available in this environment")
            store = _load_store(path)
            entry = store["C:"]
            self.assertEqual(len(entry["fingerprint"]), 64)


if __name__ == "__main__":
    unittest.main()
