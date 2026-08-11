# Volume Verifier

A deliberately minimal Windows utility that verifies that a BitLocker-protected
volume belongs to a previously registered system — based on **observable
metadata**, not on decryption.

## What it does

- Reads the volume `UniqueId` via PowerShell `Get-Volume` (and optionally the
  BitLocker `Volume ID` from `manage-bde -status`).
- Computes a SHA-256 fingerprint of that metadata.
- On `--register`: stores the fingerprint in a local JSON store
  (`%USERPROFILE%\.volume_verifier\identity_store.json` by default).
- On verify: recomputes the fingerprint and prints `VERDICT: PASS` or
  `VERDICT: DENY`.

```powershell
# Register a volume (example C:)
volume-verifier.exe --volume C: --register

# Verify a registered volume
volume-verifier.exe --volume C:
```

## What it does NOT do

- It does **not** attempt to decrypt, unlock, or read the contents of any
  volume.
- It does not modify the volume or its BitLocker state.
- It does not contact any network service.
- The only external commands it invokes are `Get-Volume` (PowerShell) and
  `manage-bde -status` (read-only status query).

## Requirements and conditions

- Windows with BitLocker tooling (`manage-bde` available; may require
  elevation for some queries).
- Python 3.8+ at runtime if you run from source (standard library only —
  no pip dependencies). The `.exe` needs nothing but Windows.
- A previous `--register` must exist for the volume before verification can
  pass; without a stored fingerprint the verdict is `DENY`.

## Reproducibility

The repository contains the source code used to build the executable:

```
SOURCE ──▶ BUILD ──▶ SHA256 ──▶ EXECUTABLE
```

- `source/volume_verifier.py` — the full implementation (231 lines).
- `build.ps1` — the exact build procedure (PyInstaller `--onefile`), which
  also prints the SHA-256 of the produced binary.
- `SHA256SUMS.txt` — hashes of the source files and of the published
  `volume-verifier.exe`.
- The `.exe` is provided as a convenience only.

For maximum transparency, users are encouraged to build the program
themselves from source and inspect the implementation. See `TESTING.md`
for the reproduction procedure.

**No confíes en la descripción. Reproduce el experimento.**

## Evidence

`evidence/identity-copy-experiment/` documents the experiment performed with
this tool:

- The `UniqueId` of a VHDX **persists** across detach/attach of the original
  volume.
- An exact copy of the VHDX receives a **different** `UniqueId`.
- The verifier reports `PASS` for the original volume after registration and
  `DENY` for the copied volume.

This demonstrates the precise claim the tool makes: it proves continuity of
the same logical volume instance, and detects that a volume is a copy. It
does not prove physical ownership of hardware.

## Limitations

- The identity is metadata, not hardware: a copied VHDX that kept its
  `UniqueId` would defeat verification at the metadata level (the experiment
  showed Windows generates a new one, but that is Windows behavior, not a
  cryptographic guarantee).
- BitLocker `Volume ID` is included only if the volume is encrypted and the
  query succeeds; otherwise the fingerprint relies on `UniqueId` alone.
- The local JSON store is plain text and not protected: an attacker with
  write access to the store can re-register. The tool verifies identity, it
  is not an anti-tamper system.

## Build

```powershell
# requires Python 3.8+ and PyInstaller
pip install -r requirements.txt
./build.ps1
# prints the SHA-256 of dist/volume-verifier.exe
```

## Tests

```powershell
python -m unittest discover tests -v
```

## License

MIT — see `LICENSE`.
