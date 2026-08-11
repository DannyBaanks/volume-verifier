# Volume Verifier 1.3

A deliberately minimal Windows utility that verifies that a volume belongs
to a previously registered system — based on **observable metadata**, not on
decryption.

> **Volume Verifier verifies continuity of observable volume metadata; it
> does not prove physical ownership of hardware.**

## What it does

- Reads the volume `UniqueId` via PowerShell `Get-Volume` and the BitLocker
  `Volume ID` via `manage-bde -status` (Windows).
- Computes a SHA-256 fingerprint of that metadata.
- On `--register`: stores the identity in a DPAPI-protected local store
  (`%USERPROFILE%\.volume_verifier\identity_store.json` by default).
- On verify: recomputes the fingerprint and prints a verdict with a reason
  code:

```
VERDICT: PASS
REASON: MATCHED_REGISTERED_IDENTITY
STRENGTH: STANDARD
```

```powershell
volume-verifier.exe --volume C: --register   # register C:
volume-verifier.exe --volume C:              # verify C:
```

## What it does NOT do

- It does **not** attempt to decrypt, unlock, or read the contents of any
  volume.
- It does not modify the volume or its BitLocker state.
- It does not contact any network service.
- It does not prove physical ownership of hardware.

## Identity model

| Strength | Observations | Meaning |
|---|---|---|
| WEAK | `UniqueId` only | The volume was not BitLocker-protected at registration time |
| STANDARD | `UniqueId` + BitLocker `Volume ID` | The volume was BitLocker-protected at registration time |

There is intentionally **no STRONG tier**: this project has no
hardware-backed attestation, so a STRONG claim would be dishonest.

- The identity strength is fixed at registration and cannot be silently
  upgraded or downgraded.
- A STANDARD identity cannot be verified if BitLocker metadata becomes
  unavailable: the result is `DENY / BITLOCKER_METADATA_UNAVAILABLE`, never
  a silent fallback to `UniqueId` only.
- A fingerprint is only comparable within the same platform; every stored
  identity carries its platform.

## Reason codes and exit codes

| Exit | Verdict | Reason | Meaning |
|---|---|---|---|
| 0 | PASS | `MATCHED_REGISTERED_IDENTITY` | Fingerprint matches the registered identity |
| 1 | DENY | `FINGERPRINT_MISMATCH` | Metadata present but fingerprint differs (e.g. a copy) |
| 1 | DENY | `NOT_REGISTERED` | Store exists but the volume was never registered |
| 1 | DENY | `STORE_MISSING` | No identity store found |
| 1 | DENY | `BITLOCKER_METADATA_UNAVAILABLE` | STANDARD identity, but no BitLocker Volume ID now |
| 1 | DENY | `BITLOCKER_QUERY_FAILED` | `manage-bde` failed (e.g. tool missing) |
| 1 | DENY | `INSUFFICIENT_PRIVILEGES` | `manage-bde` needs elevation |
| 2 | ERROR | `UNSUPPORTED_PLATFORM` | Not Windows |
| 2 | ERROR | `STORE_CORRUPTED` | Store cannot be decrypted or parsed |
| 2 | ERROR | `STORE_SCHEMA_MISMATCH` | Store format/protection incompatible (re-register) |
| 2 | ERROR | `STORE_PROTECTION_UNAVAILABLE` | DPAPI unavailable |
| 2 | ERROR | `STORE_PASSPHRASE_REQUIRED` | HMAC store needs `--passphrase` |
| 2 | ERROR | `STORE_MAC_MISMATCH` | Wrong passphrase or tampered HMAC store (same failure) |
| 2 | ERROR | `VOLUME_QUERY_FAILED` | `Get-Volume` returned no UniqueId / lsblk returned no UUID |
| 2 | ERROR | `BITLOCKER_METADATA_UNAVAILABLE` | STANDARD entry but BitLocker Volume ID now unreadable (win32) |
| 2 | ERROR | `LUKS_METADATA_UNAVAILABLE` | STANDARD entry but LUKS UUID now unreadable (linux) |
| 2 | ERROR | `INVALID_ARGS` | Invalid volume argument |

A failure to acquire evidence is **never** converted into a valid identity:
every failure produces an explicit reason code.

## Security model

- The identity store payload is encrypted with **Windows DPAPI**
  (`CryptProtectData`, per-user and per-machine scope).
- **Optional portable mode** (`--passphrase` or
  `VOLUME_VERIFIER_PASSPHRASE`): the store is protected with
  `HMAC_PASSPHRASE` — PBKDF2-HMAC-SHA256 integrity/authenticity only. The
  payload stays visible; no encryption, no keys derived beyond the
  passphrase. This mode travels between machines (the passphrase is the
  credential) and never stores or derives BitLocker keys.
- Writes are **atomic** (temp file + rename) to avoid corruption from
  interrupted writes.
- The store schema is validated strictly on every read: missing fields,
  wrong types, unknown strength, or a non-hex fingerprint → `STORE_CORRUPTED`.
- Legacy v1 plaintext stores are rejected on verify (`STORE_SCHEMA_MISMATCH`)
  and migrated automatically on the next `--register`.
- A MAC mismatch (wrong passphrase or tampering) is a single explicit
  reason: `STORE_MAC_MISMATCH`. The two are cryptographically
  indistinguishable.

**What DPAPI does and does not protect:**

- Protected: casual modification of the store by someone without the user's
  DPAPI context; accidental corruption being accepted as valid identity.
- NOT protected: an attacker with the same user's privileges (or full
  administrative control) can simply re-run `--register`. DPAPI is not a
  trust anchor and the store's per-user scope means an elevated run under a
  different account cannot read a store registered by the normal user.

## Requirements and conditions

- Windows 10/11 with BitLocker tooling available. Non-Windows platforms are
  rejected explicitly with `UNSUPPORTED_PLATFORM` (Linux/macOS evidence
  sources are a documented roadmap, not implemented).
- `manage-bde` queries may require an elevated shell; a failed query is an
  explicit error, never a silent WEAK fallback.
- A previous `--register` must exist; without a stored identity the verdict
  is `DENY`.

## Reproducibility

```
SOURCE ──▶ BUILD ──▶ SHA256 ──▶ EXECUTABLE
```

- `source/volume_verifier.py` — the full implementation.
- `build.ps1` — the exact build procedure (PyInstaller `--onefile`), which
  also prints the SHA-256 of the produced binary.
- `SHA256SUMS.txt` — real hashes of the published binary and of reference
  builds.
- The `.exe` is a convenience. Build it yourself and compare behavior.

**No confíes en la descripción. Reproduce el experimento.**

## Evidence

- `evidence/identity-copy-experiment/` — original experiment: a VHDX copy
  gets a different `UniqueId`; the verifier reports `PASS` for the original
  and `DENY` for the copy.
- `evidence/hardening-v1.1/` — hardening record: test results, build
  results, hashes, and the reviewer-issue matrix.

## Supported platforms

- **Windows** — `WindowsVolumeSource`. Evidence: PowerShell `Get-Volume`
  (NTFS volume UniqueId) + `manage-bde` (BitLocker Volume ID).
- **Linux** — `LinuxVolumeSource` (experimental, evidence-backed; verified
  against WSL2 Ubuntu 26.04). The Linux input is a **mountpoint**
  (e.g. `/mnt/data`), not a drive letter. Evidence: `findmnt` → device,
  `lsblk` (filesystem UUID = the NTFS UniqueId analog), and `cryptsetup
  luksUUID` on the resolved backing device (LUKS UUID = the BitLocker Volume
  ID analog). The disk SCSI/WWN serial is also collected as an extra
  observation (recorded; not part of the canonical fingerprint). No root,
  no `blkid`. Evidence: `evidence/linux-identity/`.
- **macOS** — explicitly NOT supported and NOT implemented. No genuine
  macOS hardware is available, and a macOS .iso inside a VM is malleable —
  no legitimate evidence could be produced. Adding macOS requires real
  hardware first (honest no-evidence stance).

### Strength semantics per platform

The core logic is identical across platforms; only the meaning of the
observations changes:

| Strength | Windows | Linux |
|----------|---------|-------|
| WEAK | FS UniqueId only | Filesystem UUID only (no LUKS) |
| STANDARD | FS UniqueId + BitLocker Volume ID | Filesystem UUID + LUKS UUID |

The Linux classification mirrors Windows: only volumes with encryption
metadata (LUKS) reach STANDARD. A disk copy preserves filesystem UUID and
disk serial (clone indistinguishable from original) — same conclusion as
Windows disk imaging; the verifier detects disk replacement and
filesystem reformat, not disk copying (documented, not assumed).

## Docs

- `docs/RECOVERY.md` — cross-OS recovery guide (legitimate credential
  only; identity verification and recovery are separate concerns).
- `ARCHITECTURE.md` — public contract and roadmap.
- `evidence/` — experiments and research (identity-copy, hardening v1.1,
  portable store research, portable reader protocol, TPM experiment).

## Roadmap (documented, not implemented)

| Line | Status | Never |
|---|---|---|
| Recovery guide | docs done (`docs/RECOVERY.md`) | never a bypass, never without credential |
| Portable store | research done (`evidence/portable-store/`) | never stores/derives keys |
| Portable metadata reader | protocol done (`evidence/portable-reader/`) | read-only, no unlock/decrypt/write |
| TPM identity | protocol done (`evidence/tpm-identity/`) | platform evidence only, never volume identity |

Policy: no component unlocks BitLocker, decrypts content, derives or stores
recovery keys, or provides bypass. Evidence before implementation; review
before publication.

## Build

```powershell
pip install -r requirements.txt
./build.ps1
# prints the SHA-256 of dist/volume-verifier.exe
```

## Tests

```powershell
python -m unittest discover tests -v
```

42 tests covering fingerprinting, schema validation, DPAPI round-trip,
tamper detection, atomic writes, legacy migration, and verdict/reason
classification (T1–T12 scenarios) with mocked evidence acquisition — no
real volume is modified or destroyed.

## License

MIT — see `LICENSE`.
