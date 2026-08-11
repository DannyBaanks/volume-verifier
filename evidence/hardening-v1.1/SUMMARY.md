# Hardening V1.1 — Summary

Date: 2026-08-11
Scope: Windows/Python hardening of Volume Verifier (source, store, CLI).
The V2.0 cross-platform roadmap is documented in ARCHITECTURE.md and is
NOT implemented (evidence per platform does not exist yet).

## Environment (recorded)

- Python 3.12.4 (64-bit, Windows)
- PyInstaller 6.22.0
- Previous published exe (v1.0) SHA-256: bd288f2eb770316a8aadde6d3ede64103d647d04a91da064d9008b34f55268b1

## Reviewer issue matrix

| # | Issue | Current behavior (pre-fix) | Impact | Fixability | Resolution |
|---|---|---|---|---|---|
| 1 | UniqueId treated as permanent/physical identity | Docs claimed metadata only, but no strength tiers, no platform scoping | Semantic confusion; readers could over-interpret PASS | PARTIALLY_FIXABLE (semantics + schema; the metadata itself is fundamental) | Explicit WEAK/STANDARD model, no STRONG tier, platform-scoped identities, PASS means "same registered logical instance" only |
| 2 | Fingerprint degrades to UniqueId when no BitLocker | Silent `sha256(unique_id)` fallback | WEAK identity used without disclosure | FIXABLE | Identity strength fixed at registration; STANDARD verify without BitLocker metadata -> DENY BITLOCKER_METADATA_UNAVAILABLE; WEAK used only when manage-bde explicitly reports no Volume ID |
| 3 | identity_store.json writable | Plaintext JSON, unvalidated, non-atomic writes | Tampering / corrupt data accepted as identity | PARTIALLY_FIXABLE (casual modification + tamper detection; full system compromise is FUNDAMENTAL) | DPAPI payload (per-user+machine), strict schema validation (STORE_CORRUPTED), atomic writes, legacy migration. Attacker with same user privileges can still re-run --register: documented |
| 4 | manage-bde privilege failure + silent fallback | Any failure returned None -> degraded fingerprint | Evidence-acquisition failure converted into identity | FIXABLE | Every query failure classified: INSUFFICIENT_PRIVILEGES (HRESULT 0x80070005 + text heuristics), BITLOCKER_QUERY_FAILED; registration blocked, no fallback |
| 5 | Windows-only not declared | Would run and misbehave on other platforms | Wrong diagnostics | FIXABLE | UNSUPPORTED_PLATFORM gate before any operation; single `_platform()` seam for V2.0 |

## Design decisions

1. Identity model: WEAK (UniqueId) / STANDARD (UniqueId + BitLocker Volume
   ID). No STRONG tier: no hardware-backed attestation exists in this model.
2. Store schema v2: versioned wrapper, DPAPI_USER protection, per-entry
   platform + strength + registered_at. Strict validation on every read.
3. Legacy v1 plaintext stores: rejected on verify (STORE_SCHEMA_MISMATCH),
   migrated deterministically on --register (strength derived from
   bitlocker_id presence, fingerprints recomputed and verified).
4. Exit codes: 0 PASS / 1 DENY / 2 ERROR. Every verdict carries a REASON.
5. External commands run with timeout (15s), -NonInteractive, stdout+stderr
   captured; classification is explicit, never swallowed.
6. Observed on this machine: `manage-bde -status C:` without elevation
   exits with code 2147749891 (0x80041003), classified as
   BITLOCKER_QUERY_FAILED (not access-denied; the 0x80070005 HRESULT
   mapping remains for builds that use it). Registration correctly blocked.

## What was NOT changed

- The project objective (verify continuity of observable metadata; never
  decryption/recovery/bypass/hardware attribution).
- The identity-copy experiment and its evidence (untouched, historical).
- No Linux/macOS code added. V2.0 remains a documented roadmap.

## Results

- tests/01-tests.txt — 42 tests, all pass.
- tests/02-build.txt — build.ps1 output.
- tests/03-hash-new-exe.txt — SHA-256 of the rebuild recorded as evidence.
- tests/04-cli-checks.txt — frozen-exe checks: --version 1.1.0, DENY
  STORE_MISSING (exit 1), register blocked BITLOCKER_QUERY_FAILED (exit 2),
  no store file created on failed register.

### Reproducibility observation

Two builds of the same source (same Python/PyInstaller) produced
c0f101a9cce5e43a81fceabbfb9bfed2802634f5372813b4d4a7eefc08fd6602 and
93adb153ce78e5de01af8a5df762a1c1586b2c83fbfd36c07998cb9b09eb3991.
PyInstaller embeds build metadata, so byte-for-byte rebuilds are not
expected; both builds showed identical behavior. This is the documented,
honest reproducibility claim: SOURCE -> BUILD -> behavior, not bit-identity.

## Known limitations (fundamental)

- A copy that preserved the registered metadata would PASS; Windows
  regenerates UniqueId on VHDX copies (observed), but that is OS behavior,
  not a cryptographic guarantee.
- DPAPI does not stop an attacker running as the same user (they can
  re-run --register). Full system compromise is out of scope by design.
- manage-bde privilege classification is best-effort (localized output can
  degrade INSUFFICIENT_PRIVILEGES to BITLOCKER_QUERY_FAILED; both are
  explicit).
- Registering a STANDARD identity requires elevation on most systems; a
  full register->verify PASS through the frozen exe requires an elevated
  shell and is covered in-process by the 42 tests.
