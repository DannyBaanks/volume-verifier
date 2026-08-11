# Portable Store — Research

Status: RESEARCH DONE + OPTION C IMPLEMENTED (v1.2, 2026-08-11).
Schema v2 gained the `HMAC_PASSPHRASE` protection variant, optional via
`--passphrase` / `VOLUME_VERIFIER_PASSPHRASE`. Default remains DPAPI_USER.
See results/01-hmac-tests.txt for the test evidence.

## Problem

The default identity store lives at `%USERPROFILE%\.volume_verifier\`
and is protected with Windows DPAPI. Two consequences:

1. **The store dies with the OS.** Reinstall or OS loss destroys the
   registered identities.
2. **DPAPI binds the store to one user on one machine.** `CryptProtectData`
   derives its key from the user profile and machine state. A store carried
   to another machine (or another account) cannot be decrypted.

## What the store actually contains (evidence)

Verified on 2026-08-11 with a real store produced by `_save_store`:

- wrapper fields only: `format_version`, `protection`, `platform`,
  `entries_b64` (DPAPI-encrypted payload).
- No 48-digit recovery-key pattern, no "password", no "recovery" text in
  the file (bytes verified).
- The payload (not visible in plaintext) contains per-volume entries:
  `unique_id`, `bitlocker_id`, `identity_strength`, `platform`,
  `fingerprint`, `registered_at`.

Key consequence: the store holds **no secret material**. Fingerprints are
SHA-256 hashes of metadata that is itself observable on the mounted volume.
The security property that matters for the store is **integrity** (a
modified store must not be accepted as valid identity), not confidentiality.

## Portability options

### A. Carry the DPAPI store as-is
- Will not decrypt on another machine/user (DPAPI scope).
- Cross-machine test still pending (needs a second machine); behavior is
  the documented Windows DPAPI contract.

### B. Store on the verified volume itself or on owner-carried media
- The CLI already accepts `--store <path>`; pointing it at a path on the
  volume (or a USB the owner carries) makes the identity travel with the
  data.
- The volume must already be unlocked by the owner's credential for the
  store to be readable — the verifier only **reads**; it never unlocks.
- Integrity: a plaintext portable store would be tamperable → needs an
  integrity mechanism (option C).

### C. Portable integrity without secrets
- PBKDF2-HMAC over the payload with an owner-chosen passphrase (stdlib:
  `hashlib.pbkdf2_hmac` + `hmac`). No AES (stdlib has none), so this is
  **integrity protection, not encryption** — acceptable because the store
  has no secrets.
- The passphrase is a credential the owner sets; it is never stored and it
  is not a BitLocker key of any kind.
- Store schema would grow a `"protection": "HMAC_PASSPHRASE"` variant
  alongside `"DPAPI_USER"`; each store keeps its protection type explicit
  (no silent downgrade — consistent with v1.1 hardening).

## Recommendation (proposal, not yet implemented)

1. Document B (portable `--store` usage) in TESTING.md — no code needed.
2. Implement C as an **optional** protection variant, default remains
   DPAPI. Verification of an HMAC store requires the owner's passphrase;
   failure → explicit `STORE_CORRUPTED`/wrong-passphrase error.
3. Never store, derive, or accept BitLocker keys or recovery material in
   any store format.

Decision needed from human review (José Daniel / Danny) before schema v2.1.
