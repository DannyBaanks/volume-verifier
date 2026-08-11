# Portable Metadata Reader — Experiment

Status: PROTOCOL + SPEC FACTS. Byte-hunt experiment pending an elevated
shell (this machine had no admin on 2026-08-11). No reader code written yet.

## Goal

Locate, at the **raw sector level**, the two observations Volume Verifier
uses, so that evidence acquisition can work without OS-specific APIs:

1. The `UniqueId` returned by PowerShell `Get-Volume`.
2. The BitLocker `Volume ID` shown by `manage-bde`.

A raw-sector reader is read-only by design: open block device/image, read
sectors, parse metadata. No unlock, no decrypt, no write, no mount.

## Constraints (policy)

- Read-only. No write path exists in the reader.
- No BitLocker unlock: the reader parses metadata that is visible without
  the credential (the FVE header is not encrypted; only the data region
  is). It never touches the encrypted data region.
- No decryption of content, no key derivation, no recovery assistance.

## Known facts (labeled as spec-based, not yet measured here)

- BitLocker FVE metadata is stored in the first sectors of the volume and
  is identifiable by the `FVE-FS` signature (Microsoft FVE spec, MS-FVE).
  The FVE metadata contains the volume GUID — the same value `manage-bde`
  prints as "Volume ID" (`{GUID}`). Spec-based; to be confirmed against a
  real BitLocker volume in the pending experiment.
- The `UniqueId` from `Get-Volume` (`\\?\Volume{...}\`) is Windows-assigned
  (observed to persist detach/attach and change on VHDX copy in the
  identity-copy experiment). Its raw location (VBR vs. `$VOLUME_*`
  attribute vs. GPT metadata) is **not determined yet** — that is the
  byte-hunt below.

## Protocol (pending, requires elevation)

1. Create a small throwaway VHDX in a temp dir:
   `New-VHD -Path <temp>\t.vhdx -SizeBytes 32MB -Fixed`
2. Mount + format (elevated):
   `Mount-VHD -Path <temp>\t.vhdx`; `Format-Volume -DriveLetter T`
3. Record `(Get-Volume -DriveLetter T).UniqueId`.
4. Dismount; the VHDX is a **file** — read its bytes with `dd`-equivalent
   (no elevation needed for the read itself) and locate the GUID bytes:
   search for the 16 raw bytes of the GUID (little-endian) across the
   first MBs; record offset + surrounding bytes.
5. Determine which structure hosts it (VBR/`$VOLUME`/partition entry).
6. Repeat for a BitLocker volume: create one with
   `Enable-BitLocker`/`manage-bde` on a throwaway VHDX (elevated), then
   search the raw image for `FVE-FS` and the Volume ID GUID; record
   offsets.
7. Expected outcome: a documented byte-offset map per observation, enabling
   a portable reader with configurable offsets and defensive parsing
   (malformed data → explicit error, mirroring v1.1 error handling).

## What depends on this experiment

- Reader implementation (Line 3) — only after offsets are measured.
- Linux/macOS portability of evidence acquisition (V2.0 roadmap) — the
  same offsets apply when opening the device or image file on any OS.

## Anti-bypass note

Even with the offsets known, the reader gains **no access to content**:
the encrypted data region requires the credential by BitLocker design.
The reader's output is metadata only, feeding the same WEAK/STANDARD
identity model.
