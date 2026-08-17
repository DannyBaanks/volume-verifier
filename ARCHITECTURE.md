# Architecture (public contract)

This document describes the architecture of the public **Volume Verifier**
product only. It is the PUBLIC product contract; it is not a description of
any larger internal ecosystem.

## PUBLIC / INTERNAL boundary

This repository is a public product. It must never become documentation of
internal architecture or internal vocabulary. Specifically:

**PUBLIC (belongs here):**
- The volume identity contract (observable metadata → fingerprint → verdict).
- Platform observations for the supported platform (Windows).
- Reason codes, exit codes, schema, tests, reproducibility.

**INTERNAL (never here):**
- Internal orchestration, internal abstractions, internal vocabulary.
- Internal implementation details of the wider ecosystem.
- Anything not approved for public release: STOP, human review, no automatic
  modifications.

Rule of thumb: if a name could be confused with internal vocabulary, the
public repo uses a plain, generic name instead — or does not introduce the
abstraction at all.

## Current structure (v1.4, Windows + Linux)

```
volume-verifier.exe / volume_verifier.py
├── platform seam         # PlatformVolumeSource.get_observations()
│   ├── WindowsVolumeSource        (functional, win32)
│   ├── LinuxVolumeSource          (functional, evidence-backed)
│   └── UnsupportedPlatformSource  (explicit, macOS - no hw)
├── evidence (Windows)    # PowerShell Get-Volume + manage-bde (read-only)
├── evidence (Linux)      # findmnt + lsblk + cryptsetup (read-only, no root)
├── identity              # strength tiers: WEAK | STANDARD
├── fingerprint           # SHA-256 of canonical observations
├── schema v2             # versioned, DPAPI_USER or HMAC_PASSPHRASE
├── store I/O             # atomic writes (temp + rename)
├── verdicts              # PASS / DENY / ERROR + REASON codes
└── CLI                   # exit 0 / 1 / 2
```

The platform seam is deliberately boring: one base contract
(`get_observations() -> normalized observations`), one functional Windows
source, one functional Linux source (evidence-backed), one explicit
unsupported source for macOS. This is a product-level abstraction for Volume
Verifier only; it does not reuse or reference any other architecture.

**Linux source implementation notes (real evidence):**

- Input: a mountpoint (e.g. `/mnt/data`), NOT a device name.
- `findmnt -no SOURCE <mountpoint>` → block device (may be a dm mapper).
- `lsblk -no UUID <device>` → filesystem UUID (analog of NTFS UniqueId).
- If device is `/dev/mapper/*`, `cryptsetup status <mapper>` →
  `device: /dev/loopN` → backing device.
- `cryptsetup luksUUID <backing>` → LUKS UUID (analog of BitLocker Volume
  ID). On plain block devices, query directly.
- `lsblk -dno SERIAL <disk>` of the parent disk → SCSI/WWN serial (extra
  observation, recorded but not part of fingerprint).
- No `blkid`, no root required. Evidence: `evidence/linux-identity/`.
- Strength: STANDARD iff LUKS UUID present (mirrors Windows: STANDARD iff
  BitLocker Volume ID present).

## V2.0 roadmap (documented, NOT implemented)

Volume Verifier can become cross-platform without changing the product
contract and without exposing internal architecture. The public shape is:

```
volume-verifier (product)
├── core (portable, platform-agnostic)
│   ├── identity model        # {platform, observations, strength, fingerprint}
│   ├── fingerprinting
│   ├── schema + store
│   ├── reason codes + verdicts
│   └── tests
└── platform sources (one per OS)
    ├── windows   # PowerShell Get-Volume + manage-bde (v1.x)
    ├── linux     # findmnt + lsblk + cryptsetup (v1.3, evidence-backed)
    ├── raw       # crypto/raw sector parsing (v1.4 --raw corroboration)
    └── macos     # diskutil/APFS metadata (planned — needs real hardware)
```

Planned public contract for a platform source (local, plain name):

```python
class PlatformVolumeSource:
    def get_observations(self, volume) -> VolumeIdentity: ...
```

Constraints for future cross-platform extensions:

1. **No fingerprint equivalence across platforms.** A fingerprint is
   meaningful only within its platform. The schema already carries a
   `platform` field per identity, so no migration is needed.
2. **Evidence per platform, claims per platform.** New platform sources are
   only added after real-machine experiments on those platforms produce
   evidence (the Windows VHDX experiment is not transferable).
3. **Strength tiers per platform.** WEAK/STANDARD may not mean the same
   thing on Linux/macOS; the public identity model keeps the tier explicit
   and never invents a STRONG tier.
4. **No internal vocabulary.** The public repo uses names like
   `PlatformVolumeSource` / `get_observations()` — local product names.
   Anything resembling internal vocabulary goes through the denylist review.
5. **Language is a later decision.** The core is plain Python and already
   portable; native language options (if ever needed) are a distribution
   decision, not an architecture one.

## Why macOS is not in v1.x

Evidence before narrative. The Windows adapter is proven by the
identity-copy experiment and by tests. The Linux adapter (v1.3) is backed
by real WSL2 Ubuntu 26.04 evidence (`evidence/linux-identity/`). macOS
observations have no experiments in this repository — no genuine macOS
hardware is available, and a macOS .iso inside a VM is malleable. The seam
(`PlatformVolumeSource`) is already in place so macOS can be added on top
when real evidence exists.

## Work lines and standing policy

Four documented work lines (see `evidence/` and `docs/RECOVERY.md`):

1. **Recovery guide** — documentation only. Every path requires the
   legitimate credential (recovery key / password). No bypass, ever.
2. **Portable store** — research done; identity records are hash-only (no
   secret material). A schema variant for portable integrity is proposed
   but NOT implemented (pending human review).
3. **Portable metadata reader** — read-only raw-sector parsing of FVE
   metadata / filesystem metadata. Protocol documented; byte-hunt
   experiment pending an elevated shell; no reader code yet.
4. **TPM identity** — separate experiment; platform evidence only, never
   volume identity; TPM-sealed data is explicitly NOT a recovery mechanism.

Standing policy (applies to every line, current and future):

- No component may unlock BitLocker, decrypt content, derive recovery
  keys, or store recovery keys by default.
- No component may provide a bypass; recovery always requires the
  legitimate credential. A proposal that enables access without it is
  out of scope, by definition.
- Read-only whenever technically possible.
- Experiment/evidence first; implementation after.
- Before publishing any component: publication review; on doubt, ask José
  Daniel / Danny.
