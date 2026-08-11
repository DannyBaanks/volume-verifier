# Recovery Guide (cross-OS)

**Scope:** help the legitimate owner regain access to their own
BitLocker-protected volume after OS loss, reinstall, or hardware change —
on Windows, Linux, or macOS.

**Scope limit:** this guide documents recovery with the **legitimate
credential only**. There is no bypass here, and there will never be one in
this project. If you do not have the credential, no tool (including Volume
Verifier) can or should help. That is BitLocker working as designed.

## Identity verification vs. recovery

These are two separate concerns, by design:

| | Volume Verifier | Recovery |
|---|---|---|
| Answers | "Is this the same volume I registered?" | "How do I open my volume?" |
| Credential | None (reads observable metadata) | BitLocker Recovery Key / password |
| Result | `PASS` / `DENY` + reason | Access to the volume |

Volume Verifier **never unlocks, never decrypts, never derives or stores
keys**. It only reads metadata. Recovery always requires the owner's
credential. The verifier cannot recover anything — and it must not be asked
to.

## The legitimate credential

- **BitLocker Recovery Key**: 48 digits, grouped in 8 groups of 6
  (`123456-123456-123456-123456-123456-123456-123456-123456`).
- **Password / PIN / startup key**: set during BitLocker activation.

The recovery key is generated when BitLocker is enabled. Typical storage
locations (must be **outside** the encrypted volume itself):

1. **Microsoft account** — account.microsoft.com → Devices → BitLocker
   recovery keys.
2. **Printed / saved to file / USB** — offered during activation.
3. **Organization (AD / Azure AD)** — if the device is managed.
4. If you never saved it, check your Microsoft account first. Without it,
   data on a fully BitLocker-protected volume cannot be recovered.

## Windows

### Automatic recovery

When Windows detects a protected volume during startup, it shows the
BitLocker recovery screen and asks for the recovery key. Enter it and
Windows unlocks the volume during boot.

### Manual unlock (volume already visible)

```powershell
# Unlock X: with the recovery key (run as administrator)
manage-bde -unlock X: -RecoveryPassword 123456-123456-123456-123456-123456-123456-123456-123456
```

### Manual unlock (OS reinstalled, data drive intact)

```powershell
# Discover the volume, then unlock
manage-bde -status
manage-bde -unlock D: -RecoveryPassword <48-digit key>
```

Best practice after unlock: copy the data out to a healthy drive before
doing anything else. An unlocked, previously-damaged volume should not be
written to before the data is safe.

## Linux

Use `dislocker` (available in most distro repositories). It reads the
BitLocker volume with the recovery key or password and presents the
cleartext as an image file you can mount **read-only**.

```bash
# Mount point for dislocker's output file
mkdir -p /mnt/bitlocker

# Read-only: -r flag. Replace /dev/sdb1 with your volume.
# The -p flag takes the recovery key (with dashes).
sudo dislocker -r -V /dev/sdb1 -p 123456-123456-123456-123456-123456-123456-123456-123456 -- /mnt/bitlocker

# The decrypted volume appears as an image file; mount it read-only:
sudo mkdir -p /mnt/recovered
sudo mount -o ro,loop /mnt/bitlocker/dislocker-file /mnt/recovered
```

Check the exact flag syntax with `man dislocker` on your distribution
(some versions differ). `-r` = read-only; omit it only if you understand
the risks of writing to a recovered volume.

## macOS

macOS has **no native BitLocker support**. The legitimate options are:

1. **Build dislocker from source** (same recovery-key flow as Linux), or
2. **A Windows or Linux VM** (or a live USB) with the volume attached
   (USB/SATA passthrough), then use the Windows/Linux procedures above.

All paths still require the BitLocker Recovery Key. macOS itself does not
bypass BitLocker.

## Rules for this guide

- Every path requires the owner's legitimate credential.
- No path unlocks, decrypts, or derives keys without that credential.
- Read-only access is preferred whenever possible.
- Volume Verifier plays no role in recovery; identity verification and
  recovery remain separate.
- If a future proposal would enable access without the credential: STOP,
  it is out of scope for this project.
