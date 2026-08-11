# Linux volume identity — Experiment (real data)

Status: DONE (2026-08-11). Environment: WSL2, Ubuntu 26.04 LTS,
kernel 6.18.33.1-microsoft-standard-WSL2, x86_64. The environment is a
genuine Linux kernel and userspace; its hypervisor is the WSL virtual-disk
stack. Scope limitation (honest): WSL2 ships no full systemd/udev session,
no partitioned (GPT) disk, and no serial hardware controller — a full VM or
bare metal would add partition-UUID evidence (PTUUID/PARTUUID) and
full-udev attributes. Nothing here is assumed; everything below was
observed and recorded in `raw/`.

## Method

| # | Step | Raw file |
|---|------|----------|
| 1 | Baseline collection, normal user | `raw/01-baseline.txt` |
| 2 | Baseline collection, root (`blkid` usable) | `raw/02-baseline-root.txt` |
| 3 | `udevadm info` for the boot disk (sda) | `raw/03-udevadm-sda.txt` |
| 4 | `udevadm info` for the data disk (sdd) | `raw/04-udevadm-sdd.txt` |
| 5 | Re-collection after `wsl --shutdown` + restart | `raw/05-after-reboot.txt` |
| 6 | LUKS container experiment (`cryptsetup luksFormat` on a loop file) | `raw/06-luks.txt` |
| 7 | Clone experiment: copied `ext4.vhdx`, imported as a second distro, identity compared | `raw/07-clone.txt` |
| 8 | Command behavior as non-root user; mountpoint→device mapping | `raw/08-as-user.txt` |

## Findings (all observed, not assumed)

1. **Filesystem UUID is stable across reboots.** The data disk (ext4)
   kept `985d4e88-aa64-40e5-9b8c-00527c683d68` through `wsl --shutdown` +
   restart. This is the direct Linux analog of the Windows NTFS volume
   UniqueId that Volume Verifier uses.
2. **Disk serial / WWN (SCSI VPD) is stable across reboots.** Same value
   (`60022480…`) before and after restart; exposed by `lsblk -dno SERIAL`,
   `/dev/disk/by-id/scsi-*`, `/dev/disk/by-id/wwn-*`, and udev
   `ID_SERIAL_SHORT` / `ID_WWN_WITH_EXTENSION`.
3. **A disk copy preserves identity completely (clone test).** The cloned
   distro reported the same serials, the same filesystem UUID, and the same
   hostname as the original. A copy is indistinguishable from the original
   by these observables — same conclusion as Windows disk imaging.
4. **Swap is ephemeral.** The swap volume received a NEW UUID and a NEW
   serial on every boot (`e8fe8399…` → `b6e06d28…`, serial `600224801125…`
   → `600224802601…`). Ephemeral volumes must never be registered as
   identity evidence.
5. **Device names (`sdX`) are NOT stable across sessions.** The same
   mountpoint resolved to `/dev/sdd` in one session and `/dev/sde` in
   another. Identity must never be keyed on device names.
6. **LUKS UUID is stable and independent of the block device.** A 64 MB
   LUKS container kept `2cdf8c67-1ae4-49fe-b57d-ad5a63d13758` across a
   reboot; `cryptsetup luksUUID`, `cryptsetup luksDump` and `blkid` agree.
   This is the direct Linux analog of the Windows BitLocker Volume ID that
   Volume Verifier uses for STANDARD strength.
7. **Root is not required for the usable commands.** As a normal user:
   `lsblk`, `udevadm`, and `findmnt` all return UUID/serial data. `blkid`
   returns nothing without root in this environment — the Linux source must
   not depend on `blkid`.
8. **WSL2 distro disks carry no filesystem UUID** (`/dev/sda`, `/dev/sdb`
   show ext4 without UUID). A consequence of WSL's provisioning; real
   distro installs (and the LUKS test) show UUIDs are the norm on
   formatted filesystems.

## Windows ↔ Linux analog table

| Concept | Windows (v1.x) | Linux (proposed, evidence-backed) |
|---------|----------------|-----------------------------------|
| Per-volume instance id | NTFS UniqueId | Filesystem UUID (`lsblk -no UUID`, `udevadm`) |
| Encryption metadata id | BitLocker Volume ID | LUKS UUID (`cryptsetup luksUUID`) |
| Physical disk id (extra) | not used | SCSI serial / WWN (`lsblk -dno SERIAL`) |
| Ephemeral volumes | — | swap: excluded (new UUID+serial every boot) |
| Names to avoid | drive letters are normalized | device names `sdX` (change across sessions) |

## Proposed Linux source contract (for a future implementation)

- Input: a mountpoint (e.g. `/mnt/data`), not a device name.
- Device resolution: `findmnt -no SOURCE <mountpoint>`.
- Observations: `fs_uuid` + `disk_serial` + `luks_uuid` (present only when
  the block device is LUKS; resolved via the mount chain, not assumed).
- Strength: `WEAK` = filesystem UUID alone; `STANDARD` = filesystem UUID +
  disk serial, or filesystem UUID + LUKS UUID (the BitLocker analog).
- No `blkid`, no root, no udev rules requirement.

## Open items (not faked)

- Full-VM pass (partitioned disk, systemd/udev, real SCSI controller) to
  confirm PTUUID/PARTUUID evidence and full udev attributes.
- macOS remains unimplemented: no genuine macOS hardware is available, and
  a macOS .iso inside a VM is malleable — no evidence would be legitimate.
