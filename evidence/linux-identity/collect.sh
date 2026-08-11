#!/usr/bin/env bash
# Linux volume identity experiment - baseline collection (run inside Linux).
# Part of Volume Verifier evidence/linux-identity. Real data only.
set +e

OUT="${1:-/mnt/c/Development/ISyCo Git/Volume Verifier/evidence/linux-identity/raw}"

echo "===== [01] system ====="
date -u +"%Y-%m-%dT%H:%M:%SZ"
uname -a
cat /etc/os-release | head -5

echo "===== [02] block devices (lsblk full) ====="
lsblk -a -o NAME,KNAME,TYPE,FSTYPE,SIZE,UUID,PTUUID,PARTUUID,LABEL,MOUNTPOINT

echo "===== [03] lsblk disk attributes ====="
lsblk -d -o NAME,TYPE,SERIAL,WWN,MODEL,TRAN,ROTA

echo "===== [04] blkid ====="
blkid -o full 2>&1

echo "===== [05] /dev/disk/by-* ====="
ls -l /dev/disk/by-uuid 2>&1
ls -l /dev/disk/by-id 2>&1
ls -l /dev/disk/by-path 2>&1
ls -l /dev/disk/by-partuuid 2>&1

echo "===== [06] /sys/class/block ====="
for b in /sys/class/block/*; do
  n=$(basename "$b")
  echo "[$n] dev=$(cat "$b/dev" 2>/dev/null)"
  echo "[$n] sysfs=$(readlink -f "$b" 2>/dev/null)"
done

echo "===== [07] /proc/partitions ====="
cat /proc/partitions

echo "===== [08] mounts (findmnt) ====="
findmnt -o SOURCE,TARGET,FSTYPE,UUID,OPTIONS

echo "===== [09] df ====="
df -T

echo "===== [10] tool availability ====="
for t in blkid lsblk findmnt udevadm cryptsetup dmsetup; do
  printf "%s: " "$t"; command -v "$t" || echo "NOT INSTALLED"
done
