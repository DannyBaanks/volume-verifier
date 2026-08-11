#!/usr/bin/env bash
# Volume Verifier - Linux end-to-end (real WSL2). Produces real evidence only.
# No set -e: several steps intentionally produce non-zero exit codes.
SRC="/mnt/c/Development/ISyCo Git/Volume Verifier/source"
WORK=/var/tmp/vv_e2e
mkdir -p "$WORK"
cd "$WORK"

# pre-cleanup of leftovers from any previous run
umount /mnt/vv_crypt 2>/dev/null || true
cryptsetup close vvcrypt 2>/dev/null || true
umount /mnt/vv_plain 2>/dev/null || true

echo "===== [e2e] setup ====="
date -u +"%Y-%m-%dT%H:%M:%SZ"
uname -a | head -1

# ext4 plain (=> WEAK, has UUID)
dd if=/dev/zero of=plain.img bs=1M count=16 status=none
mkfs.ext4 -q -F plain.img
mkdir -p /mnt/vv_plain
mount -o loop plain.img /mnt/vv_plain
PDEV=$(findmnt -no SOURCE /mnt/vv_plain)
echo "plain mountpoint: $PDEV  (uuid $(lsblk -no UUID "$PDEV"))"

# LUKS + ext4 (=> STANDARD, has LUKS UUID + fs UUID)
dd if=/dev/zero of=crypt.img bs=1M count=32 status=none
echo -n 'clave-luks-123' > ckey
cryptsetup luksFormat --batch-mode --key-file ckey crypt.img
cryptsetup open --key-file ckey crypt.img vvcrypt
mkfs.ext4 -q -F /dev/mapper/vvcrypt
mkdir -p /mnt/vv_crypt
mount /dev/mapper/vvcrypt /mnt/vv_crypt
CDEV=$(findmnt -no SOURCE /mnt/vv_crypt)
BACKING=$(cryptsetup status "$CDEV" 2>/dev/null | sed -n 's/^[ ]*device:[ ]*//p' | tr -d ' ')
echo "crypt mountpoint: $CDEV (backing: $BACKING)"
echo "luks uuid (on backing): $(cryptsetup luksUUID "$BACKING" 2>/dev/null)"
echo "fs uuid:   $(lsblk -no UUID "$CDEV")"

VV="python3 \"$SRC/volume_verifier.py\""
STORE=$WORK/store.json
rm -f "$STORE"

echo "===== [e2e] register WEAK (plain ext4) ====="
eval "$VV --volume /mnt/vv_plain --store $STORE --register --passphrase k1" || echo "exit=$?"

echo "===== [e2e] verify WEAK (correct passphrase) ====="
eval "$VV --volume /mnt/vv_plain --store $STORE --passphrase k1"; echo "exit=$?"

echo "===== [e2e] verify WEAK (wrong passphrase) ====="
eval "$VV --volume /mnt/vv_plain --store $STORE --passphrase wrong"; echo "exit=$?"

echo "===== [e2e] register STANDARD (LUKS) ====="
eval "$VV --volume /mnt/vv_crypt --store $STORE --register --passphrase k1" || echo "exit=$?"

echo "===== [e2e] verify STANDARD (correct passphrase) ====="
eval "$VV --volume /mnt/vv_crypt --store $STORE --passphrase k1"; echo "exit=$?"

echo "===== [e2e] store wrapper ====="
python3 -c "import json,base64; w=json.load(open('$STORE')); print('protection:', w['protection']); print('keys:', list(json.loads(base64.b64decode(w['payload_b64'])).keys()))"

echo "===== [e2e] tamper: flip a payload byte ====="
python3 -c "
import json, base64
w=json.load(open('$STORE'))
p=bytearray(base64.b64decode(w['payload_b64'])); p[0]^=0x01
w['payload_b64']=base64.b64encode(bytes(p)).decode()
json.dump(w, open('$STORE','w'))
"
echo "(tampered) verify STANDARD:"
eval "$VV --volume /mnt/vv_crypt --store $STORE --passphrase k1"; echo "exit=$?"

echo "===== [e2e] cleanup ====="
umount /mnt/vv_crypt 2>/dev/null || true
cryptsetup close vvcrypt 2>/dev/null || true
umount /mnt/vv_plain 2>/dev/null || true
rmdir /mnt/vv_crypt /mnt/vv_plain 2>/dev/null || true
echo "done"
