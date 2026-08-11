#!/usr/bin/env bash
# Verify LUKS UUID retrieval: mapper vs backing device. Real evidence.
set -e
WORK=/var/tmp/vv_lukstest
mkdir -p "$WORK"; cd "$WORK"
dd if=/dev/zero of=crypt.img bs=1M count=32 status=none
echo -n 'clave-luks-123' > ckey
cryptsetup luksFormat --batch-mode --key-file ckey crypt.img
cryptsetup open --key-file ckey crypt.img vvcrypt3
mkfs.ext4 -q -F /dev/mapper/vvcrypt3

echo "--- luksUUID del header creado ---"
cryptsetup luksUUID crypt.img

echo "--- source via findmnt del mapper ---"
SRC=$(findmnt -no SOURCE /dev/mapper/vvcrypt3)
echo "source(mapper)=$SRC"

echo "--- lsblk del mapper (PKNAME = backing) ---"
lsblk -o NAME,PKNAME,TYPE,FSTYPE,UUID /dev/mapper/vvcrypt3

echo "--- luksUUID sobre mapper (abierto) ---"
cryptsetup luksUUID /dev/mapper/vvcrypt3; echo "exit=$?"

echo "--- luksUUID sobre backing (loop) ---"
PK=$(lsblk -no PKNAME /dev/mapper/vvcrypt3 | tr -d ' ')
echo "backing=/dev/$PK"
cryptsetup luksUUID "/dev/$PK"; echo "exit=$?"

echo "--- udevadm del mapper ---"
udevadm info --query=property --name=/dev/mapper/vvcrypt3 2>&1 | grep -E 'ID_FS|DM_UUID|DM_NAME|DM_VARIANT' || echo "(no fs/ dm attrs)"

cryptsetup close vvcrypt3