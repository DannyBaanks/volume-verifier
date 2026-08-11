#!/usr/bin/env bash
# LUKS UUID retrieval: mapper vs backing, with the mapper mounted (as in e2e).
set -e
WORK=/var/tmp/vv_lukstest2
mkdir -p "$WORK"; cd "$WORK"
dd if=/dev/zero of=crypt.img bs=1M count=32 status=none
echo -n 'clave-luks-123' > ckey
cryptsetup luksFormat --batch-mode --key-file ckey crypt.img
cryptsetup open --key-file ckey crypt.img vvcrypt4
mkfs.ext4 -q -F /dev/mapper/vvcrypt4
mkdir -p /mnt/vv_crypt4
mount /dev/mapper/vvcrypt4 /mnt/vv_crypt4

HEADER=$(cryptsetup luksUUID crypt.img)
echo "header_uuid=$HEADER"

SRC=$(findmnt -no SOURCE /mnt/vv_crypt4)
echo "findmnt_SOURCE=$SRC"

PK=$(lsblk -no PKNAME "$SRC" | tr -d ' ')
echo "lsblk_PKNAME=$PK   -> /dev/$PK"

echo "--- luksUUID on mapper (open) ---"
M=$(cryptsetup luksUUID "$SRC" || true)
echo "mapper_luksUUID=[$M]"

echo "--- luksUUID on backing (/dev/$PK) ---"
B=$(cryptsetup luksUUID "/dev/$PK" || true)
echo "backing_luksUUID=[$B]"

echo "--- conclusion ---"
[ "$M" = "$HEADER" ] && echo "MAIN" || echo "MAPPER_FAIL"
[ "$B" = "$HEADER" ] && echo "BACKING_OK" || echo "BACKING_FAIL"

umount /mnt/vv_crypt4
cryptsetup close vvcrypt4
rmdir /mnt/vv_crypt4