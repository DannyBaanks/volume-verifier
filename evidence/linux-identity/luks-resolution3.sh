#!/usr/bin/env bash
# Resolve LUKS backing device for an opened mapper (correct evidence-based approach).
set -e
WORK=/var/tmp/vv_lukstest3
mkdir -p "$WORK"; cd "$WORK"
dd if=/dev/zero of=crypt.img bs=1M count=32 status=none
echo -n 'clave-luks-123' > ckey
cryptsetup luksFormat --batch-mode --key-file ckey crypt.img
cryptsetup open --key-file ckey crypt.img vvcrypt5
mkfs.ext4 -q -F /dev/mapper/vvcrypt5
mkdir -p /mnt/vv_crypt5
mount /dev/mapper/vvcrypt5 /mnt/vv_crypt5

HEADER=$(cryptsetup luksUUID crypt.img)
echo "header_uuid=$HEADER"

SRC=$(findmnt -no SOURCE /mnt/vv_crypt5)
echo "findmnt_SOURCE=$SRC"

echo "--- cryptsetup status (slow-path, no root needed to read) ---"
cryptsetup status "$SRC" 2>&1 | grep -i 'device:'
BACKING=$(cryptsetup status "$SRC" 2>/dev/null | sed -n 's/^[ ]*device:[ ]*//p' | tr -d ' ')
echo "resolved_backing=[$BACKING]"

echo "--- luksUUID on backing ---"
B=$(cryptsetup luksUUID "$BACKING" || true)
echo "backing_luksUUID=[$B]"
[ "$B" = "$HEADER" ] && echo "BACKING_OK (approach works)" || echo "BACKING_FAIL"

echo "--- dmsetup deps alternative ---"
dmsetup deps "$SRC" 2>&1 | head -1

umount /mnt/vv_crypt5
cryptsetup close vvcrypt5
rmdir /mnt/vv_crypt5