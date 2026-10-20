#!/bin/bash
#
# fetch-firmware.sh - copy the AMD firmware the compile-check kext embeds for both GPU families from a local
# linux-firmware checkout into src/navi48-bringup/firmware/ (gitignored; never commit it).
#
# This script does NOT use the network. Clone linux-firmware yourself first:
#     git clone https://gitlab.com/kernel-firmware/linux-firmware.git
#   (mirror: https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git)
#
# Usage:  tools/fetch-firmware.sh <path-to-linux-firmware-checkout>
#
# The blobs are AMD's, under AMD's redistribution licence (LICENSE.amdgpu in linux-firmware).
set -euo pipefail

if [ $# -ne 1 ] || [ ! -d "$1" ]; then
    echo "usage: $0 <path-to-linux-firmware-checkout>" >&2
    echo "clone it first: git clone https://gitlab.com/kernel-firmware/linux-firmware.git" >&2
    exit 2
fi
SRC="$1/amdgpu"
[ -d "$SRC" ] || { echo "fetch-firmware.sh: no amdgpu/ directory in $1" >&2; exit 2; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DST="$REPO/src/navi48-bringup/firmware"
mkdir -p "$DST"

# name  sha256 of the copy this project was developed against (a different linux-firmware
# revision may differ: a mismatch is a warning, not an error)
BLOBS="
gc_12_0_0_imu       aa15e5b3156bffc45e0c50bccbcd364fbd3f958531b695b7487a803d780b8328
gc_12_0_0_me        c288e326b9a5ccccac377455db3c25ace047a42a8e9e5a2239b5554dd2a9a9e7
gc_12_0_0_mec       9b0788eb46efa7d53a1d87cfe3031cd403ec1eef04314af2a55257883a4560d1
gc_12_0_0_pfp       cb6eb3ce40c79b0ada234b70ed038983627af78287afd7e5e26123dbcf7e79f8
gc_12_0_0_rlc       6436b582734a413456fff3d3c7195e71cc9e78a7ed31ee21c83ffd6fae1ad186
gc_12_0_0_uni_mes   309d60ad4a0210f8a68e27cae88beddb22b5ae900d70848b1e8ca0eac9d1decd
psp_14_0_2_sos      7b538448b57d4f9dd06b2eea90d4f86a16e65e3027cdecee8db71c2c5f1fa243
psp_14_0_2_ta       21b8898e56524240c19a1f834fcea3dde7d98c33044658a1641f0cb3c3b1bddd
sdma_7_0_0          beaafb53993a106edd392392d5896245ae2a957c6d0f495d0002eec72ad8ad38
smu_14_0_2          1b2054e3f710d1ab8dbdf6ff35914ad376b51caa6337831260c955add874b2ee
gc_12_0_1_imu       b3b301fb636efc77b63ce4d2ced0f90c851d03c19681852faa45598e6f5773fd
gc_12_0_1_me        fd5eb0f205a3bb7ec41f42e83a54bdc69151706b02bbee073fa775b8270e4bec
gc_12_0_1_mec       83fe5e7bffe639ec9771219cde5c9809689168f769b147c86dfd5a1ca991c1a2
gc_12_0_1_pfp       490bcd26a62e389b3f58acf5c087d324d2324b3188797ff6a36b7a6cdf1ca9ff
gc_12_0_1_rlc       6ba4459532246a5c415d3cb33c9b1248294e48f67b827e2accb292a8d1a5c0ec
gc_12_0_1_uni_mes   309d60ad4a0210f8a68e27cae88beddb22b5ae900d70848b1e8ca0eac9d1decd
psp_14_0_3_sos      28469a0857c813c54a0492423cdf0b0caf757428400036377e19c47e5af62478
psp_14_0_3_ta       fff8b0b56f21bf1d34c8d1fcf6cc903c2dbb5ef88eb06157c9f08baf95124883
sdma_7_0_1          73c29e1c1714ebc95d2221ba56e187910902891593010653bf9518937e414a59
smu_14_0_3          7624724231b0986b59f59705e7c854c482193f6b3b591ebdda58cb62af81c010
"

while read -r name want; do
    [ -n "$name" ] || continue
    if [ -f "$SRC/$name.bin" ]; then
        cp "$SRC/$name.bin" "$DST/$name.bin"
    elif [ -f "$SRC/$name.bin.zst" ] && command -v zstd >/dev/null 2>&1; then
        zstd -dqf -o "$DST/$name.bin" "$SRC/$name.bin.zst"
    else
        echo "MISSING  $name.bin (not in $SRC)" >&2
        exit 1
    fi
    got="$(shasum -a 256 "$DST/$name.bin" | awk '{print $1}')"
    if [ "$got" = "$want" ]; then echo "ok       $name.bin ($(wc -c < "$DST/$name.bin" | tr -d ' ') bytes)"
    else echo "DIFFERS  $name.bin (sha256 $got; developed against $want) - copied anyway"; fi
done <<< "$BLOBS"
if [ -f "$1/LICENSES/LICENSE.amdgpu" ]; then
    cp "$1/LICENSES/LICENSE.amdgpu" "$DST/LICENSE.amdgpu"
else
    cp "$1/LICENSE.amdgpu" "$DST/LICENSE.amdgpu"
fi
echo "copied into $DST"
