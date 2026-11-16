#!/bin/sh
# Build SoftHSM from source and install it.
#
# Usage: build-softhsm.sh PREFIX [SYSCONFDIR]
#
# The version and the checksum come from softhsm.env (same folder).
set -eu

if [ $# -lt 1 ]; then
    echo "usage: $0 PREFIX [SYSCONFDIR]" >&2
    exit 2
fi

. "$(dirname "$0")/softhsm.env"

prefix=$1
sysconfdir=${2:-$prefix/etc}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL -o "$work/softhsm.tar.gz" \
    "https://github.com/softhsm/SoftHSMv2/archive/refs/tags/${SOFTHSM_VERSION}.tar.gz"
# Stop on a mismatch, before anything is unpacked or run.
echo "${SOFTHSM_SHA256}  $work/softhsm.tar.gz" | sha256sum -c -

mkdir "$work/src"
tar -xzf "$work/softhsm.tar.gz" -C "$work/src" --strip-components=1
cd "$work/src"
sh autogen.sh
./configure \
    --prefix="$prefix" \
    --sysconfdir="$sysconfdir" \
    --with-crypto-backend=openssl \
    --disable-gost \
    --disable-static
make -j"$(nproc)"
make install
