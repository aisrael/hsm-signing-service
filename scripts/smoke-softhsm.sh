#!/bin/sh
# Check that the installed SoftHSM is the expected version and can sign with
# CKM_ECDSA_SHA256.
#
# Needs: softhsm2-util on PATH, PKCS11_MODULE set, pkcs11-tool (opensc), openssl.
# It uses a temporary token with throwaway PINs. It prints no PIN.
set -eu
set +x

. "$(dirname "$0")/softhsm.env"

: "${PKCS11_MODULE:?PKCS11_MODULE must be set}"

version=$(softhsm2-util --version | tr -d '[:space:]')
if [ "$version" != "$SOFTHSM_VERSION" ]; then
    echo "SoftHSM version is '$version'. Expected '$SOFTHSM_VERSION'." >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/tokens"
cat > "$work/softhsm2.conf" <<EOF
directories.tokendir = $work/tokens
objectstore.backend = file
log.level = ERROR
EOF
SOFTHSM2_CONF="$work/softhsm2.conf"
export SOFTHSM2_CONF

so_pin=$(openssl rand -hex 8)
user_pin=$(openssl rand -hex 8)

softhsm2-util --init-token --free --label smoke \
    --so-pin "$so_pin" --pin "$user_pin" > /dev/null

if ! pkcs11-tool --module "$PKCS11_MODULE" --list-mechanisms | grep -q 'ECDSA-SHA256'; then
    echo "The module does not list ECDSA-SHA256." >&2
    exit 1
fi

pkcs11-tool --module "$PKCS11_MODULE" --token-label smoke --login --pin "$user_pin" \
    --keypairgen --key-type EC:secp256r1 --label smoke-key --id 01 > /dev/null

printf 'smoke test payload' > "$work/payload"
pkcs11-tool --module "$PKCS11_MODULE" --token-label smoke --login --pin "$user_pin" \
    --sign --mechanism ECDSA-SHA256 --label smoke-key \
    --input-file "$work/payload" --output-file "$work/signature" > /dev/null

if [ ! -s "$work/signature" ]; then
    echo "The signature is empty." >&2
    exit 1
fi

echo "SoftHSM $version signs with ECDSA-SHA256."
