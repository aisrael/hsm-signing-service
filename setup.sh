#!/bin/sh
# Initialize the example token and keys in softhsm2 for local development and testing.
# This script is idempotent, so it can be run multiple times without causing errors.

################################################################################
# Check for required environment variables and exit with an error if they are not set.

if [ -z "$HSM_TOKEN_LABEL" ]; then
    echo "Error: HSM_TOKEN_LABEL is not set. Please set it in your environment (or copy \`.envrc.example\` to \`.envrc\` and use \`direnv allow\`)" >&2
    exit 1
fi

if [ -z "$HSM_SO_PIN" ]; then
    echo "Error: HSM_SO_PIN is not set. Please set it in your environment (or copy \`.envrc.example\` to \`.envrc\` and use \`direnv allow\`)" >&2
    exit 1
fi

if [ -z "$HSM_PIN" ]; then
    echo "Error: HSM_PIN is not set. Please set it in your environment (or copy \`.envrc.example\` to \`.envrc\` and use \`direnv allow\`)" >&2
    exit 1
fi

################################################################################
# Check for required commands and exit with an error if they are not found.
BREW=$(command -v brew 2>/dev/null)
if [ -z "$BREW" ]; then
    echo "Error: Homebrew not found. Install Homebrew (https://brew.sh/) and try again." >&2
    exit 1
fi

SOFTHSM=$(command -v softhsm2-util 2>/dev/null)
if [ -z "$SOFTHSM" ]; then
    echo "Error: softhsm2-util not found. Install SoftHSM2 (\`brew install softhsm\`) and try again." >&2
    exit 1
fi

PKCS11_MODULE="${PKCS11_MODULE:-$("$BREW" --prefix softhsm)/lib/softhsm/libsofthsm2.so}"
if [ ! -f "$PKCS11_MODULE" ]; then
    echo "Error: SoftHSM2 PKCS#11 module not found at $PKCS11_MODULE. Check your SoftHSM2 installation." >&2
    exit 1
fi

PKCS_TOOL=$(command -v pkcs11-tool 2>/dev/null)
if [ -z "$PKCS_TOOL" ]; then
    echo "Error: pkcs11-tool not found. Install OpenSC (\`brew install opensc\`) and try again." >&2
    exit 1
fi

# Run pkcs11-tool with arguments
pkcs11() {
    "$PKCS_TOOL" --module "$PKCS11_MODULE" --token-label "$HSM_TOKEN_LABEL" --login --pin "$HSM_PIN" "$@"
}

# Succeeds if the token has an object with the label in the first argument. The
# optional second argument is an object type for `pkcs11-tool --type` (for
# example `privkey` or `secrkey`). Without it, objects of all types are searched.
has_object() {
    label="$1"
    if [ -n "${2:-}" ]; then
        set -- --type "$2"
    else
        set --
    fi
    pkcs11 --list-objects "$@" | grep -q -E 'label:[[:space:]]+'"$label"'[[:space:]]*$'
}

################################################################################
# Create the token and keys if they don't already exist.

set -eu

if "$SOFTHSM" --show-slots | grep -q -E '^[[:space:]]+Label:[[:space:]]+'"$HSM_TOKEN_LABEL"'[[:space:]]*$'; then
    echo "SoftHSM2 token already initialized. Skipping."
else
    echo "Initializing SoftHSM2 token..."
    "$SOFTHSM" --init-token --free --label "$HSM_TOKEN_LABEL" --so-pin "$HSM_SO_PIN" --pin "$HSM_PIN"
fi

if has_object "$HSM_TOKEN_LABEL"; then
    echo "Keys already generated. Skipping."
else
    echo "Generating keys..."
    pkcs11 --keypairgen --key-type EC:prime256v1 --id 01 --label "$HSM_TOKEN_LABEL" --usage-sign
fi

################################################################################
# Create the AES-256 key if it doesn't already exist.

AES_KEY_LABEL="${HSM_TOKEN_LABEL}-aes"

if has_object "$AES_KEY_LABEL" secrkey; then
    echo "AES key already generated. Skipping."
else
    echo "Generating the AES-256 key..."
    pkcs11 --keygen --key-type aes:32 --id 02 --label "$AES_KEY_LABEL" --sensitive --usage-decrypt
fi

# No secret key in the token may be extractable.
if pkcs11 --list-objects --type secrkey | grep 'Access:' | grep -v -q 'never extractable'; then
    echo "Error: a secret key in the token is extractable." >&2
    exit 1
fi
