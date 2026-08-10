#!/bin/sh
set -eu

cargo_bin="${CARGO:-cargo}"

tree_raw="$(
    "$cargo_bin" tree \
    --workspace \
    --locked \
    --target all \
    -e normal,build \
    --no-dedupe \
    --prefix depth \
    --format '{p}|{f}'
)"
tree="$(
    printf '%s\n' "$tree_raw" |
        sed -E 's#^[0-9]+##; s# \(/[^)]*\)# (workspace)#' |
        sed '/^$/d' |
        sort -u
)"

metadata_raw="$("$cargo_bin" metadata --locked --format-version 1)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/wasabi-liquid-dependency-gate.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
printf '%s\n' "$tree_raw" >"$scratch/tree.txt"
printf '%s' "$metadata_raw" >"$scratch/metadata.json"
edges="$(
    python3 ci/canonicalize-dependency-edges.py \
        "$scratch/tree.txt" \
        "$scratch/metadata.json"
)"

printf '%s\n' "$tree" | awk -F '|' '
function has_feature(features, expected, count, position, item) {
    count = split(features, item, ",")
    for (position = 1; position <= count; position++) {
        if (item[position] == expected) {
            return 1
        }
    }
    return 0
}

function reject(message) {
    print message > "/dev/stderr"
    failed = 1
}

BEGIN {
    failed = 0
    bitcoin = 0
    digest = 0
    elements = 0
    miniscript = 0
    rand_count = 0
    secp = 0
    sha2 = 0
    zkp = 0
    zkp_sys = 0

    digest_prefix = "digest v0.11.3 (https://github.com/liquid-wasabi/traits.git?rev=113c5ba12876e332335e49d1462a2c96c9928006#"
    elements_prefix = "elements v0.27.0 (https://github.com/liquid-wasabi/rust-elements.git?rev=85b423a3cd69ea5409c0fbcfda1ccbced6a25d27#"
    zkp_prefix = "secp256k1-zkp v0.11.1 (https://github.com/liquid-wasabi/rust-secp256k1-zkp.git?rev=06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e#"
    zkp_sys_prefix = "secp256k1-zkp-sys v0.10.0 (https://github.com/liquid-wasabi/rust-secp256k1-zkp.git?rev=06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e#"
}

$1 ~ /^elements-miniscript v/ ||
$1 ~ /^elements v0\.25\./ ||
$1 ~ /^secp256k1-zkp v0\.11\.0([ (]|$)/ ||
$1 ~ /^serde_json v/ ||
$1 ~ /^simplicity-lang v/ ||
$1 ~ /^getrandom v/ {
    reject("denied dependency: " $0)
}

has_feature($2, "compiler") ||
has_feature($2, "getrandom") ||
has_feature($2, "global-context") ||
has_feature($2, "json-contract") ||
has_feature($2, "rand-std") ||
has_feature($2, "serde") {
    reject("denied dependency feature: " $0)
}

$1 ~ /^bitcoin v/ {
    bitcoin++
    if ($1 != "bitcoin v0.32.102" || $2 != "encoding,std") {
        reject("unexpected bitcoin capability: " $0)
    }
}

$1 ~ /^digest v/ {
    digest++
    if (index($1, digest_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "block-api,default,zeroize") {
        reject("unexpected digest capability: " $0)
    }
}

$1 ~ /^elements v/ {
    elements++
    if (index($1, elements_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "") {
        reject("unexpected Elements capability: " $0)
    }
}

$1 ~ /^miniscript v/ {
    miniscript++
    if ($1 != "miniscript v12.3.7" || $2 != "no-std") {
        reject("unexpected Miniscript capability: " $0)
    }
}

$1 ~ /^rand v/ {
    rand_count++
    if ($1 != "rand v0.8.7" || $2 != "") {
        reject("unexpected caller-randomness capability: " $0)
    }
}

$1 ~ /^secp256k1 v/ {
    secp++
    if ($1 != "secp256k1 v0.29.1" || $2 != "alloc,default,hashes,rand,std") {
        reject("unexpected secp256k1 capability: " $0)
    }
}

$1 ~ /^secp256k1-zkp v/ {
    zkp++
    if (index($1, zkp_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "actual-rand,hashes,rand,std") {
        reject("unexpected secp256k1-zkp capability: " $0)
    }
}

$1 ~ /^secp256k1-zkp-sys v/ {
    zkp_sys++
    if (index($1, zkp_sys_prefix) != 1 || $1 !~ /#[0-9a-f]+\)$/ || $2 != "std") {
        reject("unexpected secp256k1-zkp-sys capability: " $0)
    }
}

$1 ~ /^sha2 v/ {
    sha2++
    if ($1 != "sha2 v0.11.0" || $2 != "zeroize") {
        reject("unexpected SHA-256 capability: " $0)
    }
}

END {
    if (bitcoin != 1 || digest != 1 || elements != 1 || miniscript != 1 ||
        rand_count != 1 || secp != 1 || sha2 != 1 || zkp != 1 || zkp_sys != 1) {
        reject("required dependency capability count mismatch")
    }
    exit failed
}'

printf '%s\n' "$tree" | diff -u ci/expected-dependency-capabilities.txt -
printf '%s\n' "$edges" | diff -u ci/expected-dependency-edges.txt -
