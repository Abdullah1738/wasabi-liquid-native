#!/bin/sh
set -eu

cargo_bin="${CARGO:-cargo}"
repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
if [ "$(pwd -P)" != "$repository_root" ]; then
    echo "dependency capability gate must run from the repository root" >&2
    exit 1
fi

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
    plan = 0
    secp = 0
    sha2 = 0
    zkp = 0
    zkp_sys = 0
    wire = 0

    digest_prefix = "digest v0.11.3 (https://github.com/liquid-wasabi/traits.git?rev=113c5ba12876e332335e49d1462a2c96c9928006#"
    elements_prefix = "elements v0.27.0 (https://github.com/Abdullah1738/rust-elements.git?rev=5b8865f8061459f82dcb8a1cf476b7ba17b14193#"
    zkp_prefix = "secp256k1-zkp v0.11.1 (https://github.com/Abdullah1738/rust-secp256k1-zkp.git?rev=06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e#"
    zkp_sys_prefix = "secp256k1-zkp-sys v0.10.0 (https://github.com/Abdullah1738/rust-secp256k1-zkp.git?rev=06ea6e06da81d2e3a51733c8d9b5f6c5fa248c2e#"
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

$1 ~ /^wasabi-liquid-native-wallet-facts-wire v/ {
    wire++
    if ($1 != "wasabi-liquid-native-wallet-facts-wire v0.1.0 (workspace)" || $2 != "") {
        reject("unexpected wallet-facts wire capability: " $0)
    }
}

$1 ~ /^wasabi-liquid-native-ordinary-wallet-plan v/ {
    plan++
    if ($1 != "wasabi-liquid-native-ordinary-wallet-plan v0.1.0 (workspace)" || $2 != "") {
        reject("unexpected ordinary-wallet plan capability: " $0)
    }
}

END {
    if (bitcoin != 1 || digest != 1 || elements != 1 || miniscript != 1 ||
        plan != 1 || rand_count != 1 || secp != 1 || sha2 != 1 || zkp != 1 || zkp_sys != 1 || wire != 1) {
        reject("required dependency capability count mismatch")
    }
    exit failed
}'

printf '%s\n' "$tree" | diff -u ci/expected-dependency-capabilities.txt -
printf '%s\n' "$edges" | diff -u ci/expected-dependency-edges.txt -

python3 ci/check-wallet-facts-conformance.py "$repository_root"
conformance_inventory_hash="$(
    python3 -c 'import hashlib, pathlib; print(hashlib.sha256(pathlib.Path("contracts/wallet-facts/v1/nonlinkable-reference/vectors/SHA256SUMS").read_bytes()).hexdigest())'
)"
if [ "$conformance_inventory_hash" != "9bcdcf31ffe90e7a23ada162c61c71cfc84343ba1c190865e0ed34af8c7da933" ]; then
    echo "wallet-facts conformance inventory root mismatch" >&2
    exit 1
fi
conformance_parent_hash="$(
    python3 -c 'import hashlib, pathlib; print(hashlib.sha256(pathlib.Path("contracts/wallet-facts/v1/nonlinkable-reference/SHA256SUMS").read_bytes()).hexdigest())'
)"
if [ "$conformance_parent_hash" != "9a3d11662670d13e23ed248f2ae145c87a52739e2e3bb03f7628e4d12e147c63" ]; then
    echo "wallet-facts conformance parent root mismatch" >&2
    exit 1
fi

if [ "$(grep -Fxc 'sha2 = { version = "=0.11.0", default-features = false, features = ["zeroize"] }' crates/wallet-facts-wire/Cargo.toml)" -ne 1 ]; then
    echo "wallet-facts conformance test dependency mismatch" >&2
    exit 1
fi
python3 - "$repository_root" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
lock_path = root / "Cargo.lock"
baseline_path = root / "ci/expected-wallet-facts-conformance-lock-baseline.txt"
lock_bytes = lock_path.read_bytes()
baseline_text = baseline_path.read_text()
baseline_hash = "544ad20b54fe2e279a3074a5cfdeec49bd13752f358ffd0d67c0573546af326c"
wire_post_hash = "f30d4a8bfc6b43f61fb7eefdd0d86f866ebef815d5aa57cc2b5b3319023fcf25"
provider_post_hash = "5d105ea8138170cac5501f42d148855b9b9141d38b3c2b9532a246a4d5dc9ade"
plan_base_hash = "3287e329ab3d1b9868cb5eb3c39b1713a0d660b0dcd35100688bfb7c7a867178"
current_hash = "f5e471c6a9664d29e8c30ea44b0c6934d3be98c00d87d5ea45cb5843b717adde"
if baseline_text != baseline_hash + "\n":
    raise SystemExit("wallet-facts conformance lock baseline pin mismatch")
if hashlib.sha256(lock_bytes).hexdigest() != current_hash:
    raise SystemExit("wallet-facts conformance post-slice lock pin mismatch")

text = lock_bytes.decode("utf-8")
blocks = text.split("[[package]]\n")
plan_marker = 'name = "wasabi-liquid-native-ordinary-wallet-plan"\n'
plan_indexes = [index for index, block in enumerate(blocks) if plan_marker in block]
plan_block = """name = "wasabi-liquid-native-ordinary-wallet-plan"
version = "0.1.0"
dependencies = [
 "elements",
 "miniscript",
 "rand",
 "sha2",
 "static_assertions",
 "wasabi-liquid-native-address",
 "wasabi-liquid-native-ordinary-pset",
 "wasabi-liquid-native-wallet-facts",
 "zeroize",
]

"""
if len(plan_indexes) != 1 or blocks[plan_indexes[0]] != plan_block:
    raise SystemExit("ordinary-wallet plan lock package mismatch")
del blocks[plan_indexes[0]]
plan_base_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(plan_base_bytes).hexdigest() != plan_base_hash:
    raise SystemExit("ordinary-wallet plan lock reverse transform mismatch")

ordinary_marker = 'name = "wasabi-liquid-native-ordinary-pset"\n'
composer_marker = 'name = "wasabi-liquid-native-ordinary-wallet-pset"\n'
facts_marker = 'name = "wasabi-liquid-native-wallet-facts"\n'
wire_marker = 'name = "wasabi-liquid-native-wallet-facts-wire"\n'
sha_marker = 'name = "sha2"\nversion = "0.11.0"\n'
ordinary_indexes = [index for index, block in enumerate(blocks) if ordinary_marker in block]
composer_indexes = [index for index, block in enumerate(blocks) if composer_marker in block]
facts_indexes = [index for index, block in enumerate(blocks) if facts_marker in block]
wire_indexes = [index for index, block in enumerate(blocks) if wire_marker in block]
sha_blocks = [block for block in blocks if sha_marker in block]
if (
    len(ordinary_indexes) != 1
    or len(composer_indexes) != 1
    or len(facts_indexes) != 1
    or len(wire_indexes) != 1
    or len(sha_blocks) != 1
):
    raise SystemExit("wallet-facts conformance lock package multiplicity mismatch")

composer_block = """name = "wasabi-liquid-native-ordinary-wallet-pset"
version = "0.1.0"
dependencies = [
 "elements",
 "miniscript",
 "rand",
 "sha2",
 "static_assertions",
 "wasabi-liquid-native-address",
 "wasabi-liquid-native-ordinary-pset",
 "wasabi-liquid-native-wallet-facts",
]

"""
for marker in (composer_marker, facts_marker):
    indexes = [index for index, block in enumerate(blocks) if marker in block]
    entry = ' "wasabi-liquid-native-output-opening",\n'
    if len(indexes) != 1 or blocks[indexes[0]].count(entry) != 1:
        raise SystemExit("selected opening-provider lock edge multiplicity mismatch")
    blocks[indexes[0]] = blocks[indexes[0]].replace(entry, "", 1)

provider_post_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(provider_post_bytes).hexdigest() != provider_post_hash:
    raise SystemExit("selected opening-provider lock reverse transform mismatch")

if blocks[composer_indexes[0]] != composer_block:
    raise SystemExit("ordinary-wallet PSET lock package mismatch")
del blocks[composer_indexes[0]]

for marker, entry in (
    (ordinary_marker, ' "rand",\n'),
    (facts_marker, ' "wasabi-liquid-native-ordinary-pset",\n'),
):
    indexes = [index for index, block in enumerate(blocks) if marker in block]
    if len(indexes) != 1 or blocks[indexes[0]].count(entry) != 1:
        raise SystemExit("ordinary-wallet PSET lock edge multiplicity mismatch")
    blocks[indexes[0]] = blocks[indexes[0]].replace(entry, "", 1)

wire_post_bytes = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(wire_post_bytes).hexdigest() != wire_post_hash:
    raise SystemExit("ordinary-wallet PSET lock reverse transform mismatch")

wire_indexes = [index for index, block in enumerate(blocks) if wire_marker in block]
if len(wire_indexes) != 1:
    raise SystemExit("wallet-facts conformance lock package multiplicity mismatch")
wire_block = blocks[wire_indexes[0]]
entry = ' "sha2",\n'
if wire_block.count(entry) != 1:
    raise SystemExit("wallet-facts conformance lock edge multiplicity mismatch")
blocks[wire_indexes[0]] = wire_block.replace(entry, "", 1)
reconstructed = "[[package]]\n".join(blocks).encode("utf-8")
if hashlib.sha256(reconstructed).hexdigest() != baseline_hash:
    raise SystemExit("wallet-facts conformance lock reverse transform mismatch")
PY

wire_sources="crates/wallet-facts-wire/src/lib.rs crates/wallet-facts-wire/src/request.rs crates/wallet-facts-wire/src/response.rs crates/wallet-facts-wire/src/reader.rs crates/wallet-facts-wire/src/writer.rs"
if grep -En 'use (elements|secp256k1|sha2|bitcoin_hashes)(::|[[:space:]])|SecretKey|HashMap|HashSet|\.sort\(|\.sort_by\(|rand::|getrandom|no_mangle|export_name|extern[[:space:]]+"C"' $wire_sources; then
    echo "wallet-facts wire source capability escaped its reviewed boundary" >&2
    exit 1
fi
if [ "$(grep -h -c 'sort_unstable_by(|left, right| left.bytes.cmp(&right.bytes))' $wire_sources | awk '{ total += $1 } END { print total + 0 }')" -ne 1 ]; then
    echo "wallet-facts wire uniqueness call manifest mismatch" >&2
    exit 1
fi
if [ "$(grep -h -c 'validates_observed_public_output(' $wire_sources | awk '{ total += $1 } END { print total + 0 }')" -ne 2 ]; then
    echo "wallet-facts wire public-output validation call manifest mismatch" >&2
    exit 1
fi
if ! grep -Fq 'crate-type = ["rlib"]' crates/wallet-facts-wire/Cargo.toml ||
    grep -Fq 'cdylib' crates/wallet-facts-wire/Cargo.toml; then
    echo "wallet-facts wire crate type mismatch" >&2
    exit 1
fi

python3 ci/check-ordinary-wallet-plan-surface.py
python3 -c 'import importlib.util, pathlib; p = pathlib.Path("ci/check-ordinary-wallet-plan-surface.py"); s = importlib.util.spec_from_file_location("plan_surface", p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); m.validate_manifest_targets(); m.validate_dependency_authority_surface(m.production_text())'
python3 ci/test-ordinary-wallet-plan-surface.py
plan_sources="$(find crates/ordinary-wallet-plan/src -type f -name '*.rs' ! -name 'tests.rs' -print | sort)"
plan_lexical_source="$(
    python3 -c 'import importlib.util, pathlib; p = pathlib.Path("ci/check-ordinary-wallet-plan-surface.py"); s = importlib.util.spec_from_file_location("plan_surface", p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); print(m.strip_rust_comments(m.production_text()), end="")'
)"
if grep -En '^[[:space:]]*(test|doctest|doc)[[:space:]]*=[[:space:]]*false([[:space:]]|$)|^[[:space:]]*harness[[:space:]]*=|required-features[[:space:]]*=|\[\[test\]\]' crates/ordinary-wallet-plan/Cargo.toml; then
    echo "ordinary-wallet plan Cargo test or documentation target was disabled" >&2
    exit 1
fi
plan_crate_attributes="$(grep -h -E '^[[:space:]]*#!\[' $plan_sources)"
expected_plan_crate_attributes='#![forbid(unsafe_code)]
#![deny(missing_docs)]'
if [ "$plan_crate_attributes" != "$expected_plan_crate_attributes" ]; then
    echo "ordinary-wallet plan exact crate-level safety attributes changed" >&2
    exit 1
fi
if printf '%s\n' "$plan_lexical_source" | grep -En '#[[:space:]]*\[[[:space:]]*path([[:space:]=\]])|(^|[^[:alnum:]_])unsafe([^[:alnum:]_]|$)'; then
    echo "ordinary-wallet plan path attribute or unsafe syntax escaped its boundary" >&2
    exit 1
fi
plan_module_count="$(
    grep -h -E -c '^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?mod[[:space:]]+[[:alpha:]_][[:alnum:]_]*[[:space:]]*(;|\{)' $plan_sources |
        awk '{ total += $1 } END { print total + 0 }'
)"
plan_module_hash="$(
    sed -n '/^mod reader;/,/^mod tests;/p' crates/ordinary-wallet-plan/src/lib.rs |
        python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$plan_module_count" -ne 3 ] || [ "$plan_module_hash" != "9bf302755ec28c38c79a36f3f7945a47fe8d736d267b8373981852afa6949272" ]; then
    echo "ordinary-wallet plan exact module declarations or attributes changed" >&2
    exit 1
fi
plan_outer_attribute_hash="$(
    grep -h -E '^[[:space:]]*#\[' $plan_sources |
        python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$plan_outer_attribute_hash" != "51ebc7d7bb8f19ef7c51c0f6614e23c4f950a3caaf8a652588206492ea2c02df" ]; then
    echo "ordinary-wallet plan allowed outer attribute inventory changed" >&2
    exit 1
fi
plan_trait_impl_count="$(
    grep -h -E -c '^[[:space:]]*(unsafe[[:space:]]+)?impl.*[[:space:]]for[[:space:]]' $plan_sources |
        awk '{ total += $1 } END { print total + 0 }'
)"
if [ "$plan_trait_impl_count" -ne 42 ] || grep -En '^[[:space:]]+impl[[:space:]<]' $plan_sources; then
    echo "ordinary-wallet plan exact trait implementation syntax changed" >&2
    exit 1
fi
if ! cargo rustc \
        -p wasabi-liquid-native-ordinary-wallet-plan \
        --lib \
        --locked \
        --offline \
        -- \
        --emit=dep-info=- >"$scratch/ordinary-wallet-plan.dep-info" 2>/dev/null
then
    echo "ordinary-wallet plan compiler source closure derivation failed" >&2
    exit 1
fi
plan_compiled_sources="$(
    python3 -c 'import pathlib, sys; root = pathlib.Path.cwd().resolve(); found = set(); lines = pathlib.Path(sys.argv[1]).read_text().splitlines();
for line in lines:
    if ":" not in line: continue
    for token in line.split(":", 1)[1].split():
        path = pathlib.Path(token); path = path if path.is_absolute() else root / path
        if not path.exists(): continue
        path = path.resolve()
        try: found.add(path.relative_to(root).as_posix())
        except ValueError: found.add(path.as_posix())
print("\n".join(sorted(found)))' "$scratch/ordinary-wallet-plan.dep-info"
)"
expected_plan_compiled_sources='crates/ordinary-wallet-plan/src/lib.rs
crates/ordinary-wallet-plan/src/reader.rs
crates/ordinary-wallet-plan/src/writer.rs'
if [ "$plan_compiled_sources" != "$expected_plan_compiled_sources" ]; then
    echo "ordinary-wallet plan compiler source closure changed" >&2
    exit 1
fi
if printf '%s\n' "$plan_lexical_source" | grep -En 'wasabi_liquid_native_output_opening|wasabi_liquid_native_ordinary_wallet_pset|open_prepared_selected_owned_inputs|SelectedOutputOpeningProvider|SecretKey|rand::|getrandom|std[[:space:]]*::[[:space:]]*(process|env|thread|fs|net|time)|no_mangle|export_name|extern[[:space:]]*"C"|include(_str|_bytes)?[[:space:]]*!|AddressParams::ELEMENTS|LiquidAddressProfile::ElementsDefault'; then
    echo "ordinary-wallet plan source capability escaped its reviewed boundary" >&2
    exit 1
fi
plan_function_macro_count="$(
    printf '%s\n' "$plan_lexical_source" |
        grep -Eo '(^|[^[:alnum:]_])[[:alpha:]_][[:alnum:]_]*[[:space:]]*![[:space:]]*(\(|\{|\[)' |
        awk 'END { print NR + 0 }'
)"
plan_test_panic_count="$(
    printf '%s\n' "$plan_lexical_source" |
        grep -F -c 'panic!("test-only ordinary-wallet plan staging unwind");'
)"
plan_test_thread_local_count="$(
    printf '%s\n' "$plan_lexical_source" |
        grep -F -c 'thread_local! {'
)"
if [ "$plan_function_macro_count" -ne 9 ] || [ "$plan_test_thread_local_count" -ne 1 ] || [ "$plan_test_panic_count" -ne 1 ]; then
    echo "ordinary-wallet plan function-like macro surface is not the exact test-only hook" >&2
    exit 1
fi
if [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'wasabi_liquid_native_ordinary_pset' | awk 'END { print NR + 0 }')" -ne 1 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -F -c 'use wasabi_liquid_native_ordinary_pset::{ConfidentialOutput, ExplicitFee};')" -ne 1 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'ConfidentialOutput' | awk 'END { print NR + 0 }')" -ne 6 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -o 'ExplicitFee' | awk 'END { print NR + 0 }')" -ne 8 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -F -c 'ConfidentialOutput::from_address')" -ne 2 ] ||
    [ "$(printf '%s\n' "$plan_lexical_source" | grep -F -c 'ExplicitFee::new')" -ne 2 ]; then
    echo "ordinary-wallet plan ordinary-pset exact API inventory changed" >&2
    exit 1
fi
if printf '%s\n' "$plan_lexical_source" | grep -En '(^|[^[:alnum:]_])(prepare_ordinary_pset|SpendableInput|PreparedOrdinaryPset|BlindedOrdinaryPset|PsetConstructionError|OrdinaryPsetBlindingError|OrdinaryP2wpkhSigner|SignedOrdinaryPset|OrdinarySigningFailure|FinalizedOrdinaryTransaction|PartiallySignedTransaction|sign_and_finalize|serialize_for_broadcast|serialize_sensitive|as_pset|blind)([^[:alnum:]_]|$)'; then
    echo "ordinary-wallet plan ordinary-pset capability escaped its boundary" >&2
    exit 1
fi
for required_call in \
    'prepare_selected_owned_inputs(' \
    'SelectedOutputBatch::new(' \
    'ConfidentialOutput::from_address(' \
    'ExplicitFee::new(' \
    'ConfidentialLiquidAddress::parse(' \
    'preflight_frame(frame, expected_source_epoch)'
do
    expected_count=1
    case "$required_call" in
        'ConfidentialOutput::from_address('|\
        'ExplicitFee::new('|\
        'ConfidentialLiquidAddress::parse('|\
        'preflight_frame(frame, expected_source_epoch)') expected_count=2 ;;
    esac
    if [ "$(grep -h -F -c "$required_call" $plan_sources | awk '{ total += $1 } END { print total + 0 }')" -ne "$expected_count" ]; then
        echo "ordinary-wallet plan source call manifest mismatch" >&2
        exit 1
    fi
done
plan_preflight_source="$(
    awk '
        /^fn preflight_frame/ { capture = 1 }
        /^fn parse_owned/ { capture = 0 }
        capture { print }
    ' crates/ordinary-wallet-plan/src/lib.rs
)"
if printf '%s\n' "$plan_preflight_source" | grep -En 'Vec|String|Address|AssetId|SelectedOutputBatch|prepare_selected_owned_inputs|deserialize|to_vec|with_capacity|\.reserve\(|\.reserve_exact\(|collect'; then
    echo "ordinary-wallet plan structural preflight allocated or invoked semantics" >&2
    exit 1
fi
plan_preflight_hash="$(
    printf '%s\n' "$plan_preflight_source" |
        python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$plan_preflight_hash" != "483952c5fa1f9aea89585f317551c728513241c8800aeaf1fca4d0e534d6ea28" ]; then
    echo "ordinary-wallet plan structural preflight source hash mismatch" >&2
    exit 1
fi
if ! grep -Fq 'crate-type = ["rlib"]' crates/ordinary-wallet-plan/Cargo.toml ||
    grep -Fq 'cdylib' crates/ordinary-wallet-plan/Cargo.toml; then
    echo "ordinary-wallet plan crate type mismatch" >&2
    exit 1
fi

helper_source="$(
    awk '
        /^pub fn validates_observed_public_output/ { capture = 1 }
        /^\/\/\/ The public derivation branch/ { capture = 0 }
        capture { print }
    ' crates/wallet-facts/src/lib.rs
)"
if printf '%s\n' "$helper_source" | grep -En 'Vec|Box|format!|SecretKey|Transaction|Pset|rand|std::|unwrap|expect|panic!'; then
    echo "wallet-facts public-output helper call manifest escaped its reviewed boundary" >&2
    exit 1
fi
helper_source_hash="$(
    printf '%s\n' "$helper_source" |
        python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$helper_source_hash" != "c9154cfc0437b6563964de67e68ed5157f33570e3ea3c6b8618bd253ceba0ed9" ]; then
    echo "wallet-facts public-output helper source hash mismatch" >&2
    exit 1
fi
for required_call in \
    'PublicKey::from_slice(spend_public_key)' \
    'PublicKey::from_slice(blinding_public_key)' \
    'hash160::Hash::hash(spend_public_key)'
do
    if ! printf '%s\n' "$helper_source" | grep -Fq "$required_call"; then
        echo "wallet-facts public-output helper call manifest mismatch" >&2
        exit 1
    fi
done

uniqueness_source="$(
    awk '
        /^fn validate_source_uniqueness/ { capture = 1 }
        /^fn validate_output/ { capture = 0 }
        /^fn validate_response_uniqueness/ { capture = 1 }
        /^fn construct_response/ { capture = 0 }
        capture { print }
    ' crates/wallet-facts-wire/src/response.rs
)"
for required_line in \
    'Vec::with_capacity(inputs.len())' \
    'Vec::with_capacity(input_count)' \
    'for input in inputs' \
    'scratch.0.push(ScopedWireOutPoint::new(input))' \
    'scratch.0.push(ScopedWireOutPoint::new_parts(' \
    '.sort_unstable_by(|left, right| left.bytes.cmp(&right.bytes))' \
    '.windows(2)' \
    '.any(|pair| pair[0].bytes == pair[1].bytes)'
do
    if [ "$(printf '%s\n' "$uniqueness_source" | grep -F -c "$required_line")" -ne 1 ]; then
        echo "wallet-facts wire uniqueness source manifest mismatch" >&2
        exit 1
    fi
done
uniqueness_source_hash="$(
    printf '%s\n' "$uniqueness_source" |
        python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
)"
if [ "$uniqueness_source_hash" != "953e88c1fa78a5b83b85874b9c1e6a1706324595ec05a0167987ca69fe47f2ff" ]; then
    echo "wallet-facts wire uniqueness source hash mismatch" >&2
    exit 1
fi
if printf '%s\n' "$uniqueness_source" | grep -En 'HashMap|HashSet|Vec::new|vec!|Vec::from|VecDeque|LinkedList|BTree|Box|String|collect|to_vec|reserve|resize|\.sort\(|\.sort_by\(|sort_by_key|sort_unstable_by_key|slice::sort|while[[:space:]]|loop[[:space:]]*\{|enumerate|position|binary_search|dedup|\.find\(|\.filter\(|\.fold\(|\.all\(|\.chunks\('; then
    echo "wallet-facts wire uniqueness source manifest escaped its reviewed path" >&2
    exit 1
fi

if ! compiler_cargo_bin="$(command -v cargo)"; then
    echo "wallet-facts compiler and artifact gates require Cargo 1.96.0" >&2
    exit 1
fi
cargo_version="$("$compiler_cargo_bin" --version 2>/dev/null)"
case "$cargo_version" in
    cargo\ *)
        case "$cargo_version" in
            cargo\ 1.96.0\ *) ;;
            *)
                echo "wallet-facts compiler call manifests require Cargo 1.96.0" >&2
                exit 1
                ;;
        esac
        rustc_version="$(
            "$compiler_cargo_bin" rustc \
                --quiet \
                -p wasabi-liquid-native-wallet-facts-wire \
                --lib \
                --locked \
                --offline \
                -- \
                --version 2>/dev/null
        )"
        case "$rustc_version" in
            rustc\ 1.96.0\ *) ;;
            *)
                echo "wallet-facts compiler call manifests require Rust 1.96.0" >&2
                exit 1
                ;;
        esac
        "$compiler_cargo_bin" rustc \
            --quiet \
            -p wasabi-liquid-native-wallet-facts \
            --lib \
            --release \
            --locked \
            --offline \
            -- \
            --emit=mir \
            -o "$scratch/wallet-facts.mir"
        helper_mir_file="$(find "$scratch" -maxdepth 1 -name 'wallet-facts-*.mir' -print | head -1)"
        if [ -z "$helper_mir_file" ]; then
            echo "wallet-facts helper MIR was not produced" >&2
            exit 1
        fi
        helper_mir="$(
            awk '
                /^fn validates_observed_public_output/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$helper_mir_file"
        )"
        if printf '%s\n' "$helper_mir" | grep -En 'alloc::alloc|exchange_malloc|RawVec|Vec<|Box<|String|begin_panic|panic_|assert\('; then
            echo "wallet-facts public-output helper MIR escaped its nonallocating call manifest" >&2
            exit 1
        fi
        if [ "$(printf '%s\n' "$helper_mir" | grep -F -c 'secp256k1_ec_pubkey_parse')" -ne 2 ] ||
            [ "$(printf '%s\n' "$helper_mir" | grep -F -c 'Hash160::hash')" -ne 1 ] ||
            [ "$(printf '%s\n' "$helper_mir" | grep -F -c 'raw_eq::<[u8; 20]>')" -ne 1 ] ||
            [ "$(printf '%s\n' "$helper_mir" | awk '/ -> \[return:/ { count++ } END { print count + 0 }')" -ne 4 ]; then
            echo "wallet-facts public-output helper compiler call manifest mismatch" >&2
            exit 1
        fi

        "$compiler_cargo_bin" rustc \
            --quiet \
            -p wasabi-liquid-native-wallet-facts-wire \
            --lib \
            --locked \
            --offline \
            -- \
            -C opt-level=0 \
            --emit=mir="$scratch/wallet-facts-wire.mir"
        if [ ! -f "$scratch/wallet-facts-wire.mir" ]; then
            echo "wallet-facts wire MIR was not produced" >&2
            exit 1
        fi
        input_uniqueness_mir="$(
            awk '
                /^fn validate_inputs_unique/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$scratch/wallet-facts-wire.mir"
        )"
        scratch_uniqueness_mir="$(
            awk '
                /^fn scratch_is_unique/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$scratch/wallet-facts-wire.mir"
        )"
        decoder_uniqueness_mir="$(
            awk '
                /^fn validate_response_uniqueness/ { capture = 1 }
                capture { print }
                capture && /^}/ { exit }
            ' "$scratch/wallet-facts-wire.mir"
        )"
        for required_call in \
            'Vec::<ScopedWireOutPoint>::with_capacity' \
            'Vec::<ScopedWireOutPoint>::push' \
            'ScopedWireOutPoint::new::<T>' \
            'scratch_is_unique'
        do
            if [ "$(printf '%s\n' "$input_uniqueness_mir" | grep -F -c "$required_call")" -ne 1 ]; then
                echo "wallet-facts input uniqueness compiler call manifest mismatch" >&2
                exit 1
            fi
        done
        for required_call in \
            'sort_unstable_by::<' \
            '>::windows' \
            ' as Iterator>::any::<'
        do
            if [ "$(printf '%s\n' "$scratch_uniqueness_mir" | grep -F -c "$required_call")" -ne 1 ]; then
                echo "wallet-facts scratch uniqueness compiler call manifest mismatch" >&2
                exit 1
            fi
        done
        for required_call in \
            'Vec::<ScopedWireOutPoint>::with_capacity' \
            'Vec::<ScopedWireOutPoint>::push' \
            'ScopedWireOutPoint::new_parts' \
            'scratch_is_unique' \
            'checked_multiply'
        do
            if [ "$(printf '%s\n' "$decoder_uniqueness_mir" | grep -F -c "$required_call")" -ne 1 ]; then
                echo "wallet-facts decoder uniqueness compiler call manifest mismatch" >&2
                exit 1
            fi
        done
        uniqueness_mir="$input_uniqueness_mir
$scratch_uniqueness_mir
$decoder_uniqueness_mir"
        if printf '%s\n' "$uniqueness_mir" | grep -En 'RawVec|alloc::alloc|exchange_malloc|VecDeque|LinkedList|BTree|HashMap|HashSet|Vec::<ScopedWireOutPoint>::(reserve|resize|extend|from)|sort_by_key|sort_unstable_by_key|slice::<.*>::sort::<|binary_search|dedup|\.chunks\('; then
            echo "wallet-facts uniqueness compiler call manifest escaped its reviewed path" >&2
            exit 1
        fi

        "$compiler_cargo_bin" build \
            --quiet \
            -p wasabi-liquid-native-wallet-facts-wire \
            --lib \
            --release \
            --locked \
            --offline
        "$compiler_cargo_bin" build \
            --quiet \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --lib \
            --release \
            --locked \
            --offline
        target_directory="$(
            python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["target_directory"])' \
                "$scratch/metadata.json"
        )"
        wire_archive="$target_directory/release/libwasabi_liquid_native_wallet_facts_wire.rlib"
        plan_archive="$target_directory/release/libwasabi_liquid_native_ordinary_wallet_plan.rlib"
        if [ ! -f "$wire_archive" ]; then
            echo "wallet-facts wire release archive is missing" >&2
            exit 1
        fi
        if [ ! -f "$plan_archive" ]; then
            echo "ordinary-wallet plan release archive is missing" >&2
            exit 1
        fi
        if ! command -v ar >/dev/null 2>&1 || ! command -v nm >/dev/null 2>&1; then
            echo "archive or symbol inspection tool is unavailable" >&2
            exit 1
        fi
        if ! rustc_bin="$(command -v rustc)"; then
            echo "wallet-facts symbol inspection requires Rust 1.96.0" >&2
            exit 1
        fi
        case "$("$rustc_bin" --version 2>/dev/null)" in
            rustc\ 1.96.0\ *) ;;
            *)
                echo "wallet-facts symbol inspection requires Rust 1.96.0" >&2
                exit 1
                ;;
        esac
        symbol_checker="$scratch/check-rust-rlib-symbols"
        RUSTC_BOOTSTRAP=wasabi_liquid_symbol_gate "$rustc_bin" \
            --crate-name wasabi_liquid_symbol_gate \
            --edition=2024 \
            ci/check-rust-rlib-symbols.rs \
            -o "$symbol_checker"
        "$symbol_checker" --self-test
        ar t "$wire_archive" >"$scratch/wallet-facts-wire.archive"
        if ! grep -Eq '\.o$' "$scratch/wallet-facts-wire.archive"; then
            echo "wallet-facts wire release archive has no object members" >&2
            exit 1
        fi
        nm -g "$wire_archive" >"$scratch/wallet-facts-wire.symbols" 2>"$scratch/wallet-facts-wire.nm-stderr"
        if ! "$symbol_checker" "$scratch/wallet-facts-wire.symbols"; then
            echo "wallet-facts wire release archive exposes an unmangled global symbol" >&2
            exit 1
        fi
        ar t "$plan_archive" >"$scratch/ordinary-wallet-plan.archive"
        if ! grep -Eq '\.o$' "$scratch/ordinary-wallet-plan.archive"; then
            echo "ordinary-wallet plan release archive has no object members" >&2
            exit 1
        fi
        nm -g "$plan_archive" >"$scratch/ordinary-wallet-plan.symbols" 2>"$scratch/ordinary-wallet-plan.nm-stderr"
        if ! "$symbol_checker" "$scratch/ordinary-wallet-plan.symbols"; then
            echo "ordinary-wallet plan release archive exposes an unmangled global symbol" >&2
            exit 1
        fi
        if ! dynamic_artifacts="$(
            find "$target_directory/release" "$target_directory/debug" -type f \
                \( -name 'libwasabi_liquid_native_wallet_facts_wire*.dylib' \
                -o -name 'libwasabi_liquid_native_wallet_facts_wire*.so' \
                -o -name 'wasabi_liquid_native_wallet_facts_wire*.dll' \
                -o -name 'libwasabi_liquid_native_ordinary_wallet_plan*.dylib' \
                -o -name 'libwasabi_liquid_native_ordinary_wallet_plan*.so' \
                -o -name 'wasabi_liquid_native_ordinary_wallet_plan*.dll' \) \
                -print
        )"; then
            echo "wallet-facts wire dynamic-library artifact inspection failed" >&2
            exit 1
        fi
        if [ -n "$dynamic_artifacts" ]; then
            printf '%s\n' "$dynamic_artifacts" >&2
            echo "wallet-facts wire dynamic-library artifact is forbidden" >&2
            exit 1
        fi
        "$compiler_cargo_bin" check \
            --workspace \
            --all-targets \
            --all-features \
            --locked \
            --offline
        "$compiler_cargo_bin" check \
            --workspace \
            --all-targets \
            --all-features \
            --release \
            --locked \
            --offline
        "$compiler_cargo_bin" test \
            --workspace \
            --all-targets \
            --all-features \
            --locked \
            --offline
        "$compiler_cargo_bin" test \
            --workspace \
            --all-targets \
            --all-features \
            --release \
            --locked \
            --offline
        "$compiler_cargo_bin" test \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --locked \
            --offline
        "$compiler_cargo_bin" test \
            -p wasabi-liquid-native-ordinary-wallet-plan \
            --release \
            --locked \
            --offline
        "$compiler_cargo_bin" fmt --all -- --check
        "$compiler_cargo_bin" clippy \
            --workspace \
            --all-targets \
            --all-features \
            --locked \
            --offline \
            -- \
            -D warnings
        RUSTDOCFLAGS='-D warnings' "$compiler_cargo_bin" doc \
            --workspace \
            --no-deps \
            --all-features \
            --locked \
            --offline
        "$compiler_cargo_bin" test \
            -p wasabi-liquid-native-wallet-facts-wire \
            --locked \
            --offline \
            conformance
        ;;
    *)
        echo "wallet-facts compiler and artifact gates require Cargo 1.96.0" >&2
        exit 1
        ;;
esac
