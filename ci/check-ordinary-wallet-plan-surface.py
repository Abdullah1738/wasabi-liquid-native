#!/usr/bin/env python3
"""Fail-closed source, target, context, and public API gate for WLPQ v1.

The byte and authority-region hashes below are not independent authorization:
pins are drift alarms; updating pins/checker requires fresh review of the exact
new bytes, source inventory, and call edges before the update is accepted.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "crates" / "ordinary-wallet-plan"
EXPECTED_FILES = {
    "Cargo.toml",
    "src/lib.rs",
    "src/reader.rs",
    "src/tests.rs",
    "src/writer.rs",
    "tests/preparation.rs",
}
PRODUCTION_FILES = {"src/lib.rs", "src/reader.rs", "src/writer.rs"}
PIN_REVIEW_BOUNDARY = (
    "pins are drift alarms; updating pins/checker requires fresh review"
)
# These pins bind the exact compiler-reported production closure. They detect
# drift only; changing a pin never substitutes for reviewing the changed bytes.
EXPECTED_PRODUCTION_SOURCE_SHA256 = {
    "src/lib.rs": "eed32d514eca4802a8cee840a40fb2051fc55a0e81fe947f3925cedbbe7fd9e7",
    "src/reader.rs": "6024994d1209a40a59b8ee8f49b4ccb237be46cffc2e4f5f7d39e74cde3325ac",
    "src/writer.rs": "bfa55038ff8dea778f6b2ce3ff83d2ab79a7cae11303f07776d0b25495c49c01",
}
# This is the complete local production-source authority reached by WLPQ v1's
# currently approved public-only preparation call graph, excluding WLPQ's own
# three production files pinned above. Whole-file pins make every byte in each
# authority source review-sensitive, including helpers outside the narrower
# semantic regions below.
EXPECTED_RUNTIME_AUTHORITY_SOURCE_SHA256 = {
    "crates/address/src/lib.rs": "e6544c20fb1d93b473bdac7bd42aaedc68edf46b2cee0f72a28f093d5e3e6014",
    "crates/ordinary-pset/src/lib.rs": "645ea8fc7dc0f370275c571f4b622db28c8cc8ddf626175b4cc4ad0ddd9ad384",
    "crates/transaction-validation/src/lib.rs": "b31cd9785ff204aea300ddafe5bc7e9158377c2746d80df6f2afd942b98f4750",
    "crates/wallet-facts/src/lib.rs": "77c91b3348b7ff876733cfba8720a354d784aba7b782add37e7bbccf1e1a11da",
}
# These exact local call edges define why the four files above are authority.
# The syntax/count probes are semantic diagnostics layered on whole-file pins;
# they do not weaken the requirement to review every byte when a pin changes.
EXPECTED_RUNTIME_AUTHORITY_CALL_EDGES = (
    (
        "crates/ordinary-wallet-plan/src/lib.rs",
        "crates/address/src/lib.rs",
        "ConfidentialLiquidAddress::parse(",
        2,
    ),
    (
        "crates/ordinary-wallet-plan/src/lib.rs",
        "crates/ordinary-pset/src/lib.rs",
        "ConfidentialOutput::from_address(",
        2,
    ),
    (
        "crates/ordinary-wallet-plan/src/lib.rs",
        "crates/ordinary-pset/src/lib.rs",
        "ExplicitFee::new(",
        2,
    ),
    (
        "crates/ordinary-wallet-plan/src/lib.rs",
        "crates/wallet-facts/src/lib.rs",
        "SelectedOutputBatch::new(",
        1,
    ),
    (
        "crates/ordinary-wallet-plan/src/lib.rs",
        "crates/wallet-facts/src/lib.rs",
        "prepare_selected_owned_inputs(",
        1,
    ),
    (
        "crates/ordinary-wallet-plan/src/lib.rs",
        "crates/wallet-facts/src/lib.rs",
        "expected_ordinary_plan_is_balanced(",
        1,
    ),
    (
        "crates/ordinary-pset/src/lib.rs",
        "crates/address/src/lib.rs",
        "address.as_parsed()",
        1,
    ),
    (
        "crates/wallet-facts/src/lib.rs",
        "crates/ordinary-pset/src/lib.rs",
        "output.asset()",
        1,
    ),
    (
        "crates/wallet-facts/src/lib.rs",
        "crates/ordinary-pset/src/lib.rs",
        "output.value()",
        1,
    ),
    (
        "crates/wallet-facts/src/lib.rs",
        "crates/ordinary-pset/src/lib.rs",
        "fee.asset()",
        1,
    ),
    (
        "crates/wallet-facts/src/lib.rs",
        "crates/ordinary-pset/src/lib.rs",
        "fee.value()",
        1,
    ),
    (
        "crates/wallet-facts/src/lib.rs",
        "crates/wallet-facts/src/lib.rs",
        "previous_outputs_for(&transaction, &request.previous_transactions)?",
        1,
    ),
    (
        "crates/wallet-facts/src/lib.rs",
        "crates/transaction-validation/src/lib.rs",
        "validate_transaction_amount_proofs(secp, &transaction, previous_outputs.clone())?",
        1,
    ),
    (
        "crates/transaction-validation/src/lib.rs",
        "crates/transaction-validation/src/lib.rs",
        "verify_tx_amt_proofs(secp, &ordered_previous_outputs)",
        1,
    ),
)
# Neither source is reached by the exact public-only WLPQ runtime call graph:
# signing.rs belongs to later PSET signing, while output-opening belongs to the
# later private opening transition. A future edge to either file, or any other
# runtime-authority source-set drift, must fail this gate and restart review.
NOT_CURRENT_WLPQ_RUNTIME_AUTHORITY = (
    "crates/ordinary-pset/src/signing.rs",
    "crates/output-opening/src/lib.rs",
)
# Authority-region hashes are populated from exact, comment/literal-aware item
# boundaries. Like the full source pins, they are review-required drift alarms.
EXPECTED_AUTHORITY_REGION_SHA256 = {
    "address confidential impl": "d5a5a8228307107fd8ec86bd3c67ef88d407acf60188967d5f1ec41dfc0aded3",
    "address confidential struct": "e9f9413dc998423c29b2068ae76c9e9a6149cb7b1b5860c719722da430e09d4b",
    "address parse expected": "8674a80d3cf1034eceec20ce49c47351127105f31cdffd2d8bef5557afa1db9b",
    "address parsed impl": "e1df8ef612e51df095690196dcc33ceb5088bee9932bc4e0ac5925d79112d107",
    "address parsed struct": "0c1be2ebc2cc36e21403ef014eebb608e1a0291efde8e243876bbb0eecdf5193",
    "address profile enum": "281a3d1ae6a06422120f0816f7343ef35092310317681635499643e9aca9c457",
    "address profile impl": "753e460cf25f255741a45d41065d16623346c10d06831ea26b14ff79c576ff48",
    "ordinary pset confidential output from address": "36b8da1c4c1e8206849a2c91bbc7a526fef935925251500f1102dace9650bcdc",
    "ordinary pset confidential output struct": "f6fa11ea9b038927556f6b500231304a6479eb8bd16e65069187968c59525278",
    "ordinary pset explicit fee new": "04d5f0c2c81cff3dd0585e48f3dfe35fbc3e30430ab5289830cbd9421d3655b9",
    "ordinary pset explicit fee struct": "0580d6134a9063337e451585b45e3c19bad60a1234237397ac76e29a59eb02c7",
    "ordinary pset explicit fee zeroize": "9112c13aaf907460aadfb8898ca1712efba7ab37b03860c1e26ce6e1d5aa831d",
    "wallet facts descriptor catalog drop": "9c2f4dd3efc894f73e71d5af68dfa63955a89f107e6d9d47550e1312199d70cc",
    "wallet facts descriptor catalog impl": "0641b8a5a1eaf8027d92edc05df7cc3e16b68c6d53d408a81ff396a74f2b1276",
    "wallet facts descriptor catalog struct": "ab57384645a9c06a713a313edcf62ce37ed5064ac411805eb0768570eaa42ddb",
    "wallet facts descriptor network enum": "af14d113015f98e9e771c6c25bcd3bb25381d0e3cf679ae640bc84607ad4b2fc",
    "wallet facts prepare selected outputs": "2f95dc3bda090ceab5e256c8500f39ade6c34b407cedb5e7c3feb37a00f2edf3",
    "wallet facts selected output batch impl": "a70418819a069b437c5b8ea218a91494a3371632cf6370b4806330fa63897597",
    "wallet facts selected output batch struct": "5bde240c5e079271dc248e5a8ec4525b0acf122d1d2f2d2b7ce65f7f4f195aae",
}
EXPECTED_INHERENT_METHODS = {
    "ConfidentialLiquidAddress": ("as_parsed", "from_unconfidential", "into_parsed", "parse"),
    "ConfidentialOutput": ("asset", "from_address", "value"),
    "DescriptorCatalog": ("derive", "last_index", "network", "script_count"),
    "ExplicitFee": ("asset", "new", "value"),
    "LiquidAddressProfile": ("params",),
    "ParsedLiquidAddress": (
        "blinding_pubkey",
        "canonical_address",
        "from_upstream",
        "is_confidential",
        "parse",
        "profile",
        "script_pubkey",
        "unconfidential_address",
    ),
    "SelectedOutputBatch": ("expected_ordinary_plan_is_balanced", "new"),
}
PUBLIC_API = Counter(
    {
        "enum OrdinaryWalletPlanWireError": 1,
        "struct EncodedOrdinaryWalletPlanRequest": 1,
        "struct OrdinaryWalletPlanDestinationRef": 1,
        "struct OrdinaryWalletPlanRequestRef": 1,
        "struct OrdinaryWalletPlanSelectedRef": 1,
        "struct ParsedOrdinaryWalletPlanRequest": 1,
        "struct PubliclyPreparedOrdinaryWalletPlanRequest": 1,
        "fn as_bytes": 1,
        "fn code": 1,
        "fn confidential_destination_count": 1,
        "fn decode_request": 1,
        "fn encode_request": 1,
        "fn new": 3,
        "fn prepare": 1,
        "fn reencode": 1,
        "fn selected_input_count": 1,
        "fn source_revision": 1,
    }
)
EXPECTED_VISIBILITY_SYNTAX = Counter(
    {
        "src/lib.rs:pub enum OrdinaryWalletPlanWireError {": 1,
        "src/lib.rs:pub const fn code(self) -> u32 {": 1,
        "src/lib.rs:pub struct OrdinaryWalletPlanSelectedRef<'selected> {": 1,
        "src/lib.rs:pub const fn new(": 3,
        "src/lib.rs:pub struct OrdinaryWalletPlanDestinationRef<'destination> {": 1,
        "src/lib.rs:pub struct OrdinaryWalletPlanRequestRef<'request> {": 1,
        "src/lib.rs:pub struct EncodedOrdinaryWalletPlanRequest {": 1,
        "src/lib.rs:pub fn as_bytes(&self) -> &[u8] {": 1,
        "src/lib.rs:pub struct ParsedOrdinaryWalletPlanRequest {": 1,
        "src/lib.rs:pub fn reencode(": 1,
        "src/lib.rs:pub fn prepare<'catalog>(": 1,
        "src/lib.rs:pub struct PubliclyPreparedOrdinaryWalletPlanRequest<'catalog> {": 1,
        "src/lib.rs:pub const fn source_revision(&self) -> u64 {": 1,
        "src/lib.rs:pub const fn selected_input_count(&self) -> usize {": 1,
        "src/lib.rs:pub const fn confidential_destination_count(&self) -> usize {": 1,
        "src/lib.rs:pub fn encode_request(": 1,
        "src/lib.rs:pub fn decode_request(": 1,
        "src/reader.rs:pub(crate) struct Reader<'frame> {": 1,
        "src/reader.rs:pub(crate) const fn new(bytes: &'frame [u8]) -> Self {": 1,
        "src/reader.rs:pub(crate) fn take(": 1,
        "src/reader.rs:pub(crate) fn read_u16(&mut self) -> Result<u16, OrdinaryWalletPlanWireError> {": 1,
        "src/reader.rs:pub(crate) fn read_u32(&mut self) -> Result<u32, OrdinaryWalletPlanWireError> {": 1,
        "src/reader.rs:pub(crate) fn read_u64(&mut self) -> Result<u64, OrdinaryWalletPlanWireError> {": 1,
        "src/reader.rs:pub(crate) fn read_array<const LENGTH: usize>(": 1,
        "src/reader.rs:pub(crate) fn require_end(&self) -> Result<(), OrdinaryWalletPlanWireError> {": 1,
        "src/writer.rs:pub(crate) struct Writer {": 1,
        "src/writer.rs:pub(crate) fn new(mut expected_length: usize) -> Self {": 1,
        "src/writer.rs:pub(crate) fn write(&mut self, bytes: &[u8]) {": 1,
        "src/writer.rs:pub(crate) fn write_u16(&mut self, value: u16) {": 1,
        "src/writer.rs:pub(crate) fn write_u32(&mut self, value: u32) {": 1,
        "src/writer.rs:pub(crate) fn write_u64(&mut self, value: u64) {": 1,
        "src/writer.rs:pub(crate) fn finish(mut self) -> Result<Vec<u8>, OrdinaryWalletPlanWireError> {": 1,
    }
)
EXPECTED_STD_PATH_HEADS = Counter({"cell": 6, "error": 1})
EXPECTED_EXPLICIT_FEE_ZEROIZE_SHA256 = (
    "05abcb7c06e317e2643062892084e3dd6a36ea2637ab18b88b5b25fe51f5b196"
)
EXPECTED_PLAN_FEE_LIFECYCLE_SHA256 = (
    "94d94885dd05e46dd809c2217b6d1cbbdb96670acea15a4f0195b01d5bef6386"
)
EXPECTED_ERROR_ENUM_SHA256 = (
    "96fc6b799065fde8183fe3da031cee193771951fcf8082883bbede9c1ecc7c28"
)
EXPECTED_ERROR_BEHAVIOR_SHA256 = (
    "952c40948e8f87eac4bea42cb9ec93e2ba853ed8ae58b1062926134ed7c74d73"
)
EXPECTED_PUBLIC_SIGNATURE_COUNT = 25
EXPECTED_PUBLIC_SIGNATURES_SHA256 = (
    "a5c541fefffb8ff6b411b98803741b89a82fc30cd3ee36bbd35abc42869be56d"
)
EXPECTED_TRAIT_IMPL_COUNT = 42
EXPECTED_TRAIT_IMPLS_SHA256 = (
    "0df9e6dd1ef7b3862deca847f7e69f264a62793709cacb235803b02ccb10079b"
)
EXPECTED_CRATE_ATTRIBUTES = ("#![forbid(unsafe_code)]", "#![deny(missing_docs)]")
EXPECTED_MODULE_DECLARATIONS = (
    "src/lib.rs:mod reader;",
    "src/lib.rs:mod writer;",
    "src/lib.rs:#[cfg(test)]\nmod tests;",
)
EXPECTED_OUTER_ATTRIBUTE_COUNT = 61
EXPECTED_OUTER_ATTRIBUTES_SHA256 = (
    "3a8bd208272d73b042762cb63f9186375ea23ce512f9e00c0475a99bee5870ce"
)
EXPECTED_PUBLIC_ITEM_ATTRIBUTE_COUNT = 34
EXPECTED_PUBLIC_ITEM_ATTRIBUTES_SHA256 = (
    "04c984d926928f03435a8471c84e6e8bcba8603e5e416dcd9c3d8b4c8954ea1f"
)
EXPECTED_TOKEN_ATTRIBUTE_COUNT = 63
EXPECTED_TOKEN_ATTRIBUTES_SHA256 = (
    "4d9de50f16dd14b4ce32dac23d144c482cabb459d69cc27dc88568ebe08ee04f"
)
EXPECTED_COMPILED_SOURCE_FILES = tuple(sorted(PRODUCTION_FILES))
EXPECTED_ORDINARY_PSET_IMPORT = (
    "use wasabi_liquid_native_ordinary_pset::{ConfidentialOutput, ExplicitFee};"
)
EXPECTED_ORDINARY_PSET_ITEMS = Counter(
    {"ConfidentialOutput": 6, "ExplicitFee": 8}
)
EXPECTED_ORDINARY_PSET_ASSOCIATED_CALLS = Counter(
    {"ConfidentialOutput::from_address": 2, "ExplicitFee::new": 2}
)
DEPENDENCY_ROOTS = {
    "elements",
    "wasabi_liquid_native_address",
    "wasabi_liquid_native_ordinary_pset",
    "wasabi_liquid_native_wallet_facts",
    "zeroize",
}
EXPECTED_DEPENDENCY_USES = {
    "src/lib.rs": Counter(
        {
            "use elements :: secp256k1_zkp :: { All , Secp256k1 } ;": 1,
            "use elements :: { AssetId , OutPoint , Txid } ;": 1,
            "use wasabi_liquid_native_address :: { ConfidentialLiquidAddress , LiquidAddressProfile } ;": 1,
            "use wasabi_liquid_native_ordinary_pset :: { ConfidentialOutput , ExplicitFee } ;": 1,
            "use wasabi_liquid_native_wallet_facts :: { BorrowedSelectedOutput , DescriptorCatalog , DescriptorNetwork , SelectedOutputBatch , prepare_selected_owned_inputs , } ;": 1,
            "use zeroize :: Zeroize ;": 1,
        }
    ),
    "src/reader.rs": Counter({"use zeroize :: Zeroize ;": 1}),
    "src/writer.rs": Counter({"use zeroize :: Zeroize ;": 1}),
}
EXPECTED_DEPENDENCY_ITEMS = Counter(
    {
        "All": 2,
        "AssetId": 10,
        "BorrowedSelectedOutput": 3,
        "ConfidentialLiquidAddress": 3,
        "ConfidentialOutput": 6,
        "DescriptorCatalog": 4,
        "DescriptorNetwork": 4,
        "ExplicitFee": 8,
        "LiquidAddressProfile": 4,
        "OutPoint": 4,
        "Secp256k1": 2,
        "SelectedOutputBatch": 5,
        "Txid": 3,
        "Zeroize": 3,
        "prepare_selected_owned_inputs": 2,
    }
)
EXPECTED_DEPENDENCY_ASSOCIATED_REFERENCES = Counter(
    {
        "AssetId::from_byte_array": 7,
        "BorrowedSelectedOutput::new": 1,
        "ConfidentialLiquidAddress::parse": 2,
        "ConfidentialOutput::from_address": 2,
        "DescriptorNetwork::Mainnet": 1,
        "DescriptorNetwork::Test": 1,
        "ExplicitFee::new": 2,
        "LiquidAddressProfile::LiquidMainnet": 1,
        "LiquidAddressProfile::LiquidTestnet": 1,
        "OutPoint::new": 2,
        "SelectedOutputBatch::new": 1,
        "Txid::from_byte_array": 2,
    }
)
EXPECTED_MEMBER_REFERENCE_COUNT = 678
EXPECTED_MEMBER_REFERENCES_SHA256 = (
    "cdb63f355b69897c7e6cd802fdc2b6f6959ee0626746441f3ec415b55d3be0b6"
)
FUNCTION_LIKE_MACRO = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*!\s*[({\[]"
)
EXPECTED_TEST_THREAD_LOCAL = "#[cfg(test)]\nthread_local! {"
EXPECTED_TEST_THREAD_LOCAL_SHA256 = (
    "8d89b06ff5f6c48f7c2569ea77d91ed04f7e9f08640f80e416b74a575afcb489"
)
EXPECTED_TEST_PANIC = 'panic!("test-only ordinary-wallet plan staging unwind");'
FORBIDDEN = re.compile(
    r"wasabi_liquid_native_output_opening|wasabi_liquid_native_ordinary_wallet_pset|"
    r"open_prepared_selected_owned_inputs|SelectedOutputOpeningProvider|SecretKey|"
    r"rand::|getrandom|no_mangle|export_name|link_name|link_section|macro_export|"
    r"ffi_returns_twice|global_asm\s*!|asm\s*!|extern\s*(?:unsafe\s*)?\"|extern\s+crate|"
    r"include\s*!|include_str\s*!|include_bytes\s*!|macro_rules\s*!|\bpub\s+macro\b|"
    r"AddressParams::ELEMENTS|LiquidAddressProfile::ElementsDefault|build\.rs|#\s*\[\s*path\b"
)
FORBIDDEN_ORDINARY_PSET_API = re.compile(
    r"\b(?:prepare_ordinary_pset|SpendableInput|PreparedOrdinaryPset|"
    r"BlindedOrdinaryPset|PsetConstructionError|OrdinaryPsetBlindingError|"
    r"OrdinaryP2wpkhSigner|SignedOrdinaryPset|OrdinarySigningFailure|"
    r"FinalizedOrdinaryTransaction|PartiallySignedTransaction|"
    r"sign_and_finalize|serialize_for_broadcast|serialize_sensitive|as_pset|blind)\b"
)
FORBIDDEN_WALLET_FACTS_API = re.compile(
    r"\b(?:BorrowedCandidateTransaction|CandidateBatch|ValidatedOwnedInput|"
    r"SelectedOutputOpeningProvider|PubliclyPreparedSelectedOutputs|"
    r"WalletObservationError|ObservedTransactionInput|ObservedWalletTransaction|"
    r"ObservedOwnedOutput|ObservedWalletBatch|BorrowedSlip77|"
    r"open_prepared_selected_owned_inputs|validate_selected_owned_inputs|"
    r"observe_owned_outputs|validates_observed_public_output)\b"
)


def reject(message: str) -> None:
    raise SystemExit(message)


def sha256_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def strip_rust_comments(text: str) -> str:
    output = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            if newline == -1:
                break
            output.append("\n")
            index = newline + 1
            continue
        if text.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    if text[index] == "\n":
                        output.append("\n")
                    index += 1
            if depth:
                reject("ordinary-wallet plan production source has an unterminated comment")
            continue
        raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", text[index:])
        if raw is not None:
            marker = '"' + raw.group("hashes")
            end = text.find(marker, index + raw.end())
            if end == -1:
                reject("ordinary-wallet plan production source has an unterminated raw string")
            end += len(marker)
            output.append(text[index:end])
            index = end
            continue
        if text[index] == '"':
            start = index
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                reject("ordinary-wallet plan production source has an unterminated string")
            output.append(text[start:index])
            continue
        output.append(text[index])
        index += 1
    return "".join(output)


def rust_tokens(text: str) -> list[str]:
    """Returns executable Rust tokens while discarding comments and literals."""
    text = strip_rust_comments(text)
    tokens = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", text[index:])
        if raw is not None:
            marker = '"' + raw.group("hashes")
            end = text.find(marker, index + raw.end())
            if end == -1:
                reject("ordinary-wallet plan production source has an unterminated raw string")
            tokens.append("<literal>")
            index = end + len(marker)
            continue
        literal_prefix = 1 if text.startswith(('b"', 'c"'), index) else 0
        if text[index + literal_prefix : index + literal_prefix + 1] == '"':
            index += literal_prefix + 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                reject("ordinary-wallet plan production source has an unterminated string")
            tokens.append("<literal>")
            continue
        character = re.match(
            r"b?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\}|[^\n])|[^'\\\n])'",
            text[index:],
        )
        if character is not None:
            tokens.append("<literal>")
            index += character.end()
            continue
        lifetime = re.match(r"'(?:r#)?[A-Za-z_][A-Za-z0-9_]*", text[index:])
        if lifetime is not None:
            tokens.append("<lifetime>")
            index += lifetime.end()
            continue
        identifier = re.match(r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*", text[index:])
        if identifier is not None:
            tokens.append(identifier.group(0).removeprefix("r#"))
            index += identifier.end()
            continue
        number = re.match(r"[0-9][A-Za-z0-9_\.]*", text[index:])
        if number is not None:
            tokens.append(number.group(0))
            index += number.end()
            continue
        punctuation = next(
            (
                candidate
                for candidate in ("::", "->", "=>", "..=", "..", "&&", "||", "==", "!=", "<=", ">=")
                if text.startswith(candidate, index)
            ),
            text[index],
        )
        tokens.append(punctuation)
        index += len(punctuation)
    return tokens


def masked_rust_source(text: str) -> str:
    """Masks comments and literals without changing source offsets."""
    masked = list(text)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if masked[position] not in {"\n", "\r"}:
                masked[position] = " "

    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            end = len(text) if end == -1 else end
            blank(index, end)
            index = end
            continue
        if text.startswith("/*", index):
            start = index
            depth = 1
            index += 2
            while index < len(text) and depth:
                if text.startswith("/*", index):
                    depth += 1
                    index += 2
                elif text.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                reject("ordinary-wallet plan authority source has an unterminated comment")
            blank(start, index)
            continue
        raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", text[index:])
        if raw is not None:
            start = index
            marker = '"' + raw.group("hashes")
            end = text.find(marker, index + raw.end())
            if end == -1:
                reject("ordinary-wallet plan authority source has an unterminated raw string")
            index = end + len(marker)
            blank(start, index)
            continue
        literal_prefix = 1 if text.startswith(('b"', 'c"'), index) else 0
        if text[index + literal_prefix : index + literal_prefix + 1] == '"':
            start = index
            index += literal_prefix + 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                reject("ordinary-wallet plan authority source has an unterminated string")
            blank(start, index)
            continue
        character = re.match(
            r"b?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\}|[^\n])|[^'\\\n])'",
            text[index:],
        )
        if character is not None:
            end = index + character.end()
            blank(index, end)
            index = end
            continue
        index += 1
    return "".join(masked)


def rust_token_spans(text: str) -> list[tuple[str, int, int]]:
    masked = masked_rust_source(text)
    token = re.compile(
        r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*|"
        r"[0-9][A-Za-z0-9_\.]*|::|->|=>|\.\.=|\.\.|&&|\|\||==|!=|<=|>=|\S"
    )
    spans = []
    for match in token.finditer(masked):
        value = match.group(0)
        spans.append((value.removeprefix("r#"), match.start(), match.end()))
    return spans


def authority_item(text: str, marker: str, name: str) -> str:
    """Extracts one exact item using comment/literal-aware Rust token bounds."""
    spans = rust_token_spans(text)
    marker_tokens = rust_tokens(marker)
    matches = [
        index
        for index in range(len(spans) - len(marker_tokens) + 1)
        if [value for value, _, _ in spans[index : index + len(marker_tokens)]]
        == marker_tokens
    ]
    if len(matches) != 1:
        reject(f"ordinary-wallet plan {name} authority item boundary mismatch")
    start_index = matches[0]
    start = spans[start_index][1]
    round_depth = 0
    square_depth = 0
    angle_depth = 0
    for index in range(start_index + len(marker_tokens), len(spans)):
        value = spans[index][0]
        if value == "(":
            round_depth += 1
        elif value == ")":
            round_depth -= 1
        elif value == "[":
            square_depth += 1
        elif value == "]":
            square_depth -= 1
        elif value == "<":
            angle_depth += 1
        elif value == ">" and angle_depth:
            angle_depth -= 1
        elif value == ";" and round_depth == square_depth == angle_depth == 0:
            return text[start : spans[index][2]]
        elif value == "{" and round_depth == square_depth == angle_depth == 0:
            depth = 1
            for closing in range(index + 1, len(spans)):
                if spans[closing][0] == "{":
                    depth += 1
                elif spans[closing][0] == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start : spans[closing][2]]
            break
    reject(f"ordinary-wallet plan {name} authority item is incomplete")


def inherent_method_inventory(text: str, type_name: str) -> tuple[str, ...]:
    """Returns every method from every inherent impl of one exact type."""
    spans = rust_token_spans(text)
    methods = []
    index = 0
    while index < len(spans):
        if spans[index][0] != "impl":
            index += 1
            continue
        opening = index + 1
        while opening < len(spans) and spans[opening][0] != "{":
            opening += 1
        if opening == len(spans):
            break
        header = [value for value, _, _ in spans[index + 1 : opening]]
        depth = 1
        closing = opening + 1
        while closing < len(spans) and depth:
            if spans[closing][0] == "{":
                depth += 1
            elif spans[closing][0] == "}":
                depth -= 1
            closing += 1
        if depth:
            reject("ordinary-wallet plan dependency inherent impl is incomplete")
        if "for" not in header and type_name in header:
            body_depth = 1
            cursor = opening + 1
            while cursor < closing - 1:
                value = spans[cursor][0]
                if value == "{":
                    body_depth += 1
                elif value == "}":
                    body_depth -= 1
                elif value == "fn" and body_depth == 1:
                    if cursor + 1 >= closing or not re.fullmatch(
                        r"[A-Za-z_][A-Za-z0-9_]*", spans[cursor + 1][0]
                    ):
                        reject("ordinary-wallet plan dependency method inventory is invalid")
                    methods.append(spans[cursor + 1][0])
                cursor += 1
        index = closing
    return tuple(sorted(methods))


def use_statement_spans(tokens: list[str]) -> list[tuple[int, int]]:
    spans = []
    for start, token in enumerate(tokens):
        if token != "use":
            continue
        depths = {"(": 0, "[": 0, "{": 0}
        pairs = {")": "(", "]": "[", "}": "{"}
        for cursor in range(start + 1, len(tokens)):
            current = tokens[cursor]
            if current in depths:
                depths[current] += 1
            elif current in pairs:
                opener = pairs[current]
                if depths[opener] == 0:
                    reject("ordinary-wallet plan production source has an invalid use tree")
                depths[opener] -= 1
            elif current == ";" and all(depth == 0 for depth in depths.values()):
                spans.append((start, cursor + 1))
                break
        else:
            reject("ordinary-wallet plan production source has an incomplete use declaration")
    return spans


def use_has_visibility(tokens: list[str], start: int) -> bool:
    if start == 0:
        return False
    if tokens[start - 1] == "pub":
        return True
    if tokens[start - 1] != ")":
        return False
    depth = 0
    for cursor in range(start - 1, -1, -1):
        if tokens[cursor] == ")":
            depth += 1
        elif tokens[cursor] == "(":
            depth -= 1
            if depth == 0:
                return cursor > 0 and tokens[cursor - 1] == "pub"
    reject("ordinary-wallet plan production source has an invalid visibility")


def dependency_surface() -> tuple[Counter[str], Counter[str], list[str]]:
    items: Counter[str] = Counter()
    associated: Counter[str] = Counter()
    members = []
    dependency_names = set(EXPECTED_DEPENDENCY_ITEMS)
    for relative in sorted(PRODUCTION_FILES):
        tokens = rust_tokens((CRATE / relative).read_text())
        spans = use_statement_spans(tokens)
        dependency_spans = []
        actual_uses: Counter[str] = Counter()
        for start, end in spans:
            statement = tokens[start:end]
            if not DEPENDENCY_ROOTS.intersection(statement):
                continue
            if use_has_visibility(tokens, start):
                reject("ordinary-wallet plan dependency re-export escaped its boundary")
            dependency_spans.append((start, end))
            actual_uses[" ".join(statement)] += 1
        if actual_uses != EXPECTED_DEPENDENCY_USES[relative]:
            reject("ordinary-wallet plan exact dependency import boundary changed")
        approved_root_positions = {
            position
            for start, end in dependency_spans
            for position in range(start, end)
            if tokens[position] in DEPENDENCY_ROOTS
        }
        for position, token in enumerate(tokens):
            is_dependency_root = token in DEPENDENCY_ROOTS and (
                token != "zeroize"
                or (
                    position + 1 < len(tokens)
                    and tokens[position + 1] in {"::", "!"}
                )
            )
            if is_dependency_root and position not in approved_root_positions:
                reject("ordinary-wallet plan fully-qualified dependency path escaped its boundary")
            if token in dependency_names:
                items[token] += 1
            if (
                position + 2 < len(tokens)
                and token in dependency_names
                and tokens[position + 1] == "::"
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[position + 2])
            ):
                associated[f"{token}::{tokens[position + 2]}"] += 1
            if (
                token == "."
                and position + 1 < len(tokens)
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[position + 1])
            ):
                members.append(f"{relative}:{tokens[position + 1]}")
    return items, associated, members


def validate_manifest_targets() -> str:
    manifest = (CRATE / "Cargo.toml").read_text()
    try:
        manifest_data = tomllib.loads(manifest)
    except tomllib.TOMLDecodeError:
        reject("ordinary-wallet plan Cargo target manifest is invalid")
    if set(manifest_data) != {"package", "lib", "dependencies", "dev-dependencies"}:
        reject("ordinary-wallet plan unexpected Cargo target or build script")
    expected_package = {
        "name": "wasabi-liquid-native-ordinary-wallet-plan",
        "version": "0.1.0",
        "edition": "2024",
        "rust-version": "1.96",
        "license": "MIT",
        "publish": False,
        "description": "Canonical export-free ordinary-wallet plan request preparation",
    }
    expected_dependencies = {
        "elements": {
            "git": "https://github.com/Abdullah1738/rust-elements.git",
            "rev": "5b8865f8061459f82dcb8a1cf476b7ba17b14193",
            "default-features": False,
        },
        "wasabi-liquid-native-address": {"path": "../address"},
        "wasabi-liquid-native-ordinary-pset": {"path": "../ordinary-pset"},
        "wasabi-liquid-native-wallet-facts": {"path": "../wallet-facts"},
        "zeroize": {"version": "1.8", "default-features": False},
    }
    expected_dev_dependencies = {
        "miniscript": {
            "version": "=12.3.7",
            "default-features": False,
            "features": ["no-std"],
        },
        "rand": "0.8",
        "sha2": {"version": "=0.11.0", "default-features": False},
        "static_assertions": "1.1",
    }
    if (
        manifest_data["package"] != expected_package
        or manifest_data["lib"] != {"crate-type": ["rlib"]}
        or manifest_data["dependencies"] != expected_dependencies
        or manifest_data["dev-dependencies"] != expected_dev_dependencies
    ):
        reject("ordinary-wallet plan unexpected Cargo target or build script")
    return manifest


def validate_dependency_authority_surface(source: str) -> None:
    lexical_source = strip_rust_comments(source)
    source_tokens = rust_tokens(source)
    if any(
        "std" in source_tokens[start:end]
        for start, end in use_statement_spans(source_tokens)
    ):
        reject("ordinary-wallet plan may not alias or import the std capability root")
    std_positions = [
        position for position, token in enumerate(source_tokens) if token == "std"
    ]
    if any(
        position + 2 >= len(source_tokens) or source_tokens[position + 1] != "::"
        for position in std_positions
    ):
        reject("ordinary-wallet plan may not alias or import the std capability root")
    std_path_heads = Counter(source_tokens[position + 2] for position in std_positions)
    if std_path_heads != EXPECTED_STD_PATH_HEADS:
        reject("ordinary-wallet plan process, environment, thread, or clock scope changed")
    if (
        lexical_source.count("wasabi_liquid_native_ordinary_pset") != 1
        or lexical_source.count(EXPECTED_ORDINARY_PSET_IMPORT) != 1
    ):
        reject("ordinary-wallet plan ordinary-pset import boundary changed")
    ordinary_pset_items = Counter(
        re.findall(r"\b(?:ConfidentialOutput|ExplicitFee)\b", lexical_source)
    )
    if ordinary_pset_items != EXPECTED_ORDINARY_PSET_ITEMS:
        reject("ordinary-wallet plan ordinary-pset item inventory changed")
    ordinary_pset_calls = Counter(
        "::".join(match)
        for match in re.findall(
            r"\b(ConfidentialOutput|ExplicitFee)\s*::\s*([A-Za-z_][A-Za-z0-9_]*)",
            lexical_source,
        )
    )
    if ordinary_pset_calls != EXPECTED_ORDINARY_PSET_ASSOCIATED_CALLS:
        reject("ordinary-wallet plan ordinary-pset associated call inventory changed")
    if FORBIDDEN_ORDINARY_PSET_API.search(lexical_source):
        reject("ordinary-wallet plan ordinary-pset capability escaped its boundary")
    if FORBIDDEN_WALLET_FACTS_API.search(lexical_source):
        reject("ordinary-wallet plan wallet-facts capability escaped its boundary")
    dependency_items, dependency_associated, dependency_members = dependency_surface()
    if dependency_items != EXPECTED_DEPENDENCY_ITEMS:
        reject("ordinary-wallet plan exact dependency item inventory changed")
    if dependency_associated != EXPECTED_DEPENDENCY_ASSOCIATED_REFERENCES:
        reject("ordinary-wallet plan exact dependency associated API changed")
    if (
        len(dependency_members) != EXPECTED_MEMBER_REFERENCE_COUNT
        or sha256_text("\n\0\n".join(dependency_members))
        != EXPECTED_MEMBER_REFERENCES_SHA256
    ):
        reject("ordinary-wallet plan exact dependency method and member surface changed")


def rust_attributes(text: str) -> list[str]:
    attributes = []
    index = 0
    while True:
        match = re.search(r"#\s*(?P<inner>!)?\s*\[", text[index:])
        if match is None:
            return attributes
        start = index + match.start()
        cursor = index + match.end()
        depth = 1
        while cursor < len(text) and depth:
            if text[cursor] == "[":
                depth += 1
            elif text[cursor] == "]":
                depth -= 1
            cursor += 1
        if depth:
            reject("ordinary-wallet plan production source has an incomplete attribute")
        kind = "inner" if match.group("inner") else "outer"
        attributes.append(f"{kind}:" + " ".join(text[start:cursor].split()))
        index = cursor


def exact_region(text: str, start: str, end: str, name: str) -> str:
    if text.count(start) != 1 or text.count(end) != 1:
        reject(f"ordinary-wallet plan {name} region boundary mismatch")
    return text.split(start, 1)[1].split(end, 1)[0]


def braced_item(text: str, marker: str, name: str) -> str:
    if text.count(marker) != 1:
        reject(f"ordinary-wallet plan {name} item boundary mismatch")
    start = text.index(marker)
    opening = text.find("{", start)
    if opening == -1:
        reject(f"ordinary-wallet plan {name} item has no body")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    reject(f"ordinary-wallet plan {name} item body is incomplete")


def validate_process_global_state(source: str) -> None:
    test_thread_local = braced_item(
        source,
        EXPECTED_TEST_THREAD_LOCAL,
        "test thread-local audit state",
    )
    if sha256_text(test_thread_local) != EXPECTED_TEST_THREAD_LOCAL_SHA256:
        reject("ordinary-wallet plan exact test thread-local audit state changed")
    production = source.replace(test_thread_local, "", 1)
    if "static" in rust_tokens(production):
        reject("ordinary-wallet plan production static or process-global state is forbidden")


def production_text() -> str:
    parts = []
    for relative in sorted(PRODUCTION_FILES):
        parts.append((CRATE / relative).read_text())
    return "\n".join(parts)


def outer_attributes() -> list[str]:
    attributes = []
    for relative in sorted(PRODUCTION_FILES):
        for line in (CRATE / relative).read_text().splitlines():
            if re.match(r"^\s*#\[(?!path\b).+\]\s*$", line):
                attributes.append(f"{relative}:{line.strip()}")
    return attributes


def adjacent_attributes(lines: list[str], index: int) -> list[str]:
    attributes = []
    cursor = index - 1
    while cursor >= 0 and re.match(r"^\s*#\[.+\]\s*$", lines[cursor]):
        attributes.append(lines[cursor].strip())
        cursor -= 1
    return list(reversed(attributes))


def module_declarations() -> tuple[str, ...]:
    declarations = []
    module = re.compile(
        r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:;|\{)"
    )
    for relative in sorted(PRODUCTION_FILES):
        lines = (CRATE / relative).read_text().splitlines()
        for index, line in enumerate(lines):
            if module.match(line):
                attributes = adjacent_attributes(lines, index)
                declarations.append(f"{relative}:" + "\n".join([*attributes, line.strip()]))
    return tuple(declarations)


def public_item_attributes() -> list[str]:
    items = []
    public_item = re.compile(
        r"^\s*pub(?:\s*\([^)]*\))?\s+"
        r"(?:const\s+|unsafe\s+|async\s+)*"
        r"(struct|enum|trait|type|union|fn)\s+([A-Za-z_][A-Za-z0-9_]*)"
    )
    for relative in sorted(PRODUCTION_FILES):
        lines = (CRATE / relative).read_text().splitlines()
        for index, line in enumerate(lines):
            match = public_item.match(line)
            if match:
                attributes = adjacent_attributes(lines, index)
                items.append(
                    f"{relative}:{match.group(1)} {match.group(2)}:"
                    + "\n".join(attributes)
                )
    return items


def public_api(text: str) -> Counter[str]:
    found: Counter[str] = Counter()
    for line in text.splitlines():
        match = re.match(
            r"^\s*pub\s+(?:const\s+|unsafe\s+|async\s+)*"
            r"(struct|enum|trait|type|fn)\s+([A-Za-z_][A-Za-z0-9_]*)",
            line,
        )
        if match:
            found[f"{match.group(1)} {match.group(2)}"] += 1
    return found


def visibility_syntax() -> Counter[str]:
    found: Counter[str] = Counter()
    visibility = re.compile(r"^\s*pub(?:\s*\([^)]*\))?(?:\s|$)")
    for relative in sorted(PRODUCTION_FILES):
        for line in (CRATE / relative).read_text().splitlines():
            if visibility.match(line):
                found[f"{relative}:{line.strip()}"] += 1
    return found


def public_signatures() -> list[str]:
    signatures = []
    start = re.compile(
        r"^\s*pub(?:\s*\([^)]*\))?\s+"
        r"(?:const\s+|unsafe\s+|async\s+)*fn\s+"
    )
    for relative in sorted(PRODUCTION_FILES):
        lines = (CRATE / relative).read_text().splitlines()
        index = 0
        while index < len(lines):
            if not start.match(lines[index]):
                index += 1
                continue
            signature = [lines[index].rstrip()]
            while "{" not in signature[-1]:
                index += 1
                if index == len(lines):
                    reject("ordinary-wallet plan public signature is incomplete")
                signature.append(lines[index].rstrip())
            signatures.append(f"{relative}:" + "\n".join(signature))
            index += 1
    return signatures


def trait_impls() -> list[str]:
    headers = []
    start = re.compile(r"^(?P<indent>[ \t]*)(?P<unsafe>unsafe[ \t]+)?impl\b")
    for relative in sorted(PRODUCTION_FILES):
        lines = (CRATE / relative).read_text().splitlines()
        for index, line in enumerate(lines):
            match = start.match(line)
            if match is None:
                continue
            header_lines = [line]
            cursor = index
            while "{" not in header_lines[-1]:
                cursor += 1
                if cursor == len(lines):
                    reject("ordinary-wallet plan implementation header is incomplete")
                header_lines.append(lines[cursor])
            normalized = " ".join("\n".join(header_lines).split())
            if " for " not in normalized:
                continue
            attributes = adjacent_attributes(lines, index)
            headers.append(
                f"{relative}:indent={len(match.group('indent'))}:"
                + "\n".join([*attributes, normalized])
            )
    return sorted(headers)


def compiled_source_files() -> tuple[str, ...]:
    result = subprocess.run(
        [
            "cargo",
            "rustc",
            "-p",
            "wasabi-liquid-native-ordinary-wallet-plan",
            "--lib",
            "--locked",
            "--offline",
            "--",
            "--emit=dep-info=-",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        reject("ordinary-wallet plan compiler source-closure derivation failed")
    sources = set()
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        for token in line.split(":", 1)[1].split():
            path = Path(token)
            if not path.is_absolute():
                path = ROOT / path
            if not path.exists():
                continue
            try:
                relative = path.resolve().relative_to(CRATE.resolve()).as_posix()
            except ValueError:
                try:
                    relative = "../" + path.resolve().relative_to(ROOT.resolve()).as_posix()
                except ValueError:
                    relative = path.resolve().as_posix()
            sources.add(relative)
    return tuple(sorted(sources))


def validate_compiled_source_closure_and_pins(
    source: str, compiled_files: tuple[str, ...]
) -> str:
    if compiled_files != EXPECTED_COMPILED_SOURCE_FILES:
        reject("ordinary-wallet plan compiler source closure changed")
    compiled_source = "\n".join(
        (CRATE / relative).read_text() for relative in compiled_files
    )
    if compiled_source != source:
        reject("ordinary-wallet plan compiler source closure scan mismatch")
    for relative in compiled_files:
        actual = sha256_bytes((CRATE / relative).read_bytes())
        if actual != EXPECTED_PRODUCTION_SOURCE_SHA256.get(relative):
            reject(
                "ordinary-wallet plan reviewed production source bytes changed; "
                "source pins detect drift only and updating them requires fresh review"
            )
    return compiled_source


def validate_runtime_authority_sources_and_edges() -> None:
    authority_sources = tuple(sorted(EXPECTED_RUNTIME_AUTHORITY_SOURCE_SHA256))
    edge_targets = tuple(
        sorted({target for _, target, _, _ in EXPECTED_RUNTIME_AUTHORITY_CALL_EDGES})
    )
    if edge_targets != authority_sources:
        reject(
            "ordinary-wallet plan runtime-authority source inventory changed; "
            f"{PIN_REVIEW_BOUNDARY}"
        )
    if set(authority_sources).intersection(NOT_CURRENT_WLPQ_RUNTIME_AUTHORITY):
        reject(
            "ordinary-wallet plan excluded runtime-authority source became reachable; "
            f"{PIN_REVIEW_BOUNDARY}"
        )

    allowed_callers = set(authority_sources) | {
        f"crates/ordinary-wallet-plan/{relative}" for relative in PRODUCTION_FILES
    }
    if any(
        caller not in allowed_callers
        or target not in EXPECTED_RUNTIME_AUTHORITY_SOURCE_SHA256
        or count < 1
        for caller, target, _, count in EXPECTED_RUNTIME_AUTHORITY_CALL_EDGES
    ):
        reject(
            "ordinary-wallet plan runtime-authority call-edge inventory changed; "
            f"{PIN_REVIEW_BOUNDARY}"
        )

    source_text = {}
    for relative, expected_hash in EXPECTED_RUNTIME_AUTHORITY_SOURCE_SHA256.items():
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            reject(
                "ordinary-wallet plan runtime-authority source inventory changed; "
                f"{PIN_REVIEW_BOUNDARY}"
            )
        source_text[relative] = path.read_text()
        if sha256_bytes(path.read_bytes()) != expected_hash:
            reject(
                "ordinary-wallet plan reviewed runtime-authority source bytes changed; "
                f"{PIN_REVIEW_BOUNDARY}"
            )

    for caller, _, syntax, expected_count in EXPECTED_RUNTIME_AUTHORITY_CALL_EDGES:
        caller_text = source_text.get(caller)
        if caller_text is None:
            caller_text = (ROOT / caller).read_text()
        if caller_text.count(syntax) != expected_count:
            reject(
                "ordinary-wallet plan runtime-authority call-edge inventory changed; "
                f"{PIN_REVIEW_BOUNDARY}"
            )


def validate_authority_regions() -> None:
    address = (ROOT / "crates" / "address" / "src" / "lib.rs").read_text()
    ordinary_pset = (ROOT / "crates" / "ordinary-pset" / "src" / "lib.rs").read_text()
    wallet_facts = (ROOT / "crates" / "wallet-facts" / "src" / "lib.rs").read_text()
    regions = {
        "address confidential impl": authority_item(
            address, "impl ConfidentialLiquidAddress", "address confidential impl"
        ),
        "address confidential struct": authority_item(
            address,
            "pub struct ConfidentialLiquidAddress",
            "address confidential struct",
        ),
        "address parse expected": authority_item(
            address, "fn parse_expected", "address parse expected"
        ),
        "address parsed impl": authority_item(
            address, "impl ParsedLiquidAddress", "address parsed impl"
        ),
        "address parsed struct": authority_item(
            address, "pub struct ParsedLiquidAddress", "address parsed struct"
        ),
        "address profile enum": authority_item(
            address, "pub enum LiquidAddressProfile", "address profile enum"
        ),
        "address profile impl": authority_item(
            address, "impl LiquidAddressProfile", "address profile impl"
        ),
        "ordinary pset confidential output from address": authority_item(
            ordinary_pset,
            "pub fn from_address",
            "ordinary pset confidential output from address",
        ),
        "ordinary pset confidential output struct": authority_item(
            ordinary_pset,
            "pub struct ConfidentialOutput",
            "ordinary pset confidential output struct",
        ),
        "ordinary pset explicit fee new": authority_item(
            ordinary_pset,
            "pub fn new ( asset : AssetId , value : u64 )",
            "ordinary pset explicit fee new",
        ),
        "ordinary pset explicit fee struct": authority_item(
            ordinary_pset,
            "pub struct ExplicitFee",
            "ordinary pset explicit fee struct",
        ),
        "ordinary pset explicit fee zeroize": authority_item(
            ordinary_pset,
            "impl Zeroize for ExplicitFee",
            "ordinary pset explicit fee zeroize",
        ),
        "wallet facts descriptor catalog drop": authority_item(
            wallet_facts,
            "impl Drop for DescriptorCatalog",
            "wallet facts descriptor catalog drop",
        ),
        "wallet facts descriptor catalog impl": authority_item(
            wallet_facts,
            "impl DescriptorCatalog",
            "wallet facts descriptor catalog impl",
        ),
        "wallet facts descriptor catalog struct": authority_item(
            wallet_facts,
            "pub struct DescriptorCatalog",
            "wallet facts descriptor catalog struct",
        ),
        "wallet facts descriptor network enum": authority_item(
            wallet_facts,
            "pub enum DescriptorNetwork",
            "wallet facts descriptor network enum",
        ),
        "wallet facts prepare selected outputs": authority_item(
            wallet_facts,
            "pub fn prepare_selected_owned_inputs",
            "wallet facts prepare selected outputs",
        ),
        "wallet facts selected output batch impl": authority_item(
            wallet_facts,
            "impl SelectedOutputBatch",
            "wallet facts selected output batch impl",
        ),
        "wallet facts selected output batch struct": authority_item(
            wallet_facts,
            "pub struct SelectedOutputBatch",
            "wallet facts selected output batch struct",
        ),
    }
    actual_hashes = {name: sha256_text(region) for name, region in regions.items()}
    if actual_hashes != EXPECTED_AUTHORITY_REGION_SHA256:
        reject(
            "ordinary-wallet plan reviewed authority-critical dependency region changed; "
            "region pins detect drift only and updating them requires fresh review"
        )

    inventories = {
        "ConfidentialLiquidAddress": inherent_method_inventory(
            address, "ConfidentialLiquidAddress"
        ),
        "ConfidentialOutput": inherent_method_inventory(
            ordinary_pset, "ConfidentialOutput"
        ),
        "DescriptorCatalog": inherent_method_inventory(wallet_facts, "DescriptorCatalog"),
        "ExplicitFee": inherent_method_inventory(ordinary_pset, "ExplicitFee"),
        "LiquidAddressProfile": inherent_method_inventory(address, "LiquidAddressProfile"),
        "ParsedLiquidAddress": inherent_method_inventory(address, "ParsedLiquidAddress"),
        "SelectedOutputBatch": inherent_method_inventory(wallet_facts, "SelectedOutputBatch"),
    }
    if inventories != EXPECTED_INHERENT_METHODS:
        reject("ordinary-wallet plan authority-critical inherent method inventory changed")


def validate_with_compiled_source_files(compiled_files: tuple[str, ...]) -> None:
    actual_files = {
        path.relative_to(CRATE).as_posix()
        for path in CRATE.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_files != EXPECTED_FILES:
        reject("ordinary-wallet plan file inventory mismatch")
    if any(path.is_symlink() for path in CRATE.rglob("*")):
        reject("ordinary-wallet plan symlinks are forbidden")

    validate_manifest_targets()

    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
    )
    package = next(
        item
        for item in metadata["packages"]
        if item["name"] == "wasabi-liquid-native-ordinary-wallet-plan"
    )
    targets = package["targets"]
    target_facts = sorted(
        (
            target["name"],
            tuple(sorted(target["kind"])),
            tuple(sorted(target["crate_types"])),
            Path(target["src_path"]).relative_to(CRATE).as_posix(),
            target["edition"],
            target["doc"],
            target["doctest"],
            target["test"],
        )
        for target in targets
    )
    expected_targets = [
        (
            "preparation",
            ("test",),
            ("bin",),
            "tests/preparation.rs",
            "2024",
            False,
            False,
            True,
        ),
        (
            "wasabi_liquid_native_ordinary_wallet_plan",
            ("rlib",),
            ("rlib",),
            "src/lib.rs",
            "2024",
            True,
            True,
            True,
        ),
    ]
    if target_facts != expected_targets:
        reject("ordinary-wallet plan Cargo metadata target inventory mismatch")

    source = production_text()
    compiled_source = validate_compiled_source_closure_and_pins(source, compiled_files)
    validate_authority_regions()
    validate_runtime_authority_sources_and_edges()
    lexical_source = strip_rust_comments(source)
    validate_process_global_state(source)
    crate_attributes = tuple(
        line.strip()
        for relative in sorted(PRODUCTION_FILES)
        for line in (CRATE / relative).read_text().splitlines()
        if re.match(r"^\s*#!\[.+\]\s*$", line)
    )
    if crate_attributes != EXPECTED_CRATE_ATTRIBUTES:
        reject("ordinary-wallet plan exact crate-level safety attributes changed")
    if module_declarations() != EXPECTED_MODULE_DECLARATIONS:
        reject("ordinary-wallet plan exact module declarations or attributes changed")
    token_attributes = [
        f"{relative}:{attribute}"
        for relative in sorted(PRODUCTION_FILES)
        for attribute in rust_attributes(
            strip_rust_comments((CRATE / relative).read_text())
        )
    ]
    if (
        len(token_attributes) != EXPECTED_TOKEN_ATTRIBUTE_COUNT
        or sha256_text("\n\0\n".join(token_attributes))
        != EXPECTED_TOKEN_ATTRIBUTES_SHA256
    ):
        reject("ordinary-wallet plan tokenized attribute inventory changed")
    attributes = outer_attributes()
    if (
        len(attributes) != EXPECTED_OUTER_ATTRIBUTE_COUNT
        or sha256_text("\n\0\n".join(attributes)) != EXPECTED_OUTER_ATTRIBUTES_SHA256
    ):
        reject("ordinary-wallet plan allowed outer attribute inventory changed")
    item_attributes = public_item_attributes()
    if (
        len(item_attributes) != EXPECTED_PUBLIC_ITEM_ATTRIBUTE_COUNT
        or sha256_text("\n\0\n".join(item_attributes))
        != EXPECTED_PUBLIC_ITEM_ATTRIBUTES_SHA256
    ):
        reject("ordinary-wallet plan public item and signature attributes changed")
    if FORBIDDEN.search(lexical_source):
        reject("ordinary-wallet plan production capability escaped its boundary")
    if re.search(r"(?<![A-Za-z0-9_])unsafe(?![A-Za-z0-9_])", lexical_source):
        reject("ordinary-wallet plan unsafe syntax escaped its forbidden boundary")
    function_like_macros = Counter(
        name for name in FUNCTION_LIKE_MACRO.findall(lexical_source) if name != "if"
    )
    if (
        function_like_macros != Counter({"panic": 1, "thread_local": 1})
        or source.count(EXPECTED_TEST_THREAD_LOCAL) != 1
        or source.count(EXPECTED_TEST_PANIC) != 1
    ):
        reject("ordinary-wallet plan function-like macro surface is not the exact test-only hook")
    validate_dependency_authority_surface(source)
    if source.count("prepare_selected_owned_inputs(") != 1:
        reject("ordinary-wallet plan provider-free preparation call manifest mismatch")
    if source.count("SelectedOutputBatch::new(") != 1:
        reject("ordinary-wallet plan selected-batch call manifest mismatch")
    if public_api(source) != PUBLIC_API:
        reject("ordinary-wallet plan public API inventory mismatch")
    if len(re.findall(r"\bpub\b", source)) != sum(EXPECTED_VISIBILITY_SYNTAX.values()):
        reject("ordinary-wallet plan public token inventory mismatch")
    if visibility_syntax() != EXPECTED_VISIBILITY_SYNTAX:
        reject("ordinary-wallet plan exact visibility and public syntax mismatch")
    lib_source = (CRATE / "src" / "lib.rs").read_text()
    error_enum = braced_item(
        lib_source,
        "pub enum OrdinaryWalletPlanWireError {",
        "error enum",
    )
    if sha256_text(error_enum) != EXPECTED_ERROR_ENUM_SHA256:
        reject("ordinary-wallet plan complete public error enum changed")
    error_behavior = exact_region(
        lib_source,
        "impl OrdinaryWalletPlanWireError {",
        "/// One borrow-only selected-input declaration",
        "error behavior",
    )
    if sha256_text(error_behavior) != EXPECTED_ERROR_BEHAVIOR_SHA256:
        reject("ordinary-wallet plan eight-code error behavior changed")
    signatures = public_signatures()
    signature_inventory = "\n\0\n".join(signatures)
    if (
        len(signatures) != EXPECTED_PUBLIC_SIGNATURE_COUNT
        or sha256_text(signature_inventory) != EXPECTED_PUBLIC_SIGNATURES_SHA256
    ):
        reject("ordinary-wallet plan complete public signature inventory changed")
    impls = trait_impls()
    trait_impl_inventory = "\n\0\n".join(impls)
    if (
        len(impls) != EXPECTED_TRAIT_IMPL_COUNT
        or sha256_text(trait_impl_inventory) != EXPECTED_TRAIT_IMPLS_SHA256
    ):
        reject("ordinary-wallet plan exact allowed trait implementation set changed")

    ordinary_pset = (ROOT / "crates" / "ordinary-pset" / "src" / "lib.rs").read_text()
    explicit_fee_zeroize = exact_region(
        ordinary_pset,
        "impl Zeroize for ExplicitFee {",
        "/// An unblinded ordinary-wallet PSET",
        "explicit-fee zeroize",
    )
    if sha256_text(explicit_fee_zeroize) != EXPECTED_EXPLICIT_FEE_ZEROIZE_SHA256:
        reject("ordinary-wallet plan explicit-fee field zeroization changed")
    fee_lifecycle = exact_region(
        source,
        "struct StagedFee {",
        "struct StagedExpectations(",
        "fee lifecycle",
    )
    if sha256_text(fee_lifecycle) != EXPECTED_PLAN_FEE_LIFECYCLE_SHA256:
        reject("ordinary-wallet plan staged/prepared fee lifecycle changed")
    if ".take()" in fee_lifecycle or "Option<ExplicitFee>" in fee_lifecycle:
        reject("ordinary-wallet plan fee cleanup may not rely on Option take")

    context = re.search(
        r"fn reviewed_context\(.*?\n\}\n\nfn encode_view",
        source,
        flags=re.DOTALL,
    )
    if context is None:
        reject("ordinary-wallet plan reviewed context function is missing")
    context_text = context.group(0)
    exact_counts = {
        "(&MAINNET_MANIFEST, &MAINNET_PEGGED_ASSET)": 1,
        "LiquidAddressProfile::LiquidMainnet": 1,
        "DescriptorNetwork::Mainnet": 1,
        "(&TESTNET_MANIFEST, &TESTNET_PEGGED_ASSET)": 1,
        "LiquidAddressProfile::LiquidTestnet": 1,
        "DescriptorNetwork::Test": 1,
        "_ => None": 1,
    }
    if any(context_text.count(text) != count for text, count in exact_counts.items()):
        reject("ordinary-wallet plan exact two-context mapping mismatch")

    compiled_lexical_source = strip_rust_comments(compiled_source)
    if (
        FORBIDDEN.search(compiled_lexical_source)
        or re.search(r"(?<![A-Za-z0-9_])unsafe(?![A-Za-z0-9_])", compiled_lexical_source)
        or re.search(r"\b(?:use|extern\s+crate)\s+std\b", compiled_lexical_source)
        or FORBIDDEN_ORDINARY_PSET_API.search(compiled_lexical_source)
        or FORBIDDEN_WALLET_FACTS_API.search(compiled_lexical_source)
    ):
        reject("ordinary-wallet plan compiled source closure escaped its boundary")


def main() -> None:
    validate_with_compiled_source_files(compiled_source_files())


if __name__ == "__main__":
    if len(sys.argv) != 1:
        reject("usage: check-ordinary-wallet-plan-surface.py")
    main()
