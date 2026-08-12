use std::str::FromStr;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::serialize;
use elements::hashes::sha256;
use elements::secp256k1_zkp::{Secp256k1, SecretKey};
use elements::{
    Address, AddressParams, AssetId, LockTime, OutPoint, RangeProof, RangeProofMessage, Script,
    Sequence, Transaction, TxIn, TxOut, TxOutSecrets, TxOutWitness,
};
use miniscript::Descriptor;
use miniscript::bitcoin::NetworkKind;
use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use miniscript::descriptor::DescriptorPublicKey;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use wasabi_liquid_native_address::{ConfidentialLiquidAddress, LiquidAddressProfile};
use wasabi_liquid_native_ordinary_pset::ConfidentialOutput;
use wasabi_liquid_native_output_opening::{OpenedOutput, open_confidential_output};
use wasabi_liquid_native_wallet_facts::{
    BorrowedSelectedOutput, DescriptorCatalog, DescriptorNetwork, SelectedOutputBatch,
    SelectedOutputOpeningProvider,
};

pub const TEST_PUBLIC_DESCRIPTOR: &str = "elwpkh([28b3f14e/84'/1'/0']tpubDC2Q4xK4XH72GM7MowNuajyWVbigRLBWKswyP5T88hpPwu5nGqJWnda8zhJEFt71av73Hm8mUMMFSz9acNVzz8b1UbdSHCDXKTbSv5eEytu/<0;1>/*)";

pub struct FundingFixture {
    pub transaction: Transaction,
    pub transaction_bytes: Vec<u8>,
    pub previous_transaction_bytes: Vec<u8>,
    pub fee_asset: AssetId,
    pub second_asset: AssetId,
    pub slip77: [u8; 32],
}

pub struct FixtureOpeningProvider {
    slip77: [u8; 32],
    calls: usize,
    refuse_at: Option<usize>,
    panic_at: Option<usize>,
    substitute_at: Option<(usize, TxOut)>,
    seen_scripts: Vec<Vec<u8>>,
}

impl FixtureOpeningProvider {
    pub fn new(fixture: &FundingFixture) -> Self {
        Self::with_material(fixture.slip77)
    }

    pub fn with_material(slip77: [u8; 32]) -> Self {
        Self {
            slip77,
            calls: 0,
            refuse_at: None,
            panic_at: None,
            substitute_at: None,
            seen_scripts: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn refusing(fixture: &FundingFixture, call: usize) -> Self {
        let mut provider = Self::new(fixture);
        provider.refuse_at = Some(call);
        provider
    }

    #[allow(dead_code)]
    pub fn panicking(fixture: &FundingFixture, call: usize) -> Self {
        let mut provider = Self::new(fixture);
        provider.panic_at = Some(call);
        provider
    }

    #[allow(dead_code)]
    pub fn substituting(fixture: &FundingFixture, call: usize, output: TxOut) -> Self {
        let mut provider = Self::new(fixture);
        provider.substitute_at = Some((call, output));
        provider
    }

    #[allow(dead_code)]
    pub const fn calls(&self) -> usize {
        self.calls
    }

    #[allow(dead_code)]
    pub fn seen_scripts(&self) -> &[Vec<u8>] {
        &self.seen_scripts
    }
}

impl SelectedOutputOpeningProvider for FixtureOpeningProvider {
    fn open_selected_output(
        &mut self,
        secp: &Secp256k1<elements::secp256k1_zkp::All>,
        output: &TxOut,
    ) -> Option<OpenedOutput> {
        let call = self.calls;
        self.calls += 1;
        self.seen_scripts
            .push(output.script_pubkey.as_bytes().to_vec());
        if self.panic_at == Some(call) {
            panic!("test-only opening provider unwind");
        }
        if self.refuse_at == Some(call) {
            return None;
        }
        let output = self
            .substitute_at
            .as_ref()
            .filter(|(substitute_call, _)| *substitute_call == call)
            .map_or(output, |(_, substitute)| substitute);
        let key =
            ScopedFixtureBlindingKey(slip77_key(&self.slip77, output.script_pubkey.as_bytes()));
        open_confidential_output(secp, output, &key.0).ok()
    }
}

struct ScopedFixtureBlindingKey(SecretKey);

impl Drop for ScopedFixtureBlindingKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

pub fn catalog() -> DescriptorCatalog {
    DescriptorCatalog::derive(TEST_PUBLIC_DESCRIPTOR, DescriptorNetwork::Test, 1).unwrap()
}

pub fn funding_fixture() -> FundingFixture {
    funding_fixture_for_scripts(descriptor_scripts())
}

#[allow(dead_code)]
pub fn signable_funding_fixture() -> (DescriptorCatalog, FundingFixture, [SecretKey; 2]) {
    let mut seed = synthetic_material(b"ordinary wallet signing descriptor seed");
    let mut root = Xpriv::new_master(NetworkKind::Test, &seed).unwrap();
    seed.fill(0);
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
    let public = Xpub::from_priv(&secp, &root);
    let descriptor = format!("elwpkh({public}/<0;1>/*)");
    let catalog = DescriptorCatalog::derive(&descriptor, DescriptorNetwork::Test, 1).unwrap();
    let mut external = root
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ]),
        )
        .unwrap();
    let mut internal = root
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![
                ChildNumber::Normal { index: 1 },
                ChildNumber::Normal { index: 1 },
            ]),
        )
        .unwrap();
    let signing_keys = [
        SecretKey::from_slice(&external.private_key.secret_bytes()).unwrap(),
        SecretKey::from_slice(&internal.private_key.secret_bytes()).unwrap(),
    ];
    external.private_key.non_secure_erase();
    internal.private_key.non_secure_erase();
    root.private_key.non_secure_erase();
    let signing_secp = Secp256k1::new();
    let scripts = signing_keys.each_ref().map(|key| {
        let public_key = elements::bitcoin::PublicKey::new(key.public_key(&signing_secp));
        Script::new_v0_wpkh(&public_key.wpubkey_hash().unwrap())
    });
    let fixture = funding_fixture_for_scripts(scripts);
    (catalog, fixture, signing_keys)
}

fn funding_fixture_for_scripts([external_script, internal_script]: [Script; 2]) -> FundingFixture {
    let slip77 = synthetic_material(b"ordinary wallet PSET SLIP77 material");
    let fee_asset = AssetId::LIQUIDTESTNET_BTC;
    let second_asset = AssetId::from_byte_array([0x82; 32]);
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(fee_asset, 1_000, Script::from(vec![0x51])),
            explicit_output(second_asset, 2_000, Script::from(vec![0x51])),
        ],
    };
    let spent_secrets = [
        TxOutSecrets::new(
            fee_asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        ),
        TxOutSecrets::new(
            second_asset,
            AssetBlindingFactor::zero(),
            2_000,
            ValueBlindingFactor::zero(),
        ),
    ];
    let secp = Secp256k1::new();
    let external_key = slip77_key(&slip77, external_script.as_bytes());
    let internal_key = slip77_key(&slip77, internal_script.as_bytes());
    let external_address = Address::from_script(
        &external_script,
        Some(external_key.public_key(&secp)),
        &AddressParams::ELEMENTS,
    )
    .unwrap();
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET funding fixture randomness",
    ));
    let (first_output, first_abf, first_vbf, _) = TxOut::new_not_last_confidential(
        &mut rng,
        &secp,
        900,
        &external_address,
        fee_asset,
        &spent_secrets,
    )
    .unwrap();
    let first_output_secrets = TxOutSecrets::new(fee_asset, first_abf, 900, first_vbf);
    let fee_secrets = TxOutSecrets::new(
        fee_asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let (second_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        2_000,
        second_asset,
        internal_script,
        internal_key.public_key(&secp),
        &spent_secrets,
        &[&first_output_secrets, &fee_secrets],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            input(OutPoint::new(previous.txid(), 0)),
            input(OutPoint::new(previous.txid(), 1)),
        ],
        output: vec![first_output, second_output, TxOut::new_fee(100, fee_asset)],
    };

    FundingFixture {
        transaction_bytes: serialize(&transaction),
        previous_transaction_bytes: serialize(&previous),
        transaction,
        fee_asset,
        second_asset,
        slip77,
    }
}

pub fn selected_batch(fixture: &FundingFixture, output_indices: &[u32]) -> SelectedOutputBatch {
    let previous = std::slice::from_ref(&fixture.previous_transaction_bytes);
    let expectations = output_indices
        .iter()
        .map(|index| {
            let (asset, value) = match index {
                0 => (fixture.fee_asset, 900),
                1 => (fixture.second_asset, 2_000),
                2 => (fixture.fee_asset, 100),
                _ => (fixture.fee_asset, 1),
            };
            (
                OutPoint::new(fixture.transaction.txid(), *index),
                asset,
                value,
            )
        })
        .collect::<Vec<_>>();
    let requests = expectations
        .iter()
        .map(|(outpoint, asset, value)| {
            BorrowedSelectedOutput::new(
                outpoint,
                asset,
                value,
                &fixture.transaction_bytes,
                previous,
            )
        })
        .collect::<Vec<_>>();
    SelectedOutputBatch::new(&requests).unwrap()
}

pub fn planned_outputs(fixture: &FundingFixture) -> Vec<ConfidentialOutput> {
    vec![
        ConfidentialOutput::from_address(fixture.second_asset, 2_000, &receive_address()).unwrap(),
        ConfidentialOutput::from_address(fixture.fee_asset, 800, &second_receive_address())
            .unwrap(),
    ]
}

#[allow(dead_code)]
pub fn zero_opening_output(fixture: &FundingFixture) -> TxOut {
    let script_pubkey = descriptor_scripts()[0].clone();
    let secp = Secp256k1::new();
    let receiver_key = slip77_key(&fixture.slip77, script_pubkey.as_bytes());
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET provider zero-opening output",
    ));
    let spent_secrets = [TxOutSecrets::new(
        fixture.fee_asset,
        AssetBlindingFactor::zero(),
        1_000,
        ValueBlindingFactor::zero(),
    )];
    let secrets = TxOutSecrets::new(
        fixture.fee_asset,
        AssetBlindingFactor::new(&mut rng),
        0,
        ValueBlindingFactor::new(&mut rng),
    );
    let (asset, surjection_proof) = Asset::Explicit(secrets.asset)
        .blind(&mut rng, &secp, secrets.asset_bf, &spent_secrets)
        .unwrap();
    let message = RangeProofMessage::new(secrets.asset, secrets.asset_bf);
    let asset_generator = message.commitment(&secp);
    let value = Value::new_confidential(&secp, 0, asset_generator, secrets.value_bf);
    let value_commitment = value.commitment().unwrap();
    let (nonce, shared_secret) =
        Nonce::new_confidential(&mut rng, &secp, &receiver_key.public_key(&secp));
    let rangeproof = RangeProof::new(
        &secp,
        0,
        value_commitment,
        0,
        secrets.value_bf.into_inner(),
        &message.to_byte_array(),
        script_pubkey.as_bytes(),
        shared_secret,
        0,
        52,
        asset_generator,
    )
    .unwrap();

    TxOut {
        asset,
        value,
        nonce,
        script_pubkey,
        witness: TxOutWitness {
            surjection_proof,
            rangeproof,
        },
    }
}

pub fn receive_address() -> ConfidentialLiquidAddress {
    receive_address_for(0, b"ordinary wallet PSET first receiver blinding key")
}

pub fn second_receive_address() -> ConfidentialLiquidAddress {
    receive_address_for(1, b"ordinary wallet PSET second receiver blinding key")
}

fn receive_address_for(index: usize, key_label: &[u8]) -> ConfidentialLiquidAddress {
    let script = descriptor_scripts()[index].clone();
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&synthetic_material(key_label)).unwrap();
    let address = Address::from_script(
        &script,
        Some(key.public_key(&secp)),
        &AddressParams::ELEMENTS,
    )
    .unwrap();
    ConfidentialLiquidAddress::parse(&address.to_string(), LiquidAddressProfile::ElementsDefault)
        .unwrap()
}

pub fn synthetic_material(label: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(label).to_byte_array()
}

fn descriptor_scripts() -> [Script; 2] {
    let inner = TEST_PUBLIC_DESCRIPTOR
        .strip_prefix("elwpkh(")
        .and_then(|value| value.strip_suffix(')'))
        .unwrap();
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&format!("wpkh({inner})"))
        .unwrap()
        .into_single_descriptors()
        .unwrap();
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::verification_only();
    let first = descriptor[0]
        .at_derivation_index(0)
        .unwrap()
        .derived_descriptor(&secp)
        .unwrap();
    let second = descriptor[1]
        .at_derivation_index(1)
        .unwrap()
        .derived_descriptor(&secp)
        .unwrap();
    [
        Script::from(first.script_pubkey().into_bytes()),
        Script::from(second.script_pubkey().into_bytes()),
    ]
}

fn slip77_key(master_key: &[u8; 32], script: &[u8]) -> SecretKey {
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (index, key_byte) in master_key.iter().enumerate() {
        inner_pad[index] ^= key_byte;
        outer_pad[index] ^= key_byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(script);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    SecretKey::from_slice(&outer.finalize()).unwrap()
}

fn explicit_output(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        asset_issuance: Default::default(),
        witness: Default::default(),
    }
}
