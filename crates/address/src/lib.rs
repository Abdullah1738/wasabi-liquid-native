#![forbid(unsafe_code)]

use core::fmt;

use elements::secp256k1_zkp::PublicKey;
use elements::{Address, AddressParams};

/// Maximum accepted encoded-address length in bytes.
pub const MAX_ADDRESS_BYTES: usize = 256;

/// Named address-encoding profiles supported by the Wasabi Liquid wallet.
///
/// A matching profile does not authenticate a connected node's genesis or chain identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LiquidAddressProfile {
    /// The standard Liquid mainnet address parameters.
    LiquidMainnet,
    /// The standard Liquid testnet address parameters.
    LiquidTestnet,
    /// Elements' default address parameters, commonly used by regtest environments.
    ElementsDefault,
}

impl LiquidAddressProfile {
    const ALL: [Self; 3] = [
        Self::LiquidMainnet,
        Self::LiquidTestnet,
        Self::ElementsDefault,
    ];

    fn params(self) -> &'static AddressParams {
        match self {
            Self::LiquidMainnet => &AddressParams::LIQUID,
            Self::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
            Self::ElementsDefault => &AddressParams::ELEMENTS,
        }
    }
}

impl fmt::Display for LiquidAddressProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LiquidMainnet => "Liquid mainnet",
            Self::LiquidTestnet => "Liquid testnet",
            Self::ElementsDefault => "Elements default",
        })
    }
}

/// Privacy-redacted failures from address parsing and construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiquidAddressError {
    /// The input is not a valid supported address encoding.
    InvalidEncoding,
    /// The input is valid, but for a different address profile.
    WrongProfile {
        /// The address profile required by the caller.
        expected: LiquidAddressProfile,
        /// The address profile encoded by the address.
        actual: LiquidAddressProfile,
    },
    /// A confidential receive address was required, but no blinding public key was present.
    ConfidentialAddressRequired,
    /// An unconfidential source address was required for confidential-address construction.
    UnconfidentialAddressRequired,
    /// The supplied bytes are not a valid compressed secp256k1 public key.
    InvalidBlindingPublicKey,
}

impl fmt::Display for LiquidAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding => formatter.write_str("invalid Liquid address encoding"),
            Self::WrongProfile { expected, actual } => {
                write!(
                    formatter,
                    "address profile is {actual}; expected {expected}"
                )
            }
            Self::ConfidentialAddressRequired => {
                formatter.write_str("a confidential Liquid address is required")
            }
            Self::UnconfidentialAddressRequired => {
                formatter.write_str("an unconfidential Liquid address is required")
            }
            Self::InvalidBlindingPublicKey => {
                formatter.write_str("invalid compressed blinding public key")
            }
        }
    }
}

impl std::error::Error for LiquidAddressError {}

/// Owned, library-neutral facts extracted from a valid Liquid address.
#[derive(Clone, Eq, PartialEq)]
pub struct ParsedLiquidAddress {
    profile: LiquidAddressProfile,
    canonical_address: String,
    unconfidential_address: String,
    script_pubkey: Vec<u8>,
    blinding_pubkey: Option<[u8; 33]>,
}

impl ParsedLiquidAddress {
    /// Parses an address using exactly the caller-selected address profile.
    pub fn parse(
        encoded: &str,
        expected_profile: LiquidAddressProfile,
    ) -> Result<Self, LiquidAddressError> {
        parse_expected(encoded, expected_profile)
            .map(|address| Self::from_upstream(address, expected_profile))
    }

    fn from_upstream(address: Address, profile: LiquidAddressProfile) -> Self {
        let canonical_address = address.to_string();
        let unconfidential_address = address.to_unconfidential().to_string();
        let script_pubkey = address.script_pubkey().into_bytes();
        let blinding_pubkey = address.blinding_pubkey.as_ref().map(PublicKey::serialize);

        Self {
            profile,
            canonical_address,
            unconfidential_address,
            script_pubkey,
            blinding_pubkey,
        }
    }

    /// Returns the address-encoding profile used to parse the address.
    ///
    /// This value does not authenticate a connected node's genesis or chain identity.
    pub const fn profile(&self) -> LiquidAddressProfile {
        self.profile
    }

    /// Returns the canonical address encoding produced by the pinned library.
    pub fn canonical_address(&self) -> &str {
        &self.canonical_address
    }

    /// Returns the canonical address without its blinding public key.
    pub fn unconfidential_address(&self) -> &str {
        &self.unconfidential_address
    }

    /// Returns the consensus scriptPubKey bytes.
    pub fn script_pubkey(&self) -> &[u8] {
        &self.script_pubkey
    }

    /// Returns the compressed blinding public key when the address is confidential.
    pub const fn blinding_pubkey(&self) -> Option<[u8; 33]> {
        self.blinding_pubkey
    }

    /// Returns whether the address contains a blinding public key.
    pub const fn is_confidential(&self) -> bool {
        self.blinding_pubkey.is_some()
    }
}

impl fmt::Debug for ParsedLiquidAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedLiquidAddress")
            .field("profile", &self.profile)
            .field("is_confidential", &self.is_confidential())
            .field("script_pubkey_length", &self.script_pubkey.len())
            .finish_non_exhaustive()
    }
}

/// A parsed address that is guaranteed to contain a blinding public key.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfidentialLiquidAddress(ParsedLiquidAddress);

impl ConfidentialLiquidAddress {
    /// Parses a receive address and rejects unconfidential encodings.
    pub fn parse(
        encoded: &str,
        expected_profile: LiquidAddressProfile,
    ) -> Result<Self, LiquidAddressError> {
        let parsed = ParsedLiquidAddress::parse(encoded, expected_profile)?;
        if !parsed.is_confidential() {
            return Err(LiquidAddressError::ConfidentialAddressRequired);
        }

        Ok(Self(parsed))
    }

    /// Constructs a confidential address from an unconfidential address and blinding key.
    pub fn from_unconfidential(
        encoded: &str,
        expected_profile: LiquidAddressProfile,
        blinding_pubkey: [u8; 33],
    ) -> Result<Self, LiquidAddressError> {
        let address = parse_expected(encoded, expected_profile)?;
        if address.is_blinded() {
            return Err(LiquidAddressError::UnconfidentialAddressRequired);
        }

        let blinding_pubkey = PublicKey::from_slice(&blinding_pubkey)
            .map_err(|_| LiquidAddressError::InvalidBlindingPublicKey)?;
        let confidential = address.to_confidential(blinding_pubkey);

        Ok(Self(ParsedLiquidAddress::from_upstream(
            confidential,
            expected_profile,
        )))
    }

    /// Returns the guaranteed-confidential parsed facts.
    pub const fn as_parsed(&self) -> &ParsedLiquidAddress {
        &self.0
    }

    /// Consumes the type-state wrapper and returns the parsed facts.
    pub fn into_parsed(self) -> ParsedLiquidAddress {
        self.0
    }
}

impl fmt::Debug for ConfidentialLiquidAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConfidentialLiquidAddress")
            .field(&self.0)
            .finish()
    }
}

fn parse_expected(
    encoded: &str,
    expected_profile: LiquidAddressProfile,
) -> Result<Address, LiquidAddressError> {
    if encoded.is_empty() || encoded.len() > MAX_ADDRESS_BYTES {
        return Err(LiquidAddressError::InvalidEncoding);
    }

    match Address::parse_with_params(encoded, expected_profile.params()) {
        Ok(address) => Ok(address),
        Err(_) => {
            for actual_profile in LiquidAddressProfile::ALL {
                if actual_profile != expected_profile
                    && Address::parse_with_params(encoded, actual_profile.params()).is_ok()
                {
                    return Err(LiquidAddressError::WrongProfile {
                        expected: expected_profile,
                        actual: actual_profile,
                    });
                }
            }

            Err(LiquidAddressError::InvalidEncoding)
        }
    }
}
