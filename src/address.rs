use {
    crate::{format::SuiFormat, public_key::SuiPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    curve25519_dalek::Scalar,
    fastcrypto::hash::{Blake2b256, HashFunction},
    sui_types::base_types::SuiAddress as SuiAddr,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SuiAddress(pub(crate) [u8; 32]);

impl Address for SuiAddress {
    type SecretKey = Scalar;
    type PublicKey = SuiPublicKey;
    type Format = SuiFormat;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        _: &Self::Format,
    ) -> Result<Self, AddressError> {
        SuiPublicKey::from_secret_key(secret_key).to_address(&SuiFormat::Base64)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        _: &Self::Format,
    ) -> Result<Self, AddressError> {
        let pk = public_key.0.as_bytes();
        let mut hasher = Blake2b256::new();
        hasher.update([0u8]); // we deal only with ed25519 public key
        hasher.update(pk);
        let hash = hasher.finalize().digest;
        SuiAddress::new(hash)
    }
}

impl SuiAddress {
    pub fn new(hash: [u8; 32]) -> Result<Self, AddressError> {
        Ok(Self(hash))
    }

    pub fn to_raw(&self) -> Result<SuiAddr, AddressError> {
        SuiAddr::from_bytes(self.0).map_err(|e| AddressError::Message(e.to_string()))
    }
}

impl FromStr for SuiAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr = match s.starts_with("0x") {
            true => &s[2..],
            false => s,
        };
        if addr.len() != 64 {
            return Err(AddressError::InvalidCharacterLength(addr.len()));
        }
        let addr = hex::decode(addr)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&addr);
        Ok(SuiAddress(hash))
    }
}

impl Display for SuiAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "0x{}", hex::encode(self.0))
    }
}
