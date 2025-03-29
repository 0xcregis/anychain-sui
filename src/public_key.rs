use {
    crate::{format::SuiFormat, SuiAddress},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    core::{fmt, str::FromStr},
    curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE as G, Scalar},
    group::GroupEncoding,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiPublicKey(pub ed25519_dalek::PublicKey);

impl PublicKey for SuiPublicKey {
    type SecretKey = Scalar;
    type Address = SuiAddress;
    type Format = SuiFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let public_key = secret_key * G;
        let public_key = public_key.to_bytes();
        let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key).unwrap();
        SuiPublicKey(public_key)
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl FromStr for SuiPublicKey {
    type Err = PublicKeyError;
    fn from_str(_: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl fmt::Display for SuiPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(self.0.to_bytes()).into_string())
    }
}
