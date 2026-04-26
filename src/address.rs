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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sui_address_display() {
        let addr = SuiAddress::new([1u8; 32]).unwrap();

        assert_eq!(addr.to_string(), format!("0x{}", hex::encode([1u8; 32])));
        assert_eq!(addr.to_string().len(), 66);
    }

    #[test]
    fn test_sui_address_from_str_with_0x() {
        let raw = [1u8; 32];
        let s = format!("0x{}", hex::encode(raw));

        let addr = s.parse::<SuiAddress>().unwrap();

        assert_eq!(addr.to_string(), s);
    }

    #[test]
    fn test_sui_address_from_str_without_0x() {
        let raw = [2u8; 32];
        let s = hex::encode(raw);

        let addr = s.parse::<SuiAddress>().unwrap();

        assert_eq!(addr.to_string(), format!("0x{}", s));
    }
    #[test]
    fn test_sui_address_from_str_invalid_length_error() {
        let err = "0x1234".parse::<SuiAddress>().unwrap_err();

        assert!(matches!(err, AddressError::InvalidCharacterLength(4)));
    }

    #[test]
    fn test_sui_address_from_str_invalid_hex() {
        let s = format!("0x{}", "z".repeat(64));

        let result = s.parse::<SuiAddress>();

        assert!(result.is_err());
    }

    #[test]
    fn test_sui_address_from_str_uppercase_hex() {
        let s = format!("0x{}", "AB".repeat(32));

        let addr = s.parse::<SuiAddress>().unwrap();

        assert_eq!(addr.to_string(), format!("0x{}", "ab".repeat(32)));
    }

    #[test]
    fn test_sui_address_from_public_key() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk = SuiPublicKey::from_secret_key(&sk);

        let addr = SuiAddress::from_public_key(&pk, &SuiFormat::Hex).unwrap();

        assert_eq!(addr.to_string().len(), 66);
        assert!(addr.to_string().starts_with("0x"));
    }

    #[test]
    fn test_sui_address_from_secret_key_matches_public_key() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);

        let pk = SuiPublicKey::from_secret_key(&sk);
        let addr_from_pk = SuiAddress::from_public_key(&pk, &SuiFormat::Hex).unwrap();
        let addr_from_sk = SuiAddress::from_secret_key(&sk, &SuiFormat::Hex).unwrap();

        assert_eq!(addr_from_sk, addr_from_pk);
    }

    #[test]
    fn test_sui_address_to_raw() {
        let raw = [3u8; 32];
        let addr = SuiAddress::new(raw).unwrap();

        let sui_addr = addr.to_raw().unwrap();

        assert_eq!(sui_addr.to_string(), addr.to_string());
    }

    #[test]
    fn test_sui_address_known_vector() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);

        let addr = SuiAddress::from_secret_key(&sk, &SuiFormat::Hex).unwrap();

        assert_eq!(
            addr.to_string(),
            "0x9272473946cc1517b4b254957566d1cbd4baf10d8d16c6a5c23da5818e27d9ca"
        );
    }
}
