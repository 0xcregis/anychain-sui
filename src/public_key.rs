use {
    crate::{format::SuiFormat, SuiAddress},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    core::{fmt, str::FromStr},
    curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE as G, Scalar},
    group::GroupEncoding,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiPublicKey(pub ed25519_dalek::VerifyingKey);

impl PublicKey for SuiPublicKey {
    type SecretKey = Scalar;
    type Address = SuiAddress;
    type Format = SuiFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let public_key = secret_key * G;
        let public_key = public_key.to_bytes();
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_secret_key_0x01_0x02() {
        let secret_key = Scalar::from_bytes_mod_order([1u8; 32]);
        let public_key = SuiPublicKey::from_secret_key(&secret_key);

        assert_eq!(
            "2HLPkZUQbkV9x1aVNMTbBL9bNi5u7rSNYmhe1budKMR2",
            public_key.to_string()
        );

        let secret_key = Scalar::from_bytes_mod_order([2u8; 32]);
        let public_key = SuiPublicKey::from_secret_key(&secret_key);

        assert_eq!(
            "2b8eBNt4G6UineQ2cJBRL9ncYTMgWn6SjMcsyEVgkuAE",
            public_key.to_string()
        )
    }

    #[test]
    fn test_public_key_display_is_base58() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk = SuiPublicKey::from_secret_key(&sk);

        let encoded = pk.to_string();
        let decoded = bs58::decode(encoded).into_vec().unwrap();

        assert_eq!(decoded, pk.0.to_bytes());
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_public_key_to_address() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk = SuiPublicKey::from_secret_key(&sk);

        let addr1 = pk.to_address(&SuiFormat::Hex).unwrap();
        let addr2 = SuiAddress::from_public_key(&pk, &SuiFormat::Hex).unwrap();

        assert_eq!(addr1, addr2);
        assert_eq!(addr1.to_string().len(), 66); // 0x + 64 hex
    }

    #[test]
    fn test_public_key_known_vector() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk = SuiPublicKey::from_secret_key(&sk);
        let addr = pk.to_address(&SuiFormat::Hex).unwrap();

        assert_eq!(
            pk.to_string(),
            "2HLPkZUQbkV9x1aVNMTbBL9bNi5u7rSNYmhe1budKMR2"
        );
        assert_eq!(
            addr.to_string(),
            "0x9272473946cc1517b4b254957566d1cbd4baf10d8d16c6a5c23da5818e27d9ca"
        );
    }

    #[test]
    fn test_public_key_eq_and_clone() {
        let sk = Scalar::from_bytes_mod_order([1u8; 32]);
        let pk1 = SuiPublicKey::from_secret_key(&sk);
        let pk2 = pk1.clone();

        assert_eq!(pk1, pk2);
    }

    // #[test]
    // #[should_panic(expected = "not yet implemented")]
    // fn test_public_key_from_str_invalid_base58() {
    //     assert!("0OIl".parse::<SuiPublicKey>().is_err());
    // }

    // #[test]
    // #[should_panic(expected = "not yet implemented")]
    // fn test_public_key_from_str_invalid_length_1() {
    //     let _ = "abc".parse::<SuiPublicKey>();
    // }

    // #[test]
    // #[should_panic(expected = "not yet implemented")]
    // fn test_public_key_from_str_invalid_length_2() {
    //     let too_short = bs58::encode([1u8; 31]).into_string();
    //     assert!(too_short.parse::<SuiPublicKey>().is_err());
    //
    //     let too_long = bs58::encode([1u8; 33]).into_string();
    //     assert!(too_long.parse::<SuiPublicKey>().is_err());
    // }
}
