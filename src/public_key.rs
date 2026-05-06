use {
    crate::{format::SuiFormat, SuiAddress},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    base64ct::{Base64, Encoding},
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
        let bytes = public_key.to_bytes();
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .expect("ed25519 public key should be valid");
        Self(public_key)
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl FromStr for SuiPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 32];

        let decoded = Base64::decode(s, &mut bytes)
            .map_err(|e| PublicKeyError::Crate("from_str", e.to_string()))?;

        if decoded.len() != 32 {
            return Err(PublicKeyError::InvalidCharacterLength(decoded.len()));
        }

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|e| PublicKeyError::Crate("from_str", e.to_string()))?;

        Ok(SuiPublicKey(public_key))
    }
}

impl fmt::Display for SuiPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Base64::encode_string(&self.0.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCALAR_BYTES_SEED_ALICE: [u8; 32] = [
        202, 240, 171, 205, 215, 167, 224, 27, 59, 98, 120, 15, 54, 14, 189, 47, 174, 26, 23, 3,
        82, 134, 81, 182, 155, 193, 118, 192, 136, 190, 243, 14,
    ];

    const SCALAR_BYTES_SEED_BOB: [u8; 32] = [
        244, 236, 138, 247, 95, 55, 67, 44, 199, 164, 153, 95, 55, 238, 52, 98, 10, 196, 14, 137,
        134, 199, 135, 147, 219, 29, 78, 243, 105, 252, 161, 14,
    ];

    #[test]
    fn test_from_secret_key_0x01_0x02() {
        let secret_key = Scalar::from_bytes_mod_order(SCALAR_BYTES_SEED_ALICE);
        let public_key = SuiPublicKey::from_secret_key(&secret_key);

        assert_eq!(
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
            public_key.to_string()
        );

        let secret_key = Scalar::from_bytes_mod_order(SCALAR_BYTES_SEED_BOB);
        let public_key = SuiPublicKey::from_secret_key(&secret_key);
        println!("public key: {}", public_key);

        assert_eq!(
            "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=",
            public_key.to_string()
        )
    }

    #[test]
    fn test_public_key_display_is_base64() {
        let sk = Scalar::from_bytes_mod_order(SCALAR_BYTES_SEED_ALICE);
        let pk = SuiPublicKey::from_secret_key(&sk);

        let encoded = pk.to_string();

        let mut decoded = [0u8; 32];
        Base64::decode(&encoded, &mut decoded).unwrap();

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
        let sk = Scalar::from_bytes_mod_order(SCALAR_BYTES_SEED_ALICE);
        let pk = SuiPublicKey::from_secret_key(&sk);
        let addr = pk.to_address(&SuiFormat::Hex).unwrap();

        assert_eq!(
            pk.to_string(),
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
        );
        assert_eq!(
            addr.to_string(),
            "0x29dfbf688abce7ab43bb8e70cae158ae961196e721440f515482f8ba1684390f"
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
