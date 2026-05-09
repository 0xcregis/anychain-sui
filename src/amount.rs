//! Definitions for the native SUI token and its fractional MIST.

use {
    anychain_core::{to_basic_unit_u64, Amount, AmountError},
    core::fmt,
    serde::{Deserialize, Serialize},
    std::ops::{Add, Sub},
};

/// Represents the amount of SUI in MIST
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SuiAmount(pub u64);

pub enum Denomination {
    MIST,
    SUI,
}

impl Denomination {
    /// The number of decimal places more than one MIST.
    /// There are 10^9 MIST in one Sui
    fn precision(self) -> u64 {
        match self {
            Denomination::MIST => 0,

            Denomination::SUI => 9,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::MIST => "mist",
                Denomination::SUI => "sui",
            }
        )
    }
}

impl Amount for SuiAmount {}

impl SuiAmount {
    pub fn from_u64(mist: u64) -> Self {
        Self(mist)
    }

    pub fn from_u64_str(value: &str) -> Result<u64, AmountError> {
        match value.parse::<u64>() {
            Ok(mist) => Ok(mist),
            Err(error) => Err(AmountError::Crate("uint", format!("{error:?}"))),
        }
    }
    pub fn from_mist(mist_value: &str) -> Result<Self, AmountError> {
        let mist = Self::from_u64_str(mist_value)?;
        Ok(Self::from_u64(mist))
    }

    pub fn from_sui(sui_value: &str) -> Result<Self, AmountError> {
        let mist_value = to_basic_unit_u64(sui_value, Denomination::SUI.precision());
        let mist = Self::from_u64_str(&mist_value)?;
        Ok(Self::from_u64(mist))
    }
}

impl Add for SuiAmount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for SuiAmount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for SuiAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    fn test_from_mist(mist_value: &str, expected_amount: &str) {
        let amount = SuiAmount::from_mist(mist_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_sui(sui_value: &str, expected_amount: &str) {
        let amount = SuiAmount::from_sui(sui_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    pub struct AmountDenominationTestCase {
        mist: &'static str,
        sui: &'static str,
    }

    const TEST_AMOUNTS: [AmountDenominationTestCase; 2] = [
        AmountDenominationTestCase {
            mist: "0",
            sui: "0",
        },
        AmountDenominationTestCase {
            mist: "1000000000",
            sui: "1",
        },
    ];

    #[test]
    fn test_mist_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_mist(amounts.mist, amounts.mist));
    }

    #[test]
    fn test_sui_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_sui(amounts.sui, amounts.mist));
    }

    fn test_addition(a: &str, b: &str, result: &str) {
        let a = SuiAmount::from_mist(a).unwrap();
        let b = SuiAmount::from_mist(b).unwrap();
        let result = SuiAmount::from_mist(result).unwrap();

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &str, b: &str, result: &str) {
        let a = SuiAmount::from_mist(a).unwrap();
        let b = SuiAmount::from_mist(b).unwrap();
        let result = SuiAmount::from_mist(result).unwrap();

        assert_eq!(result, a.sub(b));
    }
    mod valid_arithmetic {
        use super::*;

        const TEST_VALUES: [(&str, &str, &str); 5] = [
            ("0", "0", "0"),
            ("1", "2", "3"),
            ("100000", "0", "100000"),
            ("123456789", "987654321", "1111111110"),
            ("1000000000000000", "2000000000000000", "3000000000000000"),
        ];

        #[test]
        fn test_valid_addition() {
            TEST_VALUES
                .iter()
                .for_each(|(a, b, c)| test_addition(a, b, c));
        }
    }
}
