use anychain_core::Format;
use std::fmt::Display;

#[derive(Hash, Clone, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum SuiFormat {
    Hex,
    // Base64, No address format other than hex is used in Sui
}

impl Format for SuiFormat {}

impl Display for SuiFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hex")
    }
}
