use crate::{address::SuiAddress, format::SuiFormat, public_key::SuiKeyPair, utils, SuiPublicKey};
use anychain_core::{AddressError, PublicKey, Transaction, TransactionError, TransactionId};

use fastcrypto::{encoding::{Base58, Encoding}, hash::{Blake2b256, Hash, HashFunction}};
use shared_crypto::intent::{Intent, IntentMessage};
use base64::engine::{Engine, general_purpose::STANDARD};
use std::fmt::Display;
use sui_types::{
    base_types::{ObjectID, ObjectRef, SuiAddress as RawSuiAddress}, crypto::{default_hash, Signature as RawSignature, ToFromBytes}, object::Object, transaction::TransactionData
};
use serde_json::{json, Value};
use core::str::FromStr;

#[derive(Debug, Clone)]
pub struct SuiTransactionParameters {
    pub from: SuiAddress,
    pub to: SuiAddress,
    pub amount: u64,
    pub gas_budget: u64,
    pub gas_price: u64,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SuiTransaction {
    pub params: SuiTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

impl Transaction for SuiTransaction {
    type Address = SuiAddress;
    type Format = SuiFormat;
    type PublicKey = SuiPublicKey;
    type TransactionId = SuiTransactionId;
    type TransactionParameters = SuiTransactionParameters;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(SuiTransaction { params: params.clone(), signature: None})
    }

    fn sign(&mut self, rs: Vec<u8>, recid: u8) -> Result<Vec<u8>, TransactionError> {
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some(rs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let from = self.params.from.to_raw();
        
        let object_id = "0xac8e32d0471a8fe650a809d5fb3dd8fc99b6c7202aa01455baaad9f9517c53ff";
        let object_id = ObjectID::from_str(object_id)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        
        let gas = Object::with_id_owner_for_testing(object_id, from)
            .compute_object_reference();

        let data = TransactionData::new_transfer_sui(
            self.params.to.to_raw(),
            from,
            Some(self.params.amount),
            gas,
            self.params.gas_budget,
            self.params.gas_price,
        );

        let raw_tx = bcs::to_bytes(&data)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        // let msg = IntentMessage::new(Intent::sui_transaction(), data);
        // let raw_tx = bcs::to_bytes(&msg)
        //     .map_err(|e| TransactionError::Message(e.to_string()))?;

        match &self.signature {
            Some(sig) => {
                let flag = vec![0u8]; // 0 indicates ed25519 scheme
                let pk = self.params.public_key.clone();
                let sig = [flag, sig.clone(), pk].concat();

                let raw_tx = STANDARD.encode(raw_tx);
                let sig = STANDARD.encode(sig);

                Ok(json!([raw_tx, sig]).to_string().as_bytes().to_vec())
            }
            None => Ok(raw_tx)
        }
    }

    fn from_bytes(stream: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let mut hasher = Blake2b256::new();
        let bytes = self.to_bytes()?;
        hasher.update(&bytes);
        let hash = hasher.finalize().digest;
        Ok(SuiTransactionId(hash))
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SuiTransactionId([u8; 32]);

impl TransactionId for SuiTransactionId {}

impl Display for SuiTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[test]
fn test_object_id() {
    let object_id = ObjectID::random();
    println!("object_id: {}", object_id);
}

#[test]
fn test() {
    let flag = vec![0u8]; // 0 indicates ed25519 scheme
    let format = &SuiFormat::Hex;

    let from_pk = [177, 212, 63, 234, 239, 192, 246, 9, 235, 235, 146, 97, 147, 205, 50, 42, 81, 190, 242, 142, 212, 247, 57, 84, 153, 89, 7, 172, 131, 208, 76, 118].to_vec();
    let to_pk = [152, 185, 21, 134, 56, 146, 96, 192, 175, 224, 37, 105, 223, 59, 74, 27, 96, 178, 129, 249, 151, 151, 106, 53, 123, 20, 221, 212, 197, 205, 42, 86].to_vec();
    
    let from = [flag.clone(), from_pk.clone()].concat();
    let to = [flag, to_pk].concat();
    
    let from = STANDARD.encode(from);
    let to = STANDARD.encode(to);

    let from = SuiPublicKey::from_str(&from).unwrap();
    let to = SuiPublicKey::from_str(&to).unwrap();

    let from = from.to_address(format).unwrap();
    let to = to.to_address(format).unwrap();

    println!("from: {}\nto: {}", from, to);

    let amount = 1000000000;
    let gas_budget = 300000;
    let gas_price = 750;
    
    let tx = SuiTransactionParameters {
        from,
        to,
        amount,
        gas_budget,
        gas_price,
        public_key: from_pk,
    };

    let mut tx = SuiTransaction::new(&tx).unwrap();
    let txid = tx.to_transaction_id().unwrap();

    println!("txid: {}", txid);

    let r = "c78ca2036917b70b99ccfe2e30e5152693f8045f3a0d031cddd98f4e69563974";
    let s = "e2b9f4d673b8b5ff37b62a6703a96ad6acb3c57f6cbc6a601056990e2c0c0105";
    let recid = 0;

    let r = hex::decode(r).unwrap();
    let s = hex::decode(s).unwrap();

    let rs = [r, s].concat();

    let tx = tx.sign(rs, recid).unwrap();
    let tx = String::from_utf8(tx).unwrap();

    let tx = serde_json::from_str::<Value>(&tx).unwrap();

    println!("{}", tx);
}
