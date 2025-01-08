use crate::{address::SuiAddress, format::SuiFormat, SuiPrivateKey, SuiPublicKey};
use anychain_core::{Address, Transaction, TransactionError, TransactionId};

use fastcrypto::{ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519Signature}, hash::{Blake2b256, HashFunction}, traits::KeyPair};
use base64::engine::{Engine, general_purpose::STANDARD};
use shared_crypto::intent::{Intent, IntentMessage};
use std::fmt::Display;
use sui_types::{
    base_types::{ObjectID, ObjectRef, SequenceNumber}, crypto::{Signer, ToFromBytes}, digests::ObjectDigest, object::Object, transaction::TransactionData
};
use serde_json::{json, Value};
use core::str::FromStr;

#[derive(Debug, Clone)]
pub struct SuiTransactionParameters {
    pub from: SuiAddress,
    pub to: SuiAddress,
    pub amount: u64,
    pub gas_price: u64,
    pub gas_budget: u64,
    pub coin_id: String,
    pub version: u64,
    pub digest: String,
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

    fn sign(&mut self, rs: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
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
        
        let object_id = ObjectID::from_str(&self.params.coin_id)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let sequence = SequenceNumber::from_u64(self.params.version);
        let digest = ObjectDigest::from_str(&self.params.digest)
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let data = TransactionData::new_transfer_sui(
            self.params.to.to_raw(),
            from,
            Some(self.params.amount),
            (object_id, sequence, digest),
            self.params.gas_budget,
            self.params.gas_price,
        );

        match &self.signature {
            Some(sig) => {
                let flag = vec![0u8]; // 0 indicates ed25519 scheme
                let pk = self.params.public_key.clone();
                let sig = [flag, sig.clone(), pk].concat();

                let raw_tx = bcs::to_bytes(&data)
                    .map_err(|e| TransactionError::Message(e.to_string()))?;

                let raw_tx = STANDARD.encode(raw_tx);
                let sig = STANDARD.encode(sig);

                let ret = json!({
                    "raw_tx": raw_tx,
                    "signature": sig,
                });

                Ok(ret.to_string().as_bytes().to_vec())
            }
            None => {
                let msg = IntentMessage::new(Intent::sui_transaction(), data);
                let msg = bcs::to_bytes(&msg)
                    .map_err(|e| TransactionError::Message(e.to_string()))?;
                Ok(msg)
            }
        }
    }

    fn from_bytes(_stream: &[u8]) -> Result<Self, TransactionError> {
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
pub struct SuiTransactionId(pub [u8; 32]);

impl TransactionId for SuiTransactionId {}

impl Display for SuiTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[test]
fn test_tx() {
    let sk_from = "suiprivkey1qzjx78cfcqww8prl6cw569rgz3v095a5qc3kae93374nhn23r9w0xqh7628";
    let sk_to = "suiprivkey1qz4geqyqpa83waxmnf2vr80qemktms0gzthy5r07j4naaettnvwpkf6swws";

    let from = sk_to_addr(sk_from);
    let to = sk_to_addr(sk_to);

    println!("from: {}\nto: {}", from, to);

    let amount = 1000000000;
    let gas_budget = 5000000;
    let gas_price = 1250;

    let coin_id = "0x257bd81166028d49e27261eef408d860ff39542ee12c11595b6bca3a8e26e753".to_string();
    let version = 37;
    let digest = "4TR1LKd3yRJaZSBuLX8QBb3hCHG5JDitQraWWx32jyHz".to_string();

    let public_key = sk_to_pk(sk_from);
    
    let tx = SuiTransactionParameters {
        from,
        to,
        amount,
        gas_price,
        gas_budget,
        coin_id,
        version,
        digest,
        public_key,
    };

    let mut tx = SuiTransaction::new(&tx).unwrap();
    
    let txid = tx.to_transaction_id().unwrap().0.to_vec();
    let sig = sk_sign(sk_from, &txid);

    let tx = tx.sign(sig, 0).unwrap();
    let tx = String::from_utf8(tx).unwrap();

    let tx = serde_json::from_str::<Value>(&tx).unwrap();

    println!("{}", tx);
}

use bech32::FromBase32;

fn sk_to_addr(sk: &str) -> SuiAddress {
    let (_, data, _) = bech32::decode(sk).unwrap();
    let data = Vec::from_base32(&data).unwrap();
    let sk = Ed25519PrivateKey::from_bytes(&data[1..]).unwrap();
    let sk = SuiPrivateKey::Ed25519(sk);
    let addr = SuiAddress::from_secret_key(&sk, &SuiFormat::Hex).unwrap();
    addr
}

fn sk_to_pk(sk: &str) -> Vec<u8> {
    let (_, data, _) = bech32::decode(sk).unwrap();
    let data = Vec::from_base32(&data).unwrap();
    let sk = Ed25519PrivateKey::from_bytes(&data[1..]).unwrap();
    let keypair = Ed25519KeyPair::from(sk);
    let pk = keypair.public();
    let pk = pk.as_bytes();
    pk.to_vec()
}

fn sk_sign(sk: &str, msg: &[u8]) -> Vec<u8> {
    let (_, data, _) = bech32::decode(sk).unwrap();
    let data = Vec::from_base32(&data).unwrap();
    let sk = Ed25519PrivateKey::from_bytes(&data[1..]).unwrap();
    let keypair = Ed25519KeyPair::from(sk);
    let sig: Ed25519Signature = keypair.sign(msg);
    let sig = sig.sig.to_bytes().to_vec();
    sig
}