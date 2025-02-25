use crate::{address::SuiAddress, format::SuiFormat, SuiPrivateKey, SuiPublicKey};
use anychain_core::{Address, Transaction, TransactionError, TransactionId};

use base64::engine::{general_purpose::STANDARD, Engine};
use core::str::FromStr;
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519Signature},
    hash::{Blake2b256, HashFunction},
    traits::KeyPair,
};
use serde_json::{from_str, json, Value};
use shared_crypto::intent::{Intent, IntentMessage};
use std::fmt::Display;
use sui_types::{
    base_types::{ObjectID, SequenceNumber, SuiAddress as RawSuiAddress},
    crypto::{Signer, ToFromBytes},
    digests::ObjectDigest,
    transaction::{
        Argument, CallArg, Command, ObjectArg, TransactionData, TransactionDataAPI, TransactionKind,
    },
};

#[derive(Debug, Clone)]
pub struct Input {
    pub id: String,
    pub version: u64,
    pub digest: String,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub to: SuiAddress,
    pub amount: u64,
}

impl Input {
    pub fn to_object_ref(
        &self,
    ) -> Result<(ObjectID, SequenceNumber, ObjectDigest), TransactionError> {
        let object_id =
            ObjectID::from_str(&self.id).map_err(|e| TransactionError::Message(e.to_string()))?;
        let sequence = SequenceNumber::from_u64(self.version);
        let digest = ObjectDigest::from_str(&self.digest)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        Ok((object_id, sequence, digest))
    }

    pub fn from_object_ref(obj: (ObjectID, SequenceNumber, ObjectDigest)) -> Self {
        let id = obj.0.to_string();
        let version = obj.1.value();
        let digest = obj.2.to_string();
        Self {
            id,
            version,
            digest,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SuiTransactionParameters {
    pub from: SuiAddress,
    // suix_getCoins(from, token_type)
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub gas_payment: Option<Input>,
    pub gas_price: u64,
    pub gas_budget: u64,
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
        Ok(SuiTransaction {
            params: params.clone(),
            signature: None,
        })
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

        let gas_budget = self.params.gas_budget;
        let gas_price = self.params.gas_price;

        let mut coins = vec![];
        let mut recipients = vec![];
        let mut amounts = vec![];

        for input in &self.params.inputs {
            let coin = input.to_object_ref()?;
            coins.push(coin);
        }

        for output in &self.params.outputs {
            recipients.push(output.to.to_raw());
            amounts.push(output.amount);
        }

        let data = match &self.params.gas_payment {
            Some(gas) => TransactionData::new_pay(
                from,
                coins,
                recipients,
                amounts,
                gas.to_object_ref()?,
                gas_budget,
                gas_price,
            )
            .map_err(|e| TransactionError::Message(e.to_string()))?,
            None => {
                let gas = coins.pop();
                TransactionData::new_pay_sui(
                    from,
                    coins,
                    recipients,
                    amounts,
                    gas.unwrap(),
                    gas_budget,
                    gas_price,
                )
                .map_err(|e| TransactionError::Message(e.to_string()))?
            }
        };

        match &self.signature {
            Some(sig) => {
                let flag = vec![0u8]; // 0 indicates ed25519 scheme
                let pk = self.params.public_key.clone();
                let sig = [flag, sig.clone(), pk].concat();

                let raw_tx =
                    bcs::to_bytes(&data).map_err(|e| TransactionError::Message(e.to_string()))?;

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
                let msg =
                    bcs::to_bytes(&msg).map_err(|e| TransactionError::Message(e.to_string()))?;
                Ok(msg)
            }
        }
    }

    fn from_bytes(stream: &[u8]) -> Result<Self, TransactionError> {
        let data = bcs::from_bytes::<TransactionData>(&stream)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let from = SuiAddress::from_str(&data.sender().to_string())?;
        let gas_price = data.gas_price();
        let gas_budget = data.gas_budget();

        let (inputs, outputs) = if let TransactionKind::ProgrammableTransaction(pt) = data.kind() {
            let mut inputs = vec![];
            let mut outputs = vec![];

            match &pt.inputs[0] {
                // we are dealing with token transfer
                CallArg::Object(_) => {
                    for input in &pt.inputs {
                        match input {
                            CallArg::Object(ObjectArg::ImmOrOwnedObject(obj)) => {
                                let input = Input::from_object_ref(obj.clone());
                                inputs.push(input);
                            }
                            _ => break,
                        }
                    }
                }
                // we are dealing with SUI transfer
                CallArg::Pure(_) => {
                    for obj in &data.gas_data().payment {
                        let input = Input::from_object_ref(obj.clone());
                        inputs.push(input);
                    }
                }
            }

            let mut amounts = vec![];
            let mut accounts = vec![];

            for cmd in &pt.commands {
                match cmd {
                    Command::SplitCoins(_, indexes) => {
                        for index in indexes {
                            if let Argument::Input(amount) = index {
                                amounts.push(*amount);
                            }
                        }
                    }
                    Command::TransferObjects(_, index) => {
                        if let Argument::Input(account) = index {
                            accounts.push(*account);
                        }
                    }
                    _ => {}
                }
            }

            let len = accounts.len();

            for i in 0..len {
                let mut amount = 0u64;
                let mut to = SuiAddress::default();
                if let CallArg::Pure(bytes) = &pt.inputs[amounts[i] as usize] {
                    amount = bcs::from_bytes(bytes)
                        .map_err(|e| TransactionError::Message(e.to_string()))?;
                }
                if let CallArg::Pure(bytes) = &pt.inputs[accounts[i] as usize] {
                    let _to = bcs::from_bytes::<RawSuiAddress>(bytes)
                        .map_err(|e| TransactionError::Message(e.to_string()))?;
                    to = SuiAddress::from_str(&_to.to_string())?;
                }
                outputs.push(Output { to, amount });
            }

            (inputs, outputs)
        } else {
            (vec![], vec![])
        };

        Self::new(&SuiTransactionParameters {
            from,
            inputs,
            outputs,
            gas_payment: None,
            gas_price,
            gas_budget,
            public_key: vec![],
        })
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

impl FromStr for SuiTransaction {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let val = from_str::<Value>(&tx)?;
        let raw_tx = val["raw_tx"].as_str().unwrap();
        let raw_tx = STANDARD
            .decode(raw_tx)
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        Self::from_bytes(&raw_tx)
    }
}

mod tests {
    use super::*;
    use rand::{Rng, RngCore};
    use serde_json::Value;

    #[test]
    fn test_tx() {
        let sk_from = "suiprivkey1qzjx78cfcqww8prl6cw569rgz3v095a5qc3kae93374nhn23r9w0xqh7628";
        let sk_to = "suiprivkey1qz4geqyqpa83waxmnf2vr80qemktms0gzthy5r07j4naaettnvwpkf6swws";

        let from = sk_to_addr(sk_from);
        let to = sk_to_addr(sk_to);

        println!("from: {}\nto: {}", from, to);

        let gas_budget = 5000000;
        let gas_price = 1250;

        let public_key = sk_to_pk(sk_from);

        let gas = rand_coin();

        let tx = SuiTransactionParameters {
            from,
            inputs: rand_coins(3),
            outputs: rand_outputs(10),
            gas_payment: Some(gas),
            gas_price,
            gas_budget,
            public_key,
        };

        let mut tx = SuiTransaction::new(&tx).unwrap();

        let txid = tx.to_transaction_id().unwrap().0.to_vec();
        let sig = sk_sign(sk_from, &txid);

        let tx = tx.sign(sig, 0).unwrap();

        let tx = String::from_utf8(tx).unwrap();

        let tx = SuiTransaction::from_str(&tx).unwrap();

        println!("tx = {:?}", tx);
    }

    fn rand_coins(n: u8) -> Vec<Input> {
        let mut coins = vec![];
        for _ in 0..n {
            let coin = rand_coin();
            coins.push(coin);
        }
        coins
    }

    fn rand_outputs(n: u8) -> Vec<Output> {
        let mut outputs = vec![];
        for _ in 0..n {
            let output = rand_output();
            outputs.push(output);
        }
        outputs
    }

    fn rand_output() -> Output {
        let to = rand_array();
        let to = SuiAddress::new(to);
        let amount = 10000;
        Output { to, amount }
    }

    fn rand_coin() -> Input {
        let input = Input {
            id: rand_coin_id(),
            version: 37,
            digest: rand_digest(),
        };
        input
    }

    fn rand_coin_id() -> String {
        let n = rand_array().to_vec();
        let coin_id = hex::encode(n);
        coin_id
    }

    fn rand_digest() -> String {
        let n = rand_array().to_vec();
        let digest = bs58::encode(n).into_string();
        digest
    }

    fn rand_array() -> [u8; 32] {
        let mut rng = rand::thread_rng();
        let mut array = [0u8; 32];
        rng.fill(&mut array);
        array
    }

    fn rand_u64() -> u64 {
        let mut rng = rand::thread_rng();
        rng.next_u64()
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
}
