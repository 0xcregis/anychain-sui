use crate::{SuiAddress, SuiFormat, SuiPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use base64ct::{Base64, Encoding};
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use sui_sdk_types::{
    hash::Hasher, Address as OffSuiAddr, Argument, Command, Digest, GasPayment,
    Input as OffSuiInput, ObjectReference, ProgrammableTransaction, SplitCoins,
    Transaction as OffSuiTransaction, TransactionExpiration, TransactionKind, TransferObjects,
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
    pub fn to_object_ref(&self) -> Result<ObjectReference, TransactionError> {
        // sui_sdk_types 0.3.1 ObjectReference

        let object_id =
            OffSuiAddr::from_str(&self.id).map_err(|e| TransactionError::Message(e.to_string()))?;
        let digest =
            Digest::from_str(&self.digest).map_err(|e| TransactionError::Message(e.to_string()))?;

        Ok(ObjectReference::new(object_id, self.version, digest))
    }

    pub fn from_object_ref(obj: ObjectReference) -> Self {
        let id = obj.object_id().to_string();
        let version = obj.version();
        let digest = obj.digest().to_string();
        Self {
            id,
            version,
            digest,
        }
    }
}

/*
 gas_payment is required, not optional
 This avoids conflating the gas coin with coins being transferred or split.
 GasPayment explicitly includes the gas objects, owner, price, and budget.
*/
#[derive(Debug, Clone)]
pub struct SuiTransactionParameters {
    pub from: SuiAddress,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub gas_payment: Input,
    pub gas_price: u64,
    pub gas_budget: u64,

    // Raw 32-byte Ed25519 public key
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SuiTransaction {
    pub params: SuiTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedTransactionPayload {
    raw_tx: String,
    signature: String,
}

impl SuiTransaction {
    fn from_sui_sdk_transaction(
        tx: OffSuiTransaction,
        public_key: [u8; 32],
        signature: Option<Vec<u8>>,
    ) -> Result<Self, TransactionError> {
        let from = SuiAddress::new(tx.sender.into_inner())
            .map_err(|e| TransactionError::Message(e.to_string()))?;

        let gas_payment =
            tx.gas_payment.objects.first().cloned().ok_or_else(|| {
                TransactionError::Message("missing gas payment object".to_string())
            })?;

        let outputs = match tx.kind {
            TransactionKind::ProgrammableTransaction(ptb) => Self::decode_outputs(&ptb)?,
            _ => {
                return Err(TransactionError::Message(
                    "unsupported transaction kind for SuiTransaction".to_string(),
                ))
            }
        };

        Ok(Self {
            params: SuiTransactionParameters {
                from,
                inputs: vec![],
                outputs,
                gas_payment: Input::from_object_ref(gas_payment),
                gas_price: tx.gas_payment.price,
                gas_budget: tx.gas_payment.budget,
                public_key,
            },
            signature,
        })
    }

    fn decode_outputs(ptb: &ProgrammableTransaction) -> Result<Vec<Output>, TransactionError> {
        let mut outputs = Vec::new();

        for (command_index, command) in ptb.commands.iter().enumerate() {
            let Command::SplitCoins(split) = command else {
                continue;
            };

            if !matches!(split.coin, Argument::Gas) || split.amounts.len() != 1 {
                continue;
            }

            let amount_index = match split.amounts[0] {
                Argument::Input(index) => index as usize,
                _ => continue,
            };

            let Some(Command::TransferObjects(transfer)) = ptb.commands.get(command_index + 1)
            else {
                continue;
            };

            if transfer.objects.len() != 1 {
                continue;
            }

            let expected_result = Argument::NestedResult(command_index as u16, 0);
            if transfer.objects[0] != expected_result {
                continue;
            }

            let recipient_index = match transfer.address {
                Argument::Input(index) => index as usize,
                _ => continue,
            };

            let amount_bytes = match ptb.inputs.get(amount_index) {
                Some(OffSuiInput::Pure(bytes)) => bytes,
                _ => {
                    return Err(TransactionError::Message(format!(
                        "invalid amount input index {amount_index}"
                    )))
                }
            };

            let recipient_bytes = match ptb.inputs.get(recipient_index) {
                Some(OffSuiInput::Pure(bytes)) => bytes,
                _ => {
                    return Err(TransactionError::Message(format!(
                        "invalid recipient input index {recipient_index}"
                    )))
                }
            };

            let amount: u64 = bcs::from_bytes(amount_bytes)
                .map_err(|e| TransactionError::Message(e.to_string()))?;
            let recipient: OffSuiAddr = bcs::from_bytes(recipient_bytes)
                .map_err(|e| TransactionError::Message(e.to_string()))?;
            let to = SuiAddress::new(recipient.into_inner())
                .map_err(|e| TransactionError::Message(e.to_string()))?;

            outputs.push(Output { to, amount });
        }

        Ok(outputs)
    }
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

        let raw_tx = self.to_bytes()?;

        let mut signature_bytes = Vec::with_capacity(1 + rs.len() + self.params.public_key.len());
        signature_bytes.push(0u8);
        signature_bytes.extend_from_slice(&rs);
        signature_bytes.extend_from_slice(&self.params.public_key);

        self.signature = Some(rs);

        serde_json::to_vec(&SignedTransactionPayload {
            raw_tx: Base64::encode_string(&raw_tx),
            signature: Base64::encode_string(&signature_bytes),
        })
        .map_err(|e| TransactionError::Message(e.to_string()))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let params = &self.params;
        let mut ptb_inputs = Vec::<OffSuiInput>::new();
        let mut commands = Vec::<Command>::new();

        // Build a PTB by turning each output into:
        // 1) a pure amount input
        // 2) a pure recipient input
        // 3) SplitCoins(Gas, amount)
        // 4) TransferObjects(split result, recipient)
        for output in &params.outputs {
            let amount_index = ptb_inputs.len() as u16;
            ptb_inputs.push(OffSuiInput::Pure(
                bcs::to_bytes(&output.amount)
                    .map_err(|e| TransactionError::Message(e.to_string()))?,
            ));

            let recipient = output
                .to
                .to_raw()
                .map_err(|e| TransactionError::Message(e.to_string()))?;
            let recipient_index = ptb_inputs.len() as u16;
            ptb_inputs.push(OffSuiInput::Pure(
                bcs::to_bytes(&recipient).map_err(|e| TransactionError::Message(e.to_string()))?,
            ));

            // Remember the split command index so TransferObjects can reference
            // the newly created coin via NestedResult(split_cmd_index, 0).
            let split_cmd_index = commands.len() as u16;

            commands.push(Command::SplitCoins(SplitCoins {
                coin: Argument::Gas,
                amounts: vec![Argument::Input(amount_index)],
            }));

            commands.push(Command::TransferObjects(TransferObjects {
                objects: vec![Argument::NestedResult(split_cmd_index, 0)],
                address: Argument::Input(recipient_index),
            }));
        }

        // Wrap the PTB inputs and commands into a programmable transaction.
        let ptb = ProgrammableTransaction {
            inputs: ptb_inputs,
            commands,
        };

        let sender = params
            .from
            .to_raw()
            .map_err(|e| TransactionError::Message(e.to_string()))?;
        let gas_payment = params.gas_payment.to_object_ref()?;

        // Build the SDK transaction with sender and explicit gas config,
        // then serialize the whole transaction with BCS.
        let tx = OffSuiTransaction {
            kind: TransactionKind::ProgrammableTransaction(ptb),
            sender,
            gas_payment: GasPayment {
                objects: vec![gas_payment],
                owner: sender,
                price: params.gas_price,
                budget: params.gas_budget,
            },
            expiration: TransactionExpiration::None,
        };

        bcs::to_bytes(&tx).map_err(|e| TransactionError::Message(e.to_string()))
    }

    fn from_bytes(stream: &[u8]) -> Result<Self, TransactionError> {
        if let Ok(payload) = serde_json::from_slice::<SignedTransactionPayload>(stream) {
            let raw_tx = Base64::decode_vec(&payload.raw_tx)
                .map_err(|e| TransactionError::Message(e.to_string()))?;

            let mut tx = Self::from_bytes(&raw_tx)?;

            let signature_bytes = Base64::decode_vec(&payload.signature)
                .map_err(|e| TransactionError::Message(e.to_string()))?;

            if signature_bytes.len() != 97 {
                return Err(TransactionError::Message(format!(
                    "Invalid signed payload length {}",
                    signature_bytes.len()
                )));
            }

            if signature_bytes[0] != 0u8 {
                return Err(TransactionError::Message(format!(
                    "Unsupported signature scheme flag {}",
                    signature_bytes[0]
                )));
            }

            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&signature_bytes[65..97]);

            tx.signature = Some(signature_bytes[1..65].to_vec());
            tx.params.public_key = public_key;
            return Ok(tx);
        }

        let tx: OffSuiTransaction =
            bcs::from_bytes(stream).map_err(|e| TransactionError::Message(e.to_string()))?;
        Self::from_sui_sdk_transaction(tx, [0u8; 32], None)
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let bytes = self.to_bytes()?;
        let mut hasher = Hasher::new();
        hasher.update(&bytes);
        Ok(SuiTransactionId(hasher.finalize().into_inner()))
    }
}

impl FromStr for SuiTransaction {
    type Err = TransactionError;

    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(tx.as_bytes())
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SuiTransactionId(pub [u8; 32]);

impl TransactionId for SuiTransactionId {}

impl Display for SuiTransactionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SuiAddress, SuiFormat, SuiPublicKey};
    use anychain_core::PublicKey;
    use ed25519_dalek::Signer;
    use serde_json::Value;

    fn sk_to_addr(bech32_private_key: &str) -> SuiAddress {
        let seed = suiprivkey_to_ed25519(bech32_private_key);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = SuiPublicKey(signing_key.verifying_key());
        pubkey.to_address(&SuiFormat::Hex).unwrap()
    }

    fn sk_to_pk(bech32_private_key: &str) -> [u8; 32] {
        let seed = suiprivkey_to_ed25519(bech32_private_key);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = SuiPublicKey(signing_key.verifying_key());
        pubkey.0.to_bytes()
    }
    fn suiprivkey_to_ed25519(key: &str) -> [u8; 32] {
        let (hrp, data) = bech32::decode(key).expect("Invalid bech32 string");
        assert_eq!(hrp.as_str(), "suiprivkey", "Invalid HRP");
        assert_eq!(
            data[0], 0x00,
            "Invalid signature scheme flag, expected 0x00 (Ed25519)"
        );
        data[1..].try_into().expect("Invalid private key length")
    }

    fn sk_sign(bech32_private_key: &str, message: &[u8]) -> Vec<u8> {
        let seed = suiprivkey_to_ed25519(bech32_private_key);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        signing_key.sign(message).to_bytes().to_vec()
    }

    #[test]
    fn test_tx_fixed_input() {
        let sk_from = "suiprivkey1qzjx78cfcqww8prl6cw569rgz3v095a5qc3kae93374nhn23r9w0xqh7628";
        let sk_to = "suiprivkey1qz4geqyqpa83waxmnf2vr80qemktms0gzthy5r07j4naaettnvwpkf6swws";

        let from = sk_to_addr(sk_from);
        let to = sk_to_addr(sk_to);

        assert_eq!(
            "0x9c8400f7d8bdd5a44ec6a481b6390de282bccb1cf3cb993041e22facba39829f",
            from.to_string()
        );
        assert_eq!(
            "0x31740f7baab504daf514d1cdb99965b921c50309c7410ecc98d9ccba13568ad7",
            to.to_string()
        );

        let gas_budget = 5000000;
        let gas_price = 1250;
        let public_key = sk_to_pk(sk_from);

        let tx = SuiTransactionParameters {
            from,
            inputs: fixed_coins(3),
            outputs: vec![
                Output {
                    to: to.clone(),
                    amount: 10000,
                },
                Output { to, amount: 20000 },
            ],
            gas_payment: fixed_coin(9),
            gas_price,
            gas_budget,
            public_key,
        };

        let tx_res = SuiTransaction::new(&tx);
        assert!(tx_res.is_ok());

        let mut tx = tx_res.unwrap();
        let raw_tx = tx.to_bytes().unwrap();
        let decoded: OffSuiTransaction = bcs::from_bytes(&raw_tx).unwrap();
        let decoded_from_raw = SuiTransaction::from_bytes(&raw_tx).unwrap();

        /*
            Assert decoded transaction fields match original parameters
            - sender
            - gas payment, gas price/budget from the transaction fields
            - outputs from the programmable transaction commands/inputs
        */
        assert_eq!(decoded.sender, tx.params.from.to_raw().unwrap());
        assert_eq!(decoded.gas_payment.objects.len(), 1);
        assert_eq!(decoded.gas_payment.owner, tx.params.from.to_raw().unwrap());
        assert_eq!(decoded.gas_payment.price, gas_price);
        assert_eq!(decoded.gas_payment.budget, gas_budget);
        assert!(decoded_from_raw.signature.is_none());
        assert_eq!(
            decoded_from_raw.params.from.to_string(),
            tx.params.from.to_string()
        );
        assert_eq!(
            decoded_from_raw.params.outputs.len(),
            tx.params.outputs.len()
        );
        assert_eq!(decoded_from_raw.params.outputs[0].amount, 10000);
        assert_eq!(decoded_from_raw.params.outputs[1].amount, 20000);
        assert_eq!(decoded_from_raw.params.inputs.len(), 0);
        assert_eq!(decoded_from_raw.params.public_key, [0u8; 32]);

        match decoded.kind {
            TransactionKind::ProgrammableTransaction(ptb) => {
                assert_eq!(ptb.inputs.len(), tx.params.outputs.len() * 2);
                assert_eq!(ptb.commands.len(), tx.params.outputs.len() * 2);
            }
            other => panic!("expected programmable transaction, got {other:?}"),
        }

        let txid = tx.to_transaction_id().unwrap().0;
        assert_eq!(tx.to_transaction_id().unwrap().0, txid);
        assert_eq!(tx.to_transaction_id().unwrap().to_string().len(), 66);

        let sig = sk_sign(sk_from, &txid);
        let expected_pk = sk_to_pk(sk_from);

        let signed = tx.sign(sig.clone(), 0).unwrap();
        let payload = serde_json::from_slice::<Value>(&signed).unwrap();
        let raw_tx_b64 = payload["raw_tx"].as_str().unwrap();
        let sig_b64 = payload["signature"].as_str().unwrap();

        assert_eq!(raw_tx_b64, Base64::encode_string(&raw_tx));
        assert_eq!("AD0z12exlBBSUt2/KsalNmCXos6ZV0aYMbSG1CImLwT82kpi6i17I6vDYjhKiTbm645qJ0aGL7dhRVHlM6tXsgMsjJ4+cC5bSI90eMpbSUkNUxTxyKtF9HEG9Pf9bXfNDw==", sig_b64);
        assert_eq!("AAAEAAgQJwAAAAAAAAAgMXQPe6q1BNr1FNHNuZlluSHFAwnHQQ7MmNnMuhNWitcACCBOAAAAAAAAACAxdA97qrUE2vUU0c25mWW5IcUDCcdBDsyY2cy6E1aK1wQCAAEBAAABAQMAAAAAAQEAAgABAQIAAQEDAgAAAAEDAJyEAPfYvdWkTsakgbY5DeKCvMsc88uZMEHiL6y6OYKfAQoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKJQAAAAAAAAAgbm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm6chAD32L3VpE7GpIG2OQ3igrzLHPPLmTBB4i+sujmCn+IEAAAAAAAAQEtMAAAAAAAA", raw_tx_b64);

        let decoded_sig = Base64::decode_vec(sig_b64).unwrap();
        assert_eq!(decoded_sig.len(), 97);
        assert_eq!(decoded_sig[0], 0u8);
        assert_eq!(&decoded_sig[1..65], sig.as_slice());
        assert_eq!(&decoded_sig[65..97], expected_pk.as_slice());

        let decoded_signed = SuiTransaction::from_bytes(&signed).unwrap();
        assert_eq!(decoded_signed.signature.unwrap(), sig);
        assert_eq!(decoded_signed.params.public_key, expected_pk);
    }

    fn fixed_coins(n: u8) -> Vec<Input> {
        let mut coins = vec![];
        for i in 0..n {
            coins.push(fixed_coin(i));
        }
        coins
    }

    fn fixed_coin(seed: u8) -> Input {
        Input {
            id: format!("0x{}", hex::encode([seed + 1; 32])),
            version: 37,
            digest: bs58::encode([seed + 101; 32]).into_string(),
        }
    }
}
