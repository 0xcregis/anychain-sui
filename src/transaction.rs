use crate::{SuiAddress, SuiFormat, SuiPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use base64ct::{Base64, Encoding};
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use sui_sdk_types::{
    hash::Hasher, Address as OffSuiAddr, Argument, Command, Digest, GasPayment,
    Input as OffSuiInput, MergeCoins, ObjectReference, ProgrammableTransaction, SplitCoins,
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
    // Keep the gas model aligned with GasPayment.objects.
    pub gas_payment: Vec<Input>,
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

        if tx.gas_payment.objects.is_empty() {
            return Err(TransactionError::Message(
                "missing gas payment object".to_string(),
            ));
        }

        // Preserve all gas objects from the SDK transaction.
        let gas_payment = tx
            .gas_payment
            .objects
            .into_iter()
            .map(Input::from_object_ref)
            .collect();

        let inputs = match &tx.kind {
            TransactionKind::ProgrammableTransaction(ptb) => ptb
                .inputs
                .iter()
                .filter_map(|input| match input {
                    OffSuiInput::ImmutableOrOwned(obj_ref) => {
                        Some(Input::from_object_ref(obj_ref.clone()))
                    }
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };

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
                inputs,
                outputs,
                gas_payment,
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

            let is_valid_source = matches!(split.coin, Argument::Gas | Argument::Input(0));

            if !is_valid_source || split.amounts.len() != 1 {
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

            // Accept both PTB result encodings for compatibility.
            let matches_split_result = transfer.objects[0]
                == Argument::Result(command_index as u16)
                || transfer.objects[0] == Argument::NestedResult(command_index as u16, 0);
            if !matches_split_result {
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
        self.signature = Some(rs);
        self.to_bytes()
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

        let bcs_bytes = if stream.len() >= 3 && stream[0..3] == [0u8; 3] {
            &stream[3..]
        } else {
            stream
        };

        let tx: OffSuiTransaction =
            bcs::from_bytes(bcs_bytes).map_err(|e| TransactionError::Message(e.to_string()))?;
        Self::from_sui_sdk_transaction(tx, [0u8; 32], None)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let raw_bcs = self.get_raw_bcs_bytes()?;

        match &self.signature {
            Some(rs) => {
                let raw_bcs = self.get_raw_bcs_bytes()?;

                let mut signature_bytes =
                    Vec::with_capacity(1 + rs.len() + self.params.public_key.len());
                signature_bytes.push(0u8);
                signature_bytes.extend_from_slice(rs);
                signature_bytes.extend_from_slice(&self.params.public_key);

                serde_json::to_vec(&SignedTransactionPayload {
                    raw_tx: Base64::encode_string(&raw_bcs),
                    signature: Base64::encode_string(&signature_bytes),
                })
                .map_err(|e| TransactionError::Message(e.to_string()))
            }
            None => {
                // Generates the final stream for a hasher (intent [0, 0, 0] prepended to raw BCS bytes)
                let mut intent_msg = vec![0u8; 3];
                intent_msg.extend_from_slice(&raw_bcs);
                Ok(intent_msg)
            }
        }
    }

    /// Returns a deterministic transaction id.
    ///
    /// This is for identification only, not for Sui signing.
    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        let stream = if self.signature.is_some() {
            let mut unsigned_tx = self.clone();
            unsigned_tx.signature = None;
            unsigned_tx.to_bytes()?
        } else {
            self.to_bytes()?
        };
        let mut hasher = Hasher::new();
        hasher.update(&stream);
        Ok(SuiTransactionId(hasher.finalize().into_inner()))
    }
}

impl SuiTransaction {
    fn get_raw_bcs_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let params = &self.params;
        let mut ptb_inputs = Vec::<OffSuiInput>::new();
        let mut commands = Vec::<Command>::new();

        // 1) Add custom token input coin objects to the PTB inputs.
        for input in &params.inputs {
            let obj_ref = input.to_object_ref()?;
            ptb_inputs.push(OffSuiInput::ImmutableOrOwned(obj_ref));
        }

        // 2) If we have multiple token input coins, merge them into the first coin Input(0).
        if params.inputs.len() > 1 {
            commands.push(Command::MergeCoins(MergeCoins {
                coin: Argument::Input(0),
                coins_to_merge: (1..params.inputs.len())
                    .map(|index| Argument::Input(index as u16))
                    .collect(),
            }));
        }

        // 3) Use Argument::Input(0) as the coin source if token inputs are present,
        // otherwise default to Argument::Gas for native SUI transfers.
        let source_coin = if params.inputs.is_empty() {
            Argument::Gas
        } else {
            Argument::Input(0)
        };

        // Build a PTB by turning each output into:
        // 1) a pure amount input
        // 2) a pure recipient input
        // 3) SplitCoins(source_coin, amount)
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
            // the newly created coin via Result(split_cmd_index).
            let split_cmd_index = commands.len() as u16;

            commands.push(Command::SplitCoins(SplitCoins {
                coin: source_coin,
                amounts: vec![Argument::Input(amount_index)],
            }));

            commands.push(Command::TransferObjects(TransferObjects {
                objects: vec![Argument::Result(split_cmd_index)],
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
        if params.gas_payment.is_empty() {
            return Err(TransactionError::Message(
                "missing gas payment object".to_string(),
            ));
        }

        // Convert every gas input into an SDK object reference.
        let gas_payment = params
            .gas_payment
            .iter()
            .map(Input::to_object_ref)
            .collect::<Result<Vec<_>, _>>()?;

        // Build the SDK transaction with sender and explicit gas config,
        // then serialize the whole transaction with BCS.
        let tx = OffSuiTransaction {
            kind: TransactionKind::ProgrammableTransaction(ptb),
            sender,
            gas_payment: GasPayment {
                objects: gas_payment,
                owner: sender,
                price: params.gas_price,
                budget: params.gas_budget,
            },
            expiration: TransactionExpiration::None,
        };

        bcs::to_bytes(&tx).map_err(|e| TransactionError::Message(e.to_string()))
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
    use anyhow::Result;
    use serde_json::Value;
    use std::str::FromStr;
    use sui_rpc::client::Client;
    use sui_sdk_types::{Address, ObjectReference, StructTag, TypeTag};

    use crate::{
        Input, Output, SuiAddress, SuiFormat, SuiPublicKey, SuiTransaction,
        SuiTransactionParameters,
    };
    use anychain_core::{PublicKey, Transaction};

    const PRIVATE_KEY_BECH32_ALICE: &str =
        "suiprivkey1qqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszasa5uj";
    const PRIVATE_KEY_BECH32_BOB: &str =
        "suiprivkey1qqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyucanpq";

    const SUI_TRANSFER_AMOUNT: u64 = 1_000_000; // 0.001 SUI
    const USDC_TRANSFER_AMOUNT: u64 = 10_000; // 0.01 USDC (Alice has sufficient USDC)
    const GAS_BUDGET: u64 = 3_000_000;
    const GAS_PRICE: u64 = 1_000;

    const TESTNET_RPC: &str = "https://fullnode.testnet.sui.io:443";
    const USDC_PACKAGE_ID_TESTNET: &str =
        "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC";

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

    fn usdc_type_tag() -> TypeTag {
        TypeTag::Struct(Box::new(
            StructTag::from_str(USDC_PACKAGE_ID_TESTNET).unwrap(),
        ))
    }

    fn object_ref_from_rpc(coin: sui_rpc::proto::sui::rpc::v2::Object) -> Result<ObjectReference> {
        let object_ref = (&coin.object_reference()).try_into()?;
        Ok(object_ref)
    }

    async fn select_coin_objects(
        owner: Address,
        coin_type: TypeTag,
        amount: u64,
    ) -> Result<Vec<ObjectReference>> {
        let client = Client::new(TESTNET_RPC)?;
        let coins = client.select_coins(&owner, &coin_type, amount, &[]).await?;
        if coins.is_empty() {
            return Err(anyhow::anyhow!(
                "No coins found of type {} for address {}",
                coin_type,
                owner
            ));
        }
        let mut result = Vec::new();
        for coin in coins {
            let proto_object: sui_rpc::proto::sui::rpc::v2::Object = coin;
            result.push(object_ref_from_rpc(proto_object)?);
        }
        Ok(result)
    }

    async fn select_gas_coins(owner: Address, gas_budget: u64) -> Result<Vec<ObjectReference>> {
        let sui_struct_tag = sui_sdk_types::StructTag::sui();
        let coin_type = sui_sdk_types::TypeTag::Struct(Box::new(sui_struct_tag));
        select_coin_objects(owner, coin_type, gas_budget).await
    }

    async fn execute_sui_transaction_jsonrpc(
        http_client: &reqwest::Client,
        raw_tx_b64: &str,
        sig_b64: &str,
    ) -> Result<String> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sui_executeTransactionBlock",
            "params": [
                raw_tx_b64,
                [sig_b64],
                {
                    "showEffects": true
                },
                "WaitForEffectsCert"
            ]
        });

        let response = http_client
            .post("https://sui-testnet.publicnode.com")
            .json(&payload)
            .send()
            .await?;

        let res_json: serde_json::Value = response.json().await?;

        if let Some(error) = res_json.get("error") {
            return Err(anyhow::anyhow!("JSON-RPC error: {:?}", error));
        }

        let digest = res_json
            .get("result")
            .and_then(|r| r.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing digest in response: {:?}", res_json))?;

        Ok(digest.to_string())
    }

    #[tokio::main]
    #[test]
    #[ignore]
    async fn main() -> Result<()> {
        let alice_addr = sk_to_addr(PRIVATE_KEY_BECH32_ALICE);
        let bob_addr = sk_to_addr(PRIVATE_KEY_BECH32_BOB);

        let alice_public_key = sk_to_pk(PRIVATE_KEY_BECH32_ALICE);

        let alice_addr_off = Address::from_str(&alice_addr.to_string()).unwrap();

        let http_client = reqwest::Client::new();

        println!("Alice: {}", alice_addr);
        println!("Bob: {}", bob_addr);

        // ==========================================
        // 1. PERFORM NATIVE SUI TRANSFER (ALICE -> BOB)
        // ==========================================
        println!("\n--- Step 1: Performing SUI Transfer (Alice -> Bob) ---");
        let gas_payment =
            select_gas_coins(alice_addr_off, SUI_TRANSFER_AMOUNT + GAS_BUDGET).await?;
        println!("Selected gas payment coins: {:?}", gas_payment);

        let sui_tx_params = SuiTransactionParameters {
            from: alice_addr.clone(),
            inputs: vec![],
            outputs: vec![Output {
                to: bob_addr.clone(),
                amount: SUI_TRANSFER_AMOUNT,
            }],
            gas_payment: gas_payment
                .iter()
                .cloned()
                .map(Input::from_object_ref)
                .collect(),
            gas_price: GAS_PRICE,
            gas_budget: GAS_BUDGET,
            public_key: alice_public_key,
        };

        let mut sui_tx = SuiTransaction::new(&sui_tx_params)?;

        // Obtain the 32-byte Blake2b hash for pure ed25519 signing
        let sui_txid = sui_tx.to_transaction_id()?;

        // Sign the transaction hash with pure ed25519 algorithm
        let alice_seed = suiprivkey_to_ed25519(PRIVATE_KEY_BECH32_ALICE);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&alice_seed);
        use ed25519_dalek::Signer;
        let sui_sig_bytes = signing_key.sign(&sui_txid.0).to_bytes().to_vec();

        let sui_signed = sui_tx.sign(sui_sig_bytes, 0)?;

        let sui_payload = serde_json::from_slice::<Value>(&sui_signed)?;
        let raw_sui_tx_b64 = sui_payload["raw_tx"].as_str().expect("missing raw_tx");
        let sui_sig_b64 = sui_payload["signature"]
            .as_str()
            .expect("missing signature");

        println!("Executing SUI Transfer...");
        let sui_digest =
            execute_sui_transaction_jsonrpc(&http_client, raw_sui_tx_b64, sui_sig_b64).await?;
        println!("SUI Transfer executed successfully!");
        println!("SUI Transfer Transaction Digest: {}", sui_digest);

        // ==========================================
        // 2. PERFORM CUSTOM TOKEN TRANSFER (ALICE -> BOB)
        // ==========================================
        println!("\n--- Step 2: Performing Custom Token (USDC) Transfer (Alice -> Bob) ---");

        // Select Alice's SUI for gas fees
        let token_gas_payment = select_gas_coins(alice_addr_off, GAS_BUDGET).await?;
        println!(
            "Selected gas payment coins for token transfer: {:?}",
            token_gas_payment
        );

        // Select Alice's USDC objects for the transfer
        let usdc_payment =
            select_coin_objects(alice_addr_off, usdc_type_tag(), USDC_TRANSFER_AMOUNT).await?;
        println!("Selected USDC coin objects: {:?}", usdc_payment);

        let token_tx_params = SuiTransactionParameters {
            from: alice_addr.clone(),
            inputs: usdc_payment
                .iter()
                .cloned()
                .map(Input::from_object_ref)
                .collect(),
            outputs: vec![Output {
                to: bob_addr.clone(),
                amount: USDC_TRANSFER_AMOUNT,
            }],
            gas_payment: token_gas_payment
                .iter()
                .cloned()
                .map(Input::from_object_ref)
                .collect(),
            gas_price: GAS_PRICE,
            gas_budget: GAS_BUDGET,
            public_key: alice_public_key,
        };

        let mut token_tx = SuiTransaction::new(&token_tx_params)?;

        // Obtain the 32-byte Blake2b hash for pure ed25519 signing
        let token_txid = token_tx.to_transaction_id()?;

        // Sign the transaction hash with pure ed25519 algorithm
        let token_sig_bytes = signing_key.sign(&token_txid.0).to_bytes().to_vec();

        let token_signed = token_tx.sign(token_sig_bytes, 0)?;

        let token_payload = serde_json::from_slice::<Value>(&token_signed)?;
        let raw_token_tx_b64 = token_payload["raw_tx"].as_str().expect("missing raw_tx");
        let token_sig_b64 = token_payload["signature"]
            .as_str()
            .expect("missing signature");

        println!("Executing Custom Token (USDC) Transfer...");
        let token_digest =
            execute_sui_transaction_jsonrpc(&http_client, raw_token_tx_b64, token_sig_b64).await?;
        println!("Custom Token Transfer executed successfully!");
        println!("USDC Transfer Transaction Digest: {}", token_digest);

        Ok(())
    }

    #[test]
    fn test_coin_reservation_conversion() {
        use sui_sdk_types::{Address, Digest, ObjectReference, StructTag};
        let coin_struct = StructTag::sui();
        let amount = 1000u64;
        let epoch = 10u64;
        let chain_id = Digest::new([0; 32]);
        let owner =
            Address::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();

        let obj = ObjectReference::coin_reservation(&coin_struct, amount, epoch, chain_id, owner);

        let input = Input::from_object_ref(obj.clone());
        println!("Input: {:?}", input);

        let converted = input.to_object_ref();
        println!("Converted: {:?}", converted);

        match converted {
            Ok(conv) => {
                assert_eq!(obj, conv);
            }
            Err(e) => {
                panic!("Failed to convert: {:?}", e);
            }
        }
    }
}
