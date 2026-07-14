// This example test uses `anychain-sui` modules and functions to build,
// encode, decode, sign, and submit a Sui transfer transaction.
use anychain_sui::{
    Input, Output, SuiAddress, SuiFormat, SuiPublicKey, SuiTransaction, SuiTransactionParameters,
};
const PRIVATE_KEY_BECH32_ALICE: &str =
    "suiprivkey1qqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszasa5uj";
const PRIVATE_KEY_BECH32_BOB: &str =
    "suiprivkey1qqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyucanpq";

use anychain_core::{PublicKey, Transaction};
use anyhow::Result;
use base64ct::{Base64, Encoding};
use serde_json::Value;
use std::str::FromStr;
use sui_rpc::{
    client::Client,
    field::{FieldMask, FieldMaskUtil},
    proto::sui::rpc::v2::ExecuteTransactionRequest,
};
use sui_sdk_types::{
    Address, Argument, Command, Input as SdkInput, ObjectReference, Transaction as SdkTransaction,
    TransactionKind, UserSignature,
};

const ADDRESS_ALICE: &str = "0x29dfbf688abce7ab43bb8e70cae158ae961196e721440f515482f8ba1684390f";
const ADDRESS_BOB: &str = "0x7799ea80594c35644321148485238c7a7a1c6549809e1795e6747c6d4da2504c";
const TRANSFER_AMOUNT: u64 = 1_000_000;
const GAS_PRICE: u64 = 1_000;
const GAS_BUDGET: u64 = 3_000_000;

const TESTNET_RPC: &str = "https://fullnode.testnet.sui.io:443";

// Build the same PTB shape as the sui-rust-sdk example:
// SplitCoins(Gas, [Input(0)]) -> TransferObjects([Result(0)], Input(1)).

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

fn assert_ptb_shape(
    tx: &SdkTransaction,
    expected_sender: &SuiAddress,
    expected_recipient: &SuiAddress,
    expected_gas_objects: &[ObjectReference],
) {
    // Verify the transaction header and gas configuration.
    assert_eq!(tx.sender.to_string(), expected_sender.to_string());
    assert_eq!(tx.gas_payment.objects, expected_gas_objects);
    assert_eq!(
        tx.gas_payment.owner.to_string(),
        expected_sender.to_string()
    );
    assert_eq!(tx.gas_payment.price, GAS_PRICE);
    assert_eq!(tx.gas_payment.budget, GAS_BUDGET);

    match &tx.kind {
        TransactionKind::ProgrammableTransaction(ptb) => {
            // Expect a minimal PTB: 2 pure inputs and 2 commands.
            assert_eq!(ptb.inputs.len(), 2);
            assert_eq!(ptb.commands.len(), 2);

            // Input 0 is the split amount.
            match &ptb.inputs[0] {
                SdkInput::Pure(bytes) => {
                    let amount: u64 = bcs::from_bytes(bytes).unwrap();
                    assert_eq!(amount, TRANSFER_AMOUNT);
                }
                other => panic!("expected pure amount input, got {other:?}"),
            }

            // Input 1 is the transfer recipient.
            match &ptb.inputs[1] {
                SdkInput::Pure(bytes) => {
                    let recipient = bcs::from_bytes::<sui_sdk_types::Address>(bytes).unwrap();
                    assert_eq!(recipient.to_string(), expected_recipient.to_string());
                }
                other => panic!("expected pure recipient input, got {other:?}"),
            }

            // Command 0 splits the gas coin using amount input 0.
            assert!(matches!(
                &ptb.commands[0],
                Command::SplitCoins(split)
                    if matches!(split.coin, Argument::Gas)
                        && split.amounts == vec![Argument::Input(0)]
            ));

            // Command 1 transfers the split result to recipient input 1.
            assert!(matches!(
                &ptb.commands[1],
                Command::TransferObjects(transfer)
                    if (
                        transfer.objects == vec![Argument::Result(0)]
                        || transfer.objects == vec![Argument::NestedResult(0, 0)]
                    ) && transfer.address == Argument::Input(1)
            ));
        }
        other => panic!("expected programmable transaction, got {other:?}"),
    }
}

async fn select_coins_for_payment(
    owner: Address,
    transfer_amount: u64,
    gas_budget: u64,
) -> Result<Vec<ObjectReference>> {
    // Select enough SUI coins to cover both transfer amount and gas budget.
    let client = Client::new(TESTNET_RPC)?;
    let sui_struct_tag = sui_sdk_types::StructTag::sui();
    let coin_type = sui_sdk_types::TypeTag::Struct(Box::new(sui_struct_tag));
    let required_amount = transfer_amount + gas_budget;
    let coins = client
        .select_coins(&owner, &coin_type, required_amount, &[])
        .await?;

    dbg!(coins.len());

    if coins.is_empty() {
        return Err(anyhow::anyhow!(
            "No coins found for address {} covering amount {}",
            owner,
            required_amount
        ));
    }

    coins
        .into_iter()
        .map(|coin| {
            let proto_object: sui_rpc::proto::sui::rpc::v2::Object = coin;
            (&proto_object.object_reference())
                .try_into()
                .map_err(Into::into)
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let alice_addr = sk_to_addr(PRIVATE_KEY_BECH32_ALICE);
    let bob_addr = sk_to_addr(PRIVATE_KEY_BECH32_BOB);
    let alice_public_key = sk_to_pk(PRIVATE_KEY_BECH32_ALICE);

    assert_eq!(alice_addr.to_string(), ADDRESS_ALICE);
    assert_eq!(bob_addr.to_string(), ADDRESS_BOB);

    println!("alice address: {alice_addr}");
    println!("bob address: {bob_addr}");

    let alice_addr_off = Address::from_str(&alice_addr.to_string()).unwrap();
    // Keep the example aligned with SuiTransaction.gas_payment: Vec<Input>.
    let gas_coin_refs =
        select_coins_for_payment(alice_addr_off, TRANSFER_AMOUNT, GAS_BUDGET).await?;
    dbg!(&gas_coin_refs);

    let params = SuiTransactionParameters {
        from: alice_addr.clone(),
        inputs: vec![],
        outputs: vec![Output {
            to: bob_addr.clone(),
            amount: TRANSFER_AMOUNT,
        }],
        // Pass all selected gas objects through the anychain-sui input model.
        gas_payment: gas_coin_refs
            .iter()
            .cloned()
            .map(Input::from_object_ref)
            .collect(),
        gas_price: GAS_PRICE,
        gas_budget: GAS_BUDGET,
        public_key: alice_public_key,
    };

    let mut tx = SuiTransaction::new(&params)?;
    let raw_tx = tx.to_bytes()?;
    let parsed_tx: SdkTransaction = bcs::from_bytes(&raw_tx[3..])?;
    assert_ptb_shape(&parsed_tx, &alice_addr, &bob_addr, &gas_coin_refs);

    // Compute the transaction id for display only.
    let txid = tx.to_transaction_id()?;

    // Sign the transaction ID hash with pure ed25519 algorithm.
    let seed = suiprivkey_to_ed25519(PRIVATE_KEY_BECH32_ALICE);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    use ed25519_dalek::Signer;
    let sig_bytes = signing_key.sign(&txid.0).to_bytes().to_vec();

    let signed = tx.sign(sig_bytes, 0)?;

    let payload = serde_json::from_slice::<Value>(&signed)?;
    let raw_tx_b64 = payload["raw_tx"].as_str().expect("missing raw_tx");
    let sig_b64 = payload["signature"].as_str().expect("missing signature");

    assert_eq!(raw_tx_b64, Base64::encode_string(&raw_tx[3..]));

    let decoded_tx_bytes = Base64::decode_vec(raw_tx_b64)?;
    let decoded_sig_bytes = Base64::decode_vec(sig_b64)?;

    let decoded_tx: SdkTransaction = bcs::from_bytes(&decoded_tx_bytes)?;
    let decoded_signature: UserSignature = bcs::from_bytes(&decoded_sig_bytes)?;

    assert_eq!(decoded_tx, parsed_tx);

    println!("transaction id: {}", txid);
    println!("transaction (base64): {}", raw_tx_b64);
    println!("signature (base64): {}", sig_b64);

    // finally: Submit via RPC
    let mut client = Client::new(TESTNET_RPC)?;
    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(decoded_tx.into())
                .with_signatures(vec![decoded_signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(10),
        )
        .await?
        .into_inner();

    assert!(
        response.transaction().effects().status().success(),
        "transaction execution failed"
    );

    // println!("broadcast result{:?}", response);

    if let Some(tx) = &response.transaction {
        if let Some(digest) = &tx.digest {
            println!("transaction digest: {}", digest);
        }
    }

    Ok(())
}
