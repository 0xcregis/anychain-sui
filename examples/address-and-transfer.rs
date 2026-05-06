use anyhow::Result;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::{Address, Ed25519PublicKey, StructTag};
// use base64ct::{Base64, Encoding};
// use serde_json::json;
// use sui_transaction_builder::TransactionBuilder;

const SEED_ALICE: [u8; 32] = [1u8; 32];
const SEED_BOB: [u8; 32] = [2u8; 32];

const ADDRESS_ALICE: &str = "0x29dfbf688abce7ab43bb8e70cae158ae961196e721440f515482f8ba1684390f";
const ADDRESS_BOB: &str = "0x7799ea80594c35644321148485238c7a7a1c6549809e1795e6747c6d4da2504c";

const PUBLIC_KEY_ALICE: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
const PUBLIC_KEY_BOB: &str = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";

fn generate_ed25519_accounts() -> Result<(Ed25519PrivateKey, Address, Address)> {
    let private_key_alice: Ed25519PrivateKey = Ed25519PrivateKey::new(SEED_ALICE);
    let private_key_bob: Ed25519PrivateKey = Ed25519PrivateKey::new(SEED_BOB);

    let public_key_alice: Ed25519PublicKey = private_key_alice.public_key();
    let public_key_bob: Ed25519PublicKey = private_key_bob.public_key();

    let addr_alice: Address = public_key_alice.derive_address();
    let addr_bob: Address = public_key_bob.derive_address();

    assert_eq!(ADDRESS_ALICE, addr_alice.to_string());
    assert_eq!(ADDRESS_BOB, addr_bob.to_string());

    assert_eq!(PUBLIC_KEY_ALICE, public_key_alice.to_string());
    assert_eq!(PUBLIC_KEY_BOB, public_key_bob.to_string());

    println!("alice public key: {}", public_key_alice);
    println!("alice address        : {addr_alice}");

    println!("bob public key: {}", public_key_bob);
    println!("bo address        : {addr_bob}");

    Ok((private_key_alice, addr_alice, addr_bob))
}

// async fn transfer_sui_native(
//     alice: &Ed25519PrivateKey,
//     alice_addr: Address,
//     bob_addr: Address,
// ) -> Result<()> {
//     let mut tx = TransactionBuilder::new();
//     tx.set_sender(alice_addr);
//
//     let coin = tx.coin(StructTag::sui(), MIST_PER_SUI);
//     let recipient = tx.pure(&bob_addr);
//     tx.transfer_objects(vec![coin], recipient);
//     tx.set_gas_budget(50_000_000);
//
//     let mut client = sui_rpc::Client::new(TESTNET_RPC.to_string()).await?;
//     let transaction = tx.build(&mut client).await?;
//
//     let signature = alice.sign_transaction(&transaction)?;
//
//     let tx_b64 = Base64::encode_string(&bcs::to_bytes(&transaction)?);
//     let sig_b64 = Base64::encode_string(&bcs::to_bytes(&signature)?);
//
//     let payload = json!({
//         "jsonrpc": "2.0",
//         "id": 1,
//         "method": "sui_executeTransactionBlock",
//         "params": [
//             tx_b64,
//             [sig_b64],
//             {
//                 "showEffects": true,
//                 "showBalanceChanges": true,
//                 "showObjectChanges": true
//             },
//             "WaitForLocalExecution"
//         ]
//     });
//
//     let resp: serde_json::Value = reqwest::Client::new()
//         .post(TESTNET_RPC)
//         .json(&payload)
//         .send()
//         .await?
//         .json()
//         .await?;
//
//     if let Some(err) = resp.get("error") {
//         return Err(anyhow!("broadcast failed: {err:#}"));
//     }
//
//     println!("broadcast result:\n{resp:#}");
//     Ok(())
// }

#[tokio::main]
async fn main() -> Result<()> {
    let (alice, alice_addr, bob_addr) = generate_ed25519_accounts()?;

    // transfer_sui_native(&alice, alice_addr, bob_addr).await?;

    Ok(())
}
