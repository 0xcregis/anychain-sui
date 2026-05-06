use anyhow::{anyhow, Result};
use base64ct::{Base64, Encoding};
// use serde_json::json;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::{Address, StructTag};
// use sui_transaction_builder::TransactionBuilder;

fn generate_ed25519_accounts() -> Result<(Ed25519PrivateKey, Address, Address)> {
    todo!()

    // let alice_seed = [1u8; 32];
    // let bob_seed = [2u8; 32];
    //
    // let alice = Ed25519PrivateKey::from_bytes(&alice_seed)?;
    // let bob = Ed25519PrivateKey::from_bytes(&bob_seed)?;

    // TODO: find the right private key bytes and address

    // let alice_pk = alice.public_key();
    // let bob_pk = bob.public_key();
    //
    // let alice_addr = Address::from(&alice_pk);
    // let bob_addr = Address::from(&bob_pk);
    //
    // println!("alice public key hex : {}", hex::encode(alice_pk.inner()));
    // println!("alice address        : {alice_addr}");
    //
    // println!("bob public key hex   : {}", hex::encode(bob_pk.inner()));
    // println!("bob address          : {bob_addr}");
    //
    // Ok((alice, alice_addr, bob_addr))
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
