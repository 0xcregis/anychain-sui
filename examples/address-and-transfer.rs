use anyhow::Result;
// use base64ct::{Base64, Encoding};
use bech32::{Bech32, Hrp};
use ed25519_dalek::SigningKey;
use sui_crypto::{ed25519::Ed25519PrivateKey, SuiSigner};
use sui_rpc::{
    client::Client,
    field::{FieldMask, FieldMaskUtil},
    proto::sui::rpc::v2::ExecuteTransactionRequest,
};
use sui_sdk_types::{Address, Ed25519PublicKey};
use sui_sdk_types::{
    Argument, Command, GasPayment, Input, ObjectReference, ProgrammableTransaction, SplitCoins,
    Transaction, TransactionExpiration, TransactionKind, TransferObjects, UserSignature,
};
const SEED_ALICE: [u8; 32] = [1u8; 32];
const SEED_BOB: [u8; 32] = [2u8; 32];

const ADDRESS_ALICE: &str = "0x29dfbf688abce7ab43bb8e70cae158ae961196e721440f515482f8ba1684390f";
const ADDRESS_BOB: &str = "0x7799ea80594c35644321148485238c7a7a1c6549809e1795e6747c6d4da2504c";

const PRIVATE_KEY_BECH32_ALICE: &str =
    "suiprivkey1qqqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszasa5uj";
const PRIVATE_KEY_BECH32_BOB: &str =
    "suiprivkey1qqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyucanpq";

const PUBLIC_KEY_ALICE: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
const PUBLIC_KEY_BOB: &str = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";

const TESTNET_RPC: &str = "https://fullnode.testnet.sui.io:443";
const MIST_PER_SUI: u64 = 1_000_000_000;

const SUI_PRIVKEY_HRP: &str = "suiprivkey";

fn hrp() -> Hrp {
    // "suiprivkey" is a valid Bech32 HRP (lowercase ASCII, length 10).
    Hrp::parse(SUI_PRIVKEY_HRP).expect("`suiprivkey` is a valid Bech32 HRP")
}

fn ed25519_to_suiprivkey(key: &[u8]) -> String {
    let mut payload = Vec::with_capacity(1 + key.len());
    payload.push(0x00);
    payload.extend_from_slice(key);

    bech32::encode::<Bech32>(hrp(), &payload).unwrap()
}

fn generate_ed25519_accounts() -> Result<(Ed25519PrivateKey, Address, Address)> {
    let private_key_alice: Ed25519PrivateKey = Ed25519PrivateKey::new(SEED_ALICE);
    let signing_key_alice: SigningKey = ed25519_dalek::SigningKey::from_bytes(&SEED_ALICE);
    let private_key_bech32_alice = ed25519_to_suiprivkey(signing_key_alice.as_bytes().as_slice());

    let private_key_bob: Ed25519PrivateKey = Ed25519PrivateKey::new(SEED_BOB);
    let signing_key_bob: SigningKey = ed25519_dalek::SigningKey::from_bytes(&SEED_BOB);
    let private_key_bech32_bob = ed25519_to_suiprivkey(signing_key_bob.as_bytes().as_slice());

    let public_key_alice: Ed25519PublicKey = private_key_alice.public_key();
    let public_key_bob: Ed25519PublicKey = private_key_bob.public_key();

    let addr_alice: Address = public_key_alice.derive_address();
    let addr_bob: Address = public_key_bob.derive_address();

    assert_eq!(PRIVATE_KEY_BECH32_ALICE, private_key_bech32_alice);
    assert_eq!(PRIVATE_KEY_BECH32_BOB, private_key_bech32_bob);

    assert_eq!(ADDRESS_ALICE, addr_alice.to_string());
    assert_eq!(ADDRESS_BOB, addr_bob.to_string());

    assert_eq!(PUBLIC_KEY_ALICE, public_key_alice.to_string());
    assert_eq!(PUBLIC_KEY_BOB, public_key_bob.to_string());

    println!("alice private bech32 key: {:?}", private_key_bech32_alice);
    println!("alice public key: {}", public_key_alice);
    println!("alice address: {addr_alice}");

    println!("bob private bech32 key: {:?}", private_key_bech32_bob);
    println!("bob public key: {}", public_key_bob);
    println!("bob address: {addr_bob}");

    Ok((private_key_alice, addr_alice, addr_bob))
}

async fn select_first_coin(owner: Address) -> Result<ObjectReference> {
    let client = Client::new(TESTNET_RPC)?;
    let sui_struct_tag = sui_sdk_types::StructTag::sui();
    let coin_type = sui_sdk_types::TypeTag::Struct(Box::new(sui_struct_tag));
    let amount: u64 = MIST_PER_SUI / 1000;
    let coins = client.select_coins(&owner, &coin_type, amount, &[]).await?;

    dbg!(coins.len());

    let first_coin = coins
        .first()
        .ok_or_else(|| anyhow::anyhow!("No coins found for address {}", owner))?;
    let proto_object: sui_rpc::proto::sui::rpc::v2::Object = first_coin.clone();
    let object_ref: sui_sdk_types::ObjectReference =
        (&proto_object.object_reference()).try_into()?;
    Ok(object_ref)
}

async fn transfer_sui_native(
    alice: &Ed25519PrivateKey,
    alice_addr: Address,
    bob_addr: Address,
) -> Result<()> {
    // 1. Get a SUI coin owned by Alice to use as gas
    let gas_coin_ref = select_first_coin(alice_addr).await?;
    dbg!(&gas_coin_ref);

    let mut client = Client::new(TESTNET_RPC)?;
    let amount: u64 = MIST_PER_SUI / 1000;
    let reference_gas_price = 1000;
    // let reference_gas_price = client.get_reference_gas_price().await?;

    // 2. Build the programmable transaction:
    //    - Split 1 SUI from the gas coin
    //    - Transfer the new coin to Bob
    let tx = Transaction {
        sender: alice_addr,
        kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            inputs: vec![
                Input::Pure(bcs::to_bytes(&amount)?),
                Input::Pure(bcs::to_bytes(&bob_addr)?),
            ],
            commands: vec![
                Command::SplitCoins(SplitCoins {
                    coin: Argument::Gas,
                    amounts: vec![Argument::Input(0)],
                }),
                Command::TransferObjects(TransferObjects {
                    objects: vec![Argument::Result(0)],
                    address: Argument::Input(1),
                }),
            ],
        }),
        gas_payment: GasPayment {
            objects: vec![gas_coin_ref],
            owner: alice_addr,
            price: reference_gas_price,
            budget: 3_000_000,
        },
        expiration: TransactionExpiration::None,
    };

    // 3. Sign the transaction
    let signature: UserSignature = alice.sign_transaction(&tx)?;

    // 4. Serialize and encode
    // let tx_b64 = Base64::encode_string(&bcs::to_bytes(&tx)?);
    // let sig_b64 = Base64::encode_string(&bcs::to_bytes(&signature)?);
    // println!("transaction (base64): {tx_b64}");
    // println!("signature (base64): {sig_b64}");

    // 5. Submit via RPC
    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(tx.into())
                .with_signatures(vec![signature.into()])
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

#[tokio::main]
async fn main() -> Result<()> {
    let (alice, alice_addr, bob_addr) = generate_ed25519_accounts()?;

    transfer_sui_native(&alice, alice_addr, bob_addr).await?;

    Ok(())
}
