use anyhow::Result;
use base64ct::{Base64, Encoding};
use bech32::{Bech32, Hrp};
use ed25519_dalek::SigningKey;
use std::str::FromStr;
use sui_crypto::{ed25519::Ed25519PrivateKey, SuiSigner};
use sui_rpc::{
    client::Client,
    field::{FieldMask, FieldMaskUtil},
    proto::sui::rpc::v2::{CoinMetadata, ExecuteTransactionRequest, GetCoinInfoRequest},
};
use sui_sdk_types::{Address, Ed25519PublicKey, StructTag, Transaction, TypeTag, UserSignature};
use sui_transaction_builder::TransactionBuilder;

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
const SUI_PRIVKEY_HRP: &str = "suiprivkey";

// TODO: replace with Testnet USDC Package
const USDC_PACKAGE_ID_TESTNET: &str =
    "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC";

fn hrp() -> Hrp {
    Hrp::parse(SUI_PRIVKEY_HRP).unwrap()
}

fn ed25519_to_suiprivkey(key: &[u8]) -> String {
    let mut payload = Vec::with_capacity(33);

    payload.push(0x00);
    payload.extend_from_slice(key);

    bech32::encode::<Bech32>(hrp(), &payload).unwrap()
}

fn usdc_type_tag() -> TypeTag {
    TypeTag::Struct(Box::new(
        StructTag::from_str(USDC_PACKAGE_ID_TESTNET).unwrap(),
    ))
}

fn coin_struct_tag(coin_type: &TypeTag) -> Result<StructTag> {
    match coin_type {
        TypeTag::Struct(tag) => Ok(tag.as_ref().clone()),
        _ => Err(anyhow::anyhow!(
            "coin type must be a struct tag: {coin_type}"
        )),
    }
}

fn print_tx(tx: &Transaction, sig: &UserSignature) -> Result<()> {
    let tx_bytes = bcs::to_bytes(tx)?;

    println!("transaction(base64): {}", Base64::encode_string(&tx_bytes));

    println!(
        "signature(base64): {}",
        Base64::encode_string(&bcs::to_bytes(sig)?)
    );

    Ok(())
}

fn generate_ed25519_accounts() -> Result<(Ed25519PrivateKey, Address, Ed25519PrivateKey, Address)> {
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

    Ok((private_key_alice, addr_alice, private_key_bob, addr_bob))
}

async fn get_coin_balance(
    owner: Address,
    coin_type: &TypeTag,
) -> Result<sui_rpc::proto::sui::rpc::v2::Balance> {
    let mut client = Client::new(TESTNET_RPC)?;

    let mut request = sui_rpc::proto::sui::rpc::v2::GetBalanceRequest::default();
    request.owner = Some(owner.to_string());
    request.coin_type = Some(coin_type.to_string());

    let response = client
        .state_client()
        .get_balance(request)
        .await?
        .into_inner();

    response
        .balance
        .ok_or_else(|| anyhow::anyhow!("missing balance for {owner} ({coin_type})"))
}

async fn transfer_coin_partial(
    signer: &Ed25519PrivateKey,
    sender: Address,
    recipient: Address,
    coin_type: TypeTag,
    amount: u64,
) -> Result<()> {
    let mut client = Client::new(TESTNET_RPC)?;

    println!(
        "transfer({}, {}, {}, {})",
        sender, recipient, coin_type, amount
    );

    // Describe the transfer at a high level and let the builder resolve
    // the concrete coin objects, merge/split steps, and gas payment.
    let mut builder = TransactionBuilder::new();
    builder.set_sender(sender);

    // Request a Coin<T> of the target amount, then encode the recipient
    // address as a pure input for the transfer command.
    let coin = builder.coin(coin_struct_tag(&coin_type)?, amount);
    let recipient = builder.pure(&recipient);
    builder.transfer_objects(vec![coin], recipient);

    // Resolve the declared intent through RPC and materialize the final PTB.
    let tx = builder.build(&mut client).await?;
    let signature = signer.sign_transaction(&tx)?;

    print_tx(&tx, &signature)?;

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
        "transaction failed"
    );

    if let Some(tx) = &response.transaction {
        if let Some(digest) = &tx.digest {
            println!("digest={digest}");
        }
    }

    Ok(())
}

async fn transfer_usdc(
    signer: &Ed25519PrivateKey,
    sender: Address,
    recipient: Address,
    amount: u64,
) -> Result<()> {
    transfer_coin_partial(signer, sender, recipient, usdc_type_tag(), amount).await
}

async fn query_coin_balance(owner: Address, coin_type: TypeTag) -> Result<()> {
    let balance = get_coin_balance(owner, &coin_type).await?;
    let total_balance = balance.balance.unwrap_or_default();
    let address_balance = balance.address_balance.unwrap_or_default();
    let coin_balance = balance.coin_balance.unwrap_or_default();

    println!(
        "balance for {owner} ({coin_type}): total_balance={total_balance}, address_balance={address_balance}, coin_balance={coin_balance}"
    );

    Ok(())
}

async fn get_coin_metadata(client: &mut Client, coin_type: TypeTag) -> Result<CoinMetadata> {
    let response = client
        .state_client()
        .get_coin_info(GetCoinInfoRequest::default().with_coin_type(coin_type.to_string()))
        .await?
        .into_inner();
    let metadata = response
        .metadata
        .ok_or_else(|| anyhow::anyhow!("missing coin metadata for {coin_type}"))?;

    println!(
        "coin metadata for {coin_type}: decimals={}, symbol={}, name={}",
        metadata.decimals.unwrap_or_default(),
        metadata.symbol.as_deref().unwrap_or(""),
        metadata.name.as_deref().unwrap_or(""),
    );

    Ok(metadata)
}

fn display_amount_to_base_units(metadata: &CoinMetadata, amount: f64) -> Result<u64> {
    let decimals = metadata
        .decimals
        .ok_or_else(|| anyhow::anyhow!("coin metadata is missing decimals"))?;
    let scale = 10u64
        .checked_pow(decimals)
        .ok_or_else(|| anyhow::anyhow!("decimals too large for u64 amount: {decimals}"))?;

    let base_units = (amount * scale as f64) as u64;

    Ok(base_units)
}

#[tokio::main]
async fn main() -> Result<()> {
    let (alice, alice_addr, _bob, bob_addr) = generate_ed25519_accounts()?;

    let metadata = get_coin_metadata(&mut Client::new(TESTNET_RPC)?, usdc_type_tag()).await?;

    println!("--- balances before transfer ---");
    query_coin_balance(alice_addr, usdc_type_tag()).await?;
    query_coin_balance(bob_addr, usdc_type_tag()).await?;

    let display_amount = 0.15;
    let usdc_transfer_amount = display_amount_to_base_units(&metadata, display_amount)?;
    println!(
        "{} in base units = {}",
        display_amount, usdc_transfer_amount
    );

    println!("--- balances before transfer ---");
    query_coin_balance(alice_addr, usdc_type_tag()).await?;
    query_coin_balance(bob_addr, usdc_type_tag()).await?;

    transfer_usdc(&alice, alice_addr, bob_addr, usdc_transfer_amount).await?;
    // transfer_usdc(&bob, bob_addr, alice_addr, usdc_transfer_amount).await?;

    println!("--- balances after transfer ---");
    query_coin_balance(alice_addr, usdc_type_tag()).await?;
    query_coin_balance(bob_addr, usdc_type_tag()).await?;

    Ok(())
}
