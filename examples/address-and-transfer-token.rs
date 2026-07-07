use anyhow::Result;
use base64ct::{Base64, Encoding};
use bech32::{Bech32, Hrp};
use ed25519_dalek::SigningKey;
use std::str::FromStr;
use sui_crypto::{ed25519::Ed25519PrivateKey, SuiSigner};
use sui_rpc::{
    client::Client,
    field::{FieldMask, FieldMaskUtil},
    proto::sui::rpc::v2::ExecuteTransactionRequest,
};
use sui_sdk_types::{Address, Ed25519PublicKey};
use sui_sdk_types::{
    Argument, Command, Digest, GasPayment, Input, ObjectReference, ProgrammableTransaction,
    SplitCoins, StructTag, Transaction, TransactionExpiration, TransactionKind, TransferObjects,
    TypeTag, UserSignature,
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

// TODO: replace with Testnet USDC Package
const USDC_PACKAGE_ID_TESTNET: &str =
    "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC";
// 1 USDC = 1_000_000

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
        StructTag::from_str(&USDC_PACKAGE_ID_TESTNET).unwrap(),
    ))
}

fn sui_coin_type() -> TypeTag {
    TypeTag::Struct(Box::new(StructTag::sui()))
}

fn coin_struct_tag(coin_type: &TypeTag) -> Result<StructTag> {
    match coin_type {
        TypeTag::Struct(tag) => Ok(tag.as_ref().clone()),
        _ => Err(anyhow::anyhow!(
            "coin type must be a struct tag: {coin_type}"
        )),
    }
}

fn object_ref_from_rpc(coin: sui_rpc::proto::sui::rpc::v2::Object) -> Result<ObjectReference> {
    let object_ref = (&coin.object_reference()).try_into()?;

    Ok(object_ref)
}

fn first_object(objects: Vec<ObjectReference>) -> Result<ObjectReference> {
    objects
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty object list"))
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

async fn select_coin_objects(
    owner: Address,
    coin_type: TypeTag,
    amount: u64,
) -> Result<Vec<ObjectReference>> {
    let client = Client::new(TESTNET_RPC)?;

    let coins = client.select_coins(&owner, &coin_type, amount, &[]).await?;

    if coins.is_empty() {
        return Err(anyhow::anyhow!("coin not found"));
    }

    let mut result = Vec::new();

    for coin in coins {
        let proto_object: sui_rpc::proto::sui::rpc::v2::Object = coin;

        result.push(object_ref_from_rpc(proto_object)?);
    }

    Ok(result)
}

async fn select_gas_coins(owner: Address, gas_budget: u64) -> Result<Vec<ObjectReference>> {
    select_coin_objects(owner, sui_coin_type(), gas_budget).await
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

/// Builds the programmable-transaction input used as the transferable coin source.
///
/// Sui can store fungible balances in two forms for an address:
/// 1. as owned `Coin<T>` objects (`coin_balance`)
/// 2. as aggregated address balance (`address_balance`)
///
/// When the requested amount is already available in `address_balance`, this
/// function creates a synthetic reservation object via `coin_reservation` so
/// the transfer can spend that balance even if no concrete `Coin<T>` object is
/// present on-chain for the owner. Otherwise it falls back to selecting a real
/// owned coin object and uses that object as the input.
async fn coin_input_for_transfer(
    owner: Address,
    coin_type: &TypeTag,
    amount: u64,
) -> Result<Input> {
    let balance = get_coin_balance(owner, coin_type).await?;
    let address_balance = balance.address_balance.unwrap_or_default();

    if address_balance >= amount {
        let mut client = Client::new(TESTNET_RPC)?;
        let service_info = client
            .ledger_client()
            .get_service_info(sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest::default())
            .await?
            .into_inner();

        let epoch = service_info
            .epoch
            .ok_or_else(|| anyhow::anyhow!("missing epoch in service info"))?;
        let chain_id = service_info
            .chain_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing chain id in service info"))?;
        let chain_id = Digest::from_str(chain_id)?;
        let coin_struct = coin_struct_tag(coin_type)?;

        println!("using address balance reservation for {owner} ({coin_type}), amount={amount}");

        return Ok(Input::ImmutableOrOwned(ObjectReference::coin_reservation(
            &coin_struct,
            amount,
            epoch,
            chain_id,
            owner,
        )));
    }

    let coin_ref = first_object(select_coin_objects(owner, coin_type.clone(), amount).await?)?;
    Ok(Input::ImmutableOrOwned(coin_ref))
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
    let coin_input = coin_input_for_transfer(sender, &coin_type, amount).await?;
    dbg!(&coin_input);

    let gas_budget = 3_000_000;

    let gas_objects = select_gas_coins(sender, gas_budget).await?;
    dbg!(&gas_objects);

    let gas_price = client.get_reference_gas_price().await?;

    let tx = Transaction {
        sender,

        kind: TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            inputs: vec![
                coin_input,
                Input::Pure(bcs::to_bytes(&amount)?),
                Input::Pure(bcs::to_bytes(&recipient)?),
            ],

            commands: vec![
                Command::SplitCoins(SplitCoins {
                    coin: Argument::Input(0),

                    amounts: vec![Argument::Input(1)],
                }),
                Command::TransferObjects(TransferObjects {
                    objects: vec![Argument::Result(0)],

                    address: Argument::Input(2),
                }),
            ],
        }),

        gas_payment: GasPayment {
            objects: gas_objects,
            owner: sender,
            price: gas_price,
            budget: gas_budget,
        },

        expiration: TransactionExpiration::None,
    };

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
            println!("digest={}", digest);
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
    let total = balance.balance.unwrap_or_default();
    let address_balance = balance.address_balance.unwrap_or_default();
    let coin_balance = balance.coin_balance.unwrap_or_default();

    println!(
        "balance for {owner} ({coin_type}): total={total}, address_balance={address_balance}, coin_balance={coin_balance}"
    );

    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let (alice, alice_addr, bob_addr) = generate_ed25519_accounts()?;

    println!("--- balances before transfer ---");
    query_coin_balance(alice_addr, usdc_type_tag()).await?;
    query_coin_balance(bob_addr, usdc_type_tag()).await?;

    let usdc_transfer_amount: u64 = 100_000; // 0.1 USDC
    transfer_usdc(&alice, alice_addr, bob_addr, usdc_transfer_amount).await?;

    println!("--- balances after transfer ---");
    query_coin_balance(alice_addr, usdc_type_tag()).await?;
    query_coin_balance(bob_addr, usdc_type_tag()).await?;

    Ok(())
}
