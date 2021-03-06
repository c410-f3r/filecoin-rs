# API

Documentation for the rust api.

## key_generate_mnemonic

Generate a 24 english words mnemonic.

```rust
use signer::key_generate_mnemonic;

let mnemonic = key_generate_mnemonic().unwrap();
println!("{}", mnemonic);
```

## key_derive

Derive a child key from a mnemonic following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **mnemonic**: a string containing the words;
* **path**: a BIP44 path;

```rust
use signer::key_derive;
use bip39::{Mnemonic, MnemonicType, Language};

let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
let path = "m/44'/461'/0/0/1";

let extended_key = key_derive(mnemonic.phrase(), path).unwrap();

println!("{:?}", extended_key);
```

## key_derive_from_seed

Derive a child key from a seed following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **seed**: a seed as a hex string;
* **path**: a BIP44 path;

```rust
use signer::key_derive_from_seed;
use bip39::{Mnemonic, MnemonicType, Language, Seed};

let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
let path = "m/44'/461'/0/0/1".to_string();

let mnemonic = Mnemonic::from_phrase(&mnemonic.0, Language::English).unwrap();

let seed = Seed::new(&mnemonic, "");

let extended_key = key_derive_from_seed(seed.as_bytes(), path).unwrap();

println!("{:?}", extended_key);
```

## key_recover

Get extended private key from private key.

Arguments:
* **PrivateKey**: A `PrivateKey`.
* **testnet**: A boolean value that indicate if testnet (`true`) or mainnet (`false`);

```rust
use signer::{key_recover, PrivateKey};

let private_key = PrivateKey::try_from("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a").unwrap();

let extended_key = key_recover(private_key, true).unwrap();

println!("{:?}", extended_key);
```

## transaction_serialize

Serialize a transaction and return a CBOR hexstring.

Arguments :
* **transaction**: a filecoin transaction;

```rust
use signer::transaction_serialize;
use signer::api::UnsignedMessageAPI;

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": "25000",
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI = serde_json::from_str(transaction).unwrap();

let cbor_transaction = transaction_serialize(message_user_api).unwrap();

println!("{:?}", cbor_transaction);
```

## transaction_parse

Parse a CBOR hextring into a filecoin transaction (signed or unsigned).

Arguments:
* **hexstring**: the cbor hexstring to parse;
* **testnet**: boolean value `true` if testnet or `false` for mainnet;

```rust
use signer::{transaction_parse, CborBuffer};
use signer::api::MessageTxAPI;


let cbor_data = CborBuffer(from_hex_string("885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c4430061a80040").unwrap());


let transaction = transaction_parse(&cbor_data, true).unwrap();

match transaction {
        MessageTxAPI::UnsignedMessageAPI(unsigned_tx) => println!("To address in unsigned message : {}", unsigned_tx.to.to_string()),
        MessageTxAPI::SignedMessageAPI(signed_tx) => println!("To address in signed message : {}", signed_tx.message.to.to_string()),
    }
```

## transaction\_sign\_raw

Sign a transaction and return a raw signature (RSV format).

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a private key as hexstring;

```rust
use signer::{transaction_sign_raw, PrivateKey};
use signer::api::UnsignedMessageAPI;

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": "25000",
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI = serde_json::from_str(transaction).unwrap();

let private_key = PrivateKey::try_from("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a").unwrap();

let raw_signature = transaction_sign_raw(&message_user_api, &private_key).unwrap();

println!("{:?}", raw_signature);
```

## transaction_sign

Sign a transaction and return a signed message (message + signature).

```rust
pub struct SignedMessageAPI {
    pub message: UnsignedMessageAPI,
    pub signature: SignatureAPI,
}
```

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a private key as hexstring;

```rust
use signer::{transaction_sign, PrivateKey};
use signer::api::UnsignedMessageAPI;

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": "25000",
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI = serde_json::from_str(transaction).unwrap();

let private_key = PrivateKey::try_from("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a").unwrap();

let raw_signature = transaction_sign(&message_user_api, &private_key).unwrap();

println!("{:?}", raw_signature);
```

## verify_signature

Verify a signature. Return a boolean.

Arguments :
* **signature**: RSV format signature;
* **CBOR transaction**: the CBOR transaction;

```rust
use signer::{transaction_sign_raw, verify_signature};

let cbor_data = CborBuffer(from_hex_string("885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c4430061a80040").unwrap());

let private_key = PrivateKey::try_from("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a".to_string()).unwrap();

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": "25000",
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI =
    serde_json::from_str(transaction).unwrap();

let mut signature = transaction_sign_raw(&message_user_api, &private_key).unwrap();

let result = verify_signature(&signature, &cbor_data).unwrap()

println!("{}", result);
```
