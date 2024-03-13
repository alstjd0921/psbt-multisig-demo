use miniscript::bitcoin::key::Secp256k1;
use miniscript::bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2, OP_PUSHNUM_3};
use miniscript::bitcoin::script::Builder;
use miniscript::bitcoin::secp256k1::All;
use miniscript::bitcoin::{Address, Network, PrivateKey, PublicKey};
use miniscript::{DefiniteDescriptorKey, Descriptor};
use std::collections::BTreeMap;
use std::str::FromStr;

pub fn create_2of3_p2wsh_example(
    secp: &Secp256k1<All>,
) -> anyhow::Result<(
    Address,
    BTreeMap<PublicKey, PrivateKey>,
    Descriptor<DefiniteDescriptorKey>,
)> {
    // example private keys
    let secret_keys = [
        PrivateKey::from_slice(&[0x01; 32], Network::Regtest).expect(""),
        PrivateKey::from_slice(&[0x02; 32], Network::Regtest).expect(""),
        PrivateKey::from_slice(&[0x03; 32], Network::Regtest).expect(""),
    ];

    let mut pub_keys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|sk| PublicKey::from_private_key(secp, sk))
        .collect();

    let mut signers = BTreeMap::new();
    for (i, sk) in secret_keys.into_iter().enumerate() {
        signers.insert(pub_keys[i], sk);
    }

    pub_keys.sort(); // must sort

    let redeem_script = Builder::new()
        .push_opcode(OP_PUSHNUM_2) // m
        .push_key(&pub_keys[0])
        .push_key(&pub_keys[1])
        .push_key(&pub_keys[2])
        .push_opcode(OP_PUSHNUM_3) // n
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();
    println!("redeem script: {:#?}", redeem_script);
    println!("redeem script (hex): {}", redeem_script.to_hex_string());

    let sender = Address::p2wsh(redeem_script.as_script(), Network::Regtest); // address encoding
    println!("Address: {:?}", sender);

    let _d = Descriptor::new_wsh_sortedmulti(2, pub_keys.clone())?.to_string();
    let descriptor = Descriptor::from_str(&_d)?;
    descriptor.sanity_check()?;

    Ok((sender, signers, descriptor))
}
