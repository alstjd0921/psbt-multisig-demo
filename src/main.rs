use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2, OP_PUSHNUM_3};
use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, PrivateKey, PublicKey};

fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    // example private keys
    let secret_keys = [
        PrivateKey::from_slice(&[0x01; 32], Network::Regtest).expect(""),
        PrivateKey::from_slice(&[0x02; 32], Network::Regtest).expect(""),
        PrivateKey::from_slice(&[0x03; 32], Network::Regtest).expect(""),
    ];

    let mut pub_keys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|sk| PublicKey::from_private_key(&secp, sk))
        .collect();
    pub_keys.sort(); // must sort

    let redeem_script = Builder::new()
        .push_opcode(OP_PUSHNUM_2) // m
        .push_key(&pub_keys[0])
        .push_key(&pub_keys[1])
        .push_key(&pub_keys[2])
        .push_opcode(OP_PUSHNUM_3) // n
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();

    let sender = Address::p2wsh(redeem_script.as_script(), Network::Regtest); // address encoding

    println!("{:#?}", redeem_script);
    println!("{sender}");

    Ok(())
}
