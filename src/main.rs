use hex_lit::hex;
use miniscript::bitcoin::{
    absolute, consensus,
    opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2, OP_PUSHNUM_3},
    script::Builder,
    secp256k1::Secp256k1,
    transaction, Address, Amount, Network, OutPoint, PrivateKey, Psbt, PublicKey, Script, Sequence,
    Transaction, TxIn, TxOut,
};
use miniscript::psbt::PsbtExt;
use miniscript::{DefiniteDescriptorKey, Descriptor};
use std::collections::BTreeMap;
use std::str::FromStr;

const PREV_RAW_TX: &str = "02000000000102a02b8bdce9f23e2e7d3f111b50ad3334b5a53efc28f5924aa1d1e28d94cf14730000000000fdffffff867aad64aa72fbc1418c408f6b8ce92555d1beb59d87d4760d0a6e0dd863fb2f0000000000fdffffff0200f2052a01000000220020a3379884c9919e8ae37a568e76b4af9d72b0928bf52f5ea8e5f53032691d17bee016a804000000002251201670c00d2006f10166d98f57244ec8a4d09f87b1ad48926a3dc7fe46920bd1dc02473044022072afd5f378f71c042893fe66c542e4ee3d2363e8a6bb217815e3573afe34cea60220353ff9aa48368da42aed23fb5bfd7c5cbca71ef201c08e6275522f1a3f1f02d80121025569ef2c661ffb9a3ca1b86604c2dc6aacf39d4c55bfdd55e029cfb9556ebd7f02473044022006cb61493553dd2cecadc7e119c3ac3cf979d3489a23c89922c4ccc5c18b722502203d03ce4e07283a6ccbf3ae99a331aeddf6882a4d3bc952f70e234e692df504570121025569ef2c661ffb9a3ca1b86604c2dc6aacf39d4c55bfdd55e029cfb9556ebd7fd7040000";

const RECEIVE_ADDRESS: &str = "bcrt1qurj4xpaw95jlr28lqhankfdqce7tatgkeqrk9q";

fn get_vout(tx: &Transaction, spk: &Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == &txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("cannot find utxo")
}

fn create_psbt(
    sender: &Address,
    descriptor: Descriptor<DefiniteDescriptorKey>,
) -> anyhow::Result<Psbt> {
    let prev_tx = consensus::deserialize::<Transaction>(&hex!(PREV_RAW_TX))?;
    let (outpoint, witness_utxo) = get_vout(&prev_tx, &sender.script_pubkey());

    let mut txin = TxIn::default();
    txin.previous_output = outpoint;
    txin.sequence = Sequence::MAX;

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![txin],
        output: vec![TxOut {
            value: Amount::from_int_btc(45),
            script_pubkey: Address::from_str(RECEIVE_ADDRESS)?
                .require_network(Network::Regtest)?
                .script_pubkey(),
        }],
    };

    let mut psbt = Psbt::from_unsigned_tx(tx)?;

    psbt.inputs[0].witness_utxo = Some(witness_utxo);
    psbt.update_input_with_descriptor(0, &descriptor)?;

    Ok(psbt)
}

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

    let mut psbt = create_psbt(&sender, descriptor.clone())?;

    let secp = Secp256k1::new();
    let _a = psbt.sign(&signers, &secp).unwrap();

    let secp = Secp256k1::new();
    psbt.finalize_mut(&secp).expect("cannot finalize");

    let tx = psbt.extract_tx_unchecked_fee_rate();
    println!("{}", consensus::encode::serialize_hex(&tx));

    Ok(())
}
