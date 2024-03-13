use crate::{PREV_RAW_TX, RECEIVE_ADDRESS};
use hex_lit::hex;
use miniscript::bitcoin::{
    absolute, consensus, transaction, Address, Amount, Network, OutPoint, Psbt, Script, Sequence,
    Transaction, TxIn, TxOut,
};
use miniscript::psbt::PsbtExt;
use miniscript::{DefiniteDescriptorKey, Descriptor};
use std::str::FromStr;

pub fn create_psbt(
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

fn get_vout(tx: &Transaction, spk: &Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == &txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("cannot find utxo")
}
