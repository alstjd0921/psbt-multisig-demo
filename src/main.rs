mod p2wsh_generation_example;
mod psbt_generation_example;

use crate::p2wsh_generation_example::create_2of3_p2wsh_example;
use miniscript::bitcoin::{consensus, secp256k1::Secp256k1};
use miniscript::psbt::PsbtExt;
use std::collections::BTreeMap;

pub const PREV_RAW_TX: &str = "02000000000102a02b8bdce9f23e2e7d3f111b50ad3334b5a53efc28f5924aa1d1e28d94cf14730000000000fdffffff867aad64aa72fbc1418c408f6b8ce92555d1beb59d87d4760d0a6e0dd863fb2f0000000000fdffffff0200f2052a01000000220020a3379884c9919e8ae37a568e76b4af9d72b0928bf52f5ea8e5f53032691d17bee016a804000000002251201670c00d2006f10166d98f57244ec8a4d09f87b1ad48926a3dc7fe46920bd1dc02473044022072afd5f378f71c042893fe66c542e4ee3d2363e8a6bb217815e3573afe34cea60220353ff9aa48368da42aed23fb5bfd7c5cbca71ef201c08e6275522f1a3f1f02d80121025569ef2c661ffb9a3ca1b86604c2dc6aacf39d4c55bfdd55e029cfb9556ebd7f02473044022006cb61493553dd2cecadc7e119c3ac3cf979d3489a23c89922c4ccc5c18b722502203d03ce4e07283a6ccbf3ae99a331aeddf6882a4d3bc952f70e234e692df504570121025569ef2c661ffb9a3ca1b86604c2dc6aacf39d4c55bfdd55e029cfb9556ebd7fd7040000";

pub const RECEIVE_ADDRESS: &str = "bcrt1qurj4xpaw95jlr28lqhankfdqce7tatgkeqrk9q";

fn main() -> anyhow::Result<()> {
    let secp = Secp256k1::new();

    let (sender, signers, descriptor) = create_2of3_p2wsh_example(&secp)?;

    let (signers1, signers2, signers3) = {
        let pks: Vec<_> = signers.keys().collect();

        let signers1 = BTreeMap::from([(pks[0].clone(), signers.get(pks[0]).unwrap().clone())]);
        let signers2 = BTreeMap::from([(pks[1].clone(), signers.get(pks[1]).unwrap().clone())]);
        let signers3 = BTreeMap::from([(pks[2].clone(), signers.get(pks[2]).unwrap().clone())]);

        (signers1, signers2, signers3)
    };

    let mut psbt = psbt_generation_example::create_psbt(&sender, descriptor.clone())?;

    let mut psbt1 = psbt.clone();
    psbt1.sign(&signers1, &secp).unwrap();
    let mut psbt2 = psbt.clone();
    psbt2.sign(&signers2, &secp).unwrap();
    let mut psbt3 = psbt.clone();
    psbt3.sign(&signers3, &secp).unwrap();

    psbt.combine(psbt1)?;
    psbt.combine(psbt2)?;
    // psbt.combine(psbt3)?;
    psbt.finalize_mut(&secp).expect("cannot finalize");
    let tx = psbt.extract_tx_unchecked_fee_rate();
    println!("{}", consensus::encode::serialize_hex(&tx));

    Ok(())
}
