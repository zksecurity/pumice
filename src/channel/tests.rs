use super::fs_prover_channel::FSProverChannel;
use super::fs_verifier_channel::FSVerifierChannel;
use super::{Channel, FSChannel, ProverChannel, VerifierChannel};
use crate::{
    randomness::prng::{Prng, PrngKeccak256, PrngOnlyForTest},
    Felt252,
};
use ark_ff::{BigInteger, PrimeField, Zero};
use sha3::Sha3_256;

type MyFSVerifierChannel = FSVerifierChannel<Felt252, Sha3_256, PrngKeccak256>;
type MyFSProverChannel = FSProverChannel<Felt252, Sha3_256, PrngKeccak256>;
type BigIntFelt252 = <Felt252 as PrimeField>::BigInt;

// fn hex_str_to_bigint_with_suffix(hex: &str) -> Felt252 {
//     assert!(
//         hex.starts_with("0x") && hex.ends_with("_Z"),
//         "Only hex input with '_Z' suffix is currently supported"
//     );

//     let hex = &hex[2..hex.len() - 2]; // Remove "0x" prefix and "_Z" suffix
//     let bit_res: Vec<bool> = hex
//         .chars()
//         .flat_map(|c| {
//             let num = c.to_digit(16).unwrap();
//             (0..4).rev().map(move |i| (num & (1 << i)) != 0)
//         })
//         .collect();

//     println!("bit_res_len: {}", bit_res.len());
//     let big_int = BigIntFelt252::from_bits_be(&bit_res);

//     println!(
//         "data in hex: {:?}",
//         big_int
//             .to_bytes_be()
//             .iter()
//             .map(|x| format!("{:02x}", x))
//             .collect::<Vec<String>>()
//             .join("")
//     );
//     Felt252::from_bigint(big_int).unwrap()
// }

#[test]
fn sending_elements_span_consistent_with_receiving() {
    let mut prng = PrngKeccak256::new();
    let num_felts = 1;
    let random_vec = prng.random_felts_vec::<Felt252>(num_felts);

    //let prng_
    let mut prover_channel = MyFSProverChannel::new(PrngKeccak256::new());
    let result = prover_channel.send_felts(&random_vec);
    assert!(result.is_ok());
    let random_num_p = prover_channel.draw_number(1000);
    let proof = prover_channel.get_proof();
    assert_eq!(
        proof.len(),
        ((Felt252::MODULUS_BIT_SIZE as usize) + 7) / 8 * num_felts
    );

    let mut verifier_channel = MyFSVerifierChannel::new(PrngKeccak256::new(), proof);
    //let mut verifier_output = vec![Felt252::zero(); 20];
    let verifier_output = verifier_channel.recv_felts(num_felts).unwrap();
    let random_num_v = verifier_channel.draw_number(1000);

    // assert_eq!(random_vec, verifier_output);
    assert_eq!(random_num_p, random_num_v);
}
