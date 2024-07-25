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

#[test]
fn sending_felts_consistent_with_receiving() {
    let mut prng = PrngKeccak256::new();
    let num_felts = 20;
    let random_vec = prng.random_felts_vec::<Felt252>(num_felts);

    //let prng_
    let mut prover_channel = MyFSProverChannel::new(PrngKeccak256::new());
    let result = prover_channel.send_felts(&random_vec);
    assert!(result.is_ok());
    let random_num_p = prover_channel.draw_number(1000);
    let proof = prover_channel.get_proof();

    let mut verifier_channel = MyFSVerifierChannel::new(PrngKeccak256::new(), proof);
    //let mut verifier_output = vec![Felt252::zero(); 20];
    let verifier_output = verifier_channel.recv_felts(num_felts).unwrap();
    let random_num_v = verifier_channel.draw_number(1000);

    assert_eq!(random_vec, verifier_output);
    assert_eq!(random_num_p, random_num_v);
}

#[test]
fn sending_consistent_with_receiving_bytes() {
    let mut prng = PrngKeccak256::new();
    let mut pdata1 = vec![0; 8];
    prng.random_bytes(&mut pdata1);
    let mut pdata2 = vec![0; 4];
    prng.random_bytes(&mut pdata2);

    let mut prover_channel = MyFSProverChannel::new(PrngKeccak256::new());
    prover_channel.send_bytes(&pdata1);
    prover_channel.send_bytes(&pdata2);

    let proof = prover_channel.get_proof();
    let mut verifier_channel = MyFSVerifierChannel::new(PrngKeccak256::new(), proof);

    let vdata1 = verifier_channel.recv_bytes(8).unwrap();
    let vdata2 = verifier_channel.recv_bytes(4).unwrap();

    assert_eq!(vdata1, pdata1);
    assert_eq!(vdata2, pdata2);
}

// TODO : later
// #[test]
// fn proof_of_work() {
//     let prng = PrngKeccak256::new();
//     let mut prover_channel = MyFSProverChannel::new(prng);

//     let work_bits = 15;
//     prover_channel.apply_proof_of_work(work_bits);
//     let pow_value = prover_channel.recv_number(1 << 24);

//     let proof = prover_channel.get_proof();
//     let prng = PrngKeccak256::new();
//     let mut verifier_channel = MyFSVerifierChannel::new(prng, proof);

//     verifier_channel.apply_proof_of_work(work_bits);
//     assert_eq!(verifier_channel.send_number(1 << 24), pow_value);

//     let prng = PrngKeccak256::new();
//     let mut verifier_channel_bad_1 = MyFSVerifierChannel::new(prng, proof.clone());
//     assert!(verifier_channel_bad_1.apply_proof_of_work(work_bits + 1).is_err());

//     let prng = PrngKeccak256::new();
//     let mut verifier_channel_bad2 = MyFSVerifierChannel::new(prng, proof.clone());
//     assert!(verifier_channel_bad2.apply_proof_of_work(work_bits - 1).is_err());

//     let prng = PrngKeccak256::new();
//     let mut nonpow_prover_channel = MyFSProverChannel::new(prng);
//     assert_ne!(nonpow_prover_channel.recv_number(1 << 24), pow_value);
// }

// #[test]
// fn proof_of_work_depends_on_state() {
//     let prng = PrngKeccak256::new();
//     let mut prover_channel_1 = MyFSProverChannel::new(prng);
//     let pdata1 = prover_channel_1.draw_byte_vector(8);
//     prover_channel_1.send_bytes(&pdata1);

//     let work_bits = 15;
//     prover_channel_1.apply_proof_of_work(work_bits);
//     let pow_value_1 = prover_channel_1.recv_number(1 << 24);

//     let prng = PrngKeccak256::new();
//     let mut prover_channel_2 = MyFSProverChannel::new(prng);
//     let pdata2 = prover_channel_2.draw_byte_vector(8);
//     prover_channel_2.send_bytes(&pdata2);

//     prover_channel_2.apply_proof_of_work(work_bits);
//     let pow_value_2 = prover_channel_2.recv_number(1 << 24);

//     assert_ne!(pow_value_1, pow_value_2);
// }

// #[test]
// fn proof_of_work_zero_bits() {
//     let prng = PrngKeccak256::new();
//     let mut prover_channel_1 = MyFSProverChannel::new(prng);

//     prover_channel_1.apply_proof_of_work(0);
//     let pow_value_1 = prover_channel_1.recv_number(1 << 24);

//     let prng = PrngKeccak256::new();
//     let mut prover_channel_2 = MyFSProverChannel::new(prng);
//     let pow_value_2 = prover_channel_2.recv_number(1 << 24);

//     assert_eq!(pow_value_1, pow_value_2);

//     let proof = prover_channel_1.get_proof();
//     let prng = PrngKeccak256::new();
//     let mut verifier_channel = MyFSVerifierChannel::new(prng, proof);

//     verifier_channel.apply_proof_of_work(0);
//     let pow_value_3 = verifier_channel.send_number(1 << 24);
//     assert_eq!(pow_value_1, pow_value_3);
// }

#[test]
fn sending_consistent_with_receiving_random_bytes() {
    let mut prng = PrngKeccak256::new();
    let mut prover_channel = MyFSProverChannel::new(PrngKeccak256::new());
    let mut bytes_sent = Vec::new();

    for _ in 0..100 {
        let random_num = prng.uniform_int(0..=128) as usize;
        let mut bytes_to_send = vec![0; random_num];
        prng.random_bytes(&mut bytes_to_send);
        prover_channel.send_bytes(&bytes_to_send);
        bytes_sent.push(bytes_to_send);
    }

    let proof = prover_channel.get_proof();
    let mut verifier_channel = MyFSVerifierChannel::new(PrngKeccak256::new(), proof);
    for bytes in bytes_sent {
        assert_eq!(verifier_channel.recv_bytes(bytes.len()).unwrap(), bytes);
    }
}

// #[test]
// fn fri_flow_simulation() {
//     let prng = PrngKeccak256::new();
//     let mut prover_channel = MyFSProverChannel::new(PrngKeccak256::new());

//     let pcommitment1 = prng.random_hash();
//     prover_channel.send_commitment_hash(pcommitment1, "First FRI layer");

//     let ptest_field_element1 = prover_channel.recv_field_element(test_field, "evaluation point");
//     let ptest_field_element2 =
//         prover_channel.recv_field_element(test_field, "2nd evaluation point");

//     let pexpected_last_layer_const = test_field.random_element(&prng);
//     prover_channel.send_field_element(pexpected_last_layer_const, "expected last layer const");

//     let pnumber1 = prover_channel.recv_number(8, "query index #1 first layer");
//     let pnumber2 = prover_channel.recv_number(8, "query index #2 first layer");

//     let mut pdecommitment1 = Vec::new();
//     for _ in 0..15 {
//         let node = prng.random_hash();
//         prover_channel.send_decommitment_node(node, "FRI layer");
//         pdecommitment1.push(node);
//     }

//     let proof = prover_channel.get_proof();
//     let prng = PrngKeccak256::new();
//     let mut verifier_channel = MyFSVerifierChannel::new(prng, proof);

//     let vcommitment1 = verifier_channel.recv_commitment_hash("First FRI layer");
//     assert_eq!(vcommitment1, pcommitment1);
//     let vtest_field_element1 = verifier_channel.send_field_element(test_field, "evaluation point");
//     assert_eq!(vtest_field_element1, ptest_field_element1);
//     let vtest_field_element2 =
//         verifier_channel.send_field_element(test_field, "evaluation point ^ 2");
//     assert_eq!(vtest_field_element2, ptest_field_element2);
//     let vexpected_last_layer_const =
//         verifier_channel.recv_field_element(test_field, "expected last layer const");
//     assert_eq!(vexpected_last_layer_const, pexpected_last_layer_const);
//     let vnumber1 = verifier_channel.send_number(8, "query index #1 first layer");
//     assert_eq!(vnumber1, pnumber1);
//     let vnumber2 = verifier_channel.send_number(8, "query index #2 first layer");
//     assert_eq!(vnumber2, pnumber2);
//     let mut vdecommitment1 = Vec::new();
//     for _ in 0..15 {
//         vdecommitment1.push(verifier_channel.recv_decommitment_node("FRI layer"));
//     }
//     assert_eq!(vdecommitment1, pdecommitment1);
// }
