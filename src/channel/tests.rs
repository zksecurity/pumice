use super::fs_prover_channel::FSProverChannel;
use super::fs_verifier_channel::FSVerifierChannel;
use super::{Channel, FSChannel, ProverChannel, VerifierChannel};
use crate::{
    randomness::prng::{Prng, PrngKeccak256, PrngOnlyForTest},
    Felt252,
};
use ark_ff::PrimeField;
use blake2::{Blake2s256, Digest};
use hex_literal::hex;
use sha3::digest::generic_array::GenericArray;
use sha3::digest::OutputSizeUser;
use sha3::Sha3_256;

type MyFSVerifierChannel = FSVerifierChannel<Felt252, Sha3_256, PrngKeccak256>;
type MyFSProverChannel = FSProverChannel<Felt252, Sha3_256, PrngKeccak256>;
type BigIntFelt252 = <Felt252 as PrimeField>::BigInt;

fn generate_commitment(
    prng: &mut PrngKeccak256,
) -> GenericArray<u8, <Blake2s256 as OutputSizeUser>::OutputSize> {
    let mut raw_bytes = [0u8; 32];
    prng.random_bytes(&mut raw_bytes);
    GenericArray::<u8, <Blake2s256 as OutputSizeUser>::OutputSize>::clone_from_slice(&raw_bytes)
}

#[test]
fn constant_keccak_channel() {
    let prng_p = PrngKeccak256::new_with_seed(&[0u8; 4]);
    let prng_v = PrngKeccak256::new_with_seed(&[0u8; 4]);
    let prover_channel = MyFSProverChannel::new(prng_p);
    let mut verifier_channel = MyFSVerifierChannel::new(prng_v, prover_channel.get_proof());

    // values are calculated from stone-prover/src/starkware/channel/noninteractive_channel_test.cc
    // using PrimeFieldElement<252, 3>
    let random_felem_v1 = verifier_channel.draw_felem();
    let expected_felem_v1 = Felt252::from_be_bytes_mod_order(&hex!(
        "01f75714e70bf92f1a472085588006caf99aa605bb062098f25af56f9cb988dd"
    ));
    assert_eq!(random_felem_v1, expected_felem_v1);

    let random_felem_v2 = verifier_channel.draw_felem();
    let expected_felem_v2 = Felt252::from_be_bytes_mod_order(&hex!(
        "060b22b317393cd9509829cf22b8379cd9607c2328363f64ac34f89d0cc6b679"
    ));
    assert_eq!(random_felem_v2, expected_felem_v2);

    let random_felem_v3 = verifier_channel.draw_felem();
    let expected_felem_v3 = Felt252::from_be_bytes_mod_order(&hex!(
        "06225ab6b4b37f0eb3bb2d694ff09fda59ae3daeafb17c93db11ddfb7511a59b"
    ));
    assert_eq!(random_felem_v3, expected_felem_v3);
}

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
    let _ = prover_channel.send_bytes(&pdata1);
    let _ = prover_channel.send_bytes(&pdata2);

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
        let _ = prover_channel.send_bytes(&bytes_to_send);
        bytes_sent.push(bytes_to_send);
    }

    let proof = prover_channel.get_proof();
    let mut verifier_channel = MyFSVerifierChannel::new(PrngKeccak256::new(), proof);
    for bytes in bytes_sent {
        assert_eq!(verifier_channel.recv_bytes(bytes.len()).unwrap(), bytes);
    }
}

#[test]
fn fri_flow_simulation() {
    let mut prover_channel = MyFSProverChannel::new(PrngKeccak256::new());

    let mut prng: PrngKeccak256 = PrngKeccak256::new();
    let pcommitment1 = generate_commitment(&mut prng);

    // First FRI layer
    let _ = prover_channel.send_commit_hash(pcommitment1);
    // first evaluation point
    let ptest_field_element1 = prover_channel.draw_felem();
    // second evaluation point
    let ptest_field_element2 = prover_channel.draw_felem();

    // expected last layer const
    let pexpected_last_layer_const = prng.random_felem::<Felt252>();
    let _ = prover_channel.send_felts(&[pexpected_last_layer_const]);

    // query index#1 first layer
    let pnumber1 = prover_channel.draw_number(8);
    // query index#2 first layer
    let pnumber2 = prover_channel.draw_number(8);

    let mut pdecommitment1 = Vec::new();
    for _ in 0..15 {
        let node = generate_commitment(&mut prng);
        // FRI layer
        let _ = prover_channel.send_decommit_node(node);
        pdecommitment1.push(node);
    }

    let proof = prover_channel.get_proof();
    let mut verifier_channel = MyFSVerifierChannel::new(PrngKeccak256::new(), proof);

    let vcommitment1 = verifier_channel.recv_commit_hash().unwrap();
    assert_eq!(vcommitment1, pcommitment1);

    // first evaluation point
    let vtest_field_element1 = verifier_channel.draw_felem();
    assert_eq!(vtest_field_element1, ptest_field_element1);
    // second evaluation point
    let vtest_field_element2 = verifier_channel.draw_felem();
    assert_eq!(vtest_field_element2, ptest_field_element2);

    // expected last layer const
    let vexpected_last_layer_const = verifier_channel.recv_felts(1).unwrap()[0];
    assert_eq!(vexpected_last_layer_const, pexpected_last_layer_const);

    // query index #1 first layer
    let vnumber1 = verifier_channel.draw_number(8);
    assert_eq!(vnumber1, pnumber1);
    // query index #2 first layer
    let vnumber2 = verifier_channel.draw_number(8);
    assert_eq!(vnumber2, pnumber2);

    let mut vdecommitment1 = Vec::new();
    for _ in 0..15 {
        // FRI layer
        vdecommitment1.push(verifier_channel.recv_decommit_node().unwrap());
    }
    assert_eq!(vdecommitment1, pdecommitment1);
}
