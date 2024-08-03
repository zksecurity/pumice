use super::fs_prover_channel::FSProverChannel;
use super::fs_verifier_channel::FSVerifierChannel;
use super::{Channel, FSChannel, ProverChannel, VerifierChannel};
use ark_ff::PrimeField;
use felt::Felt252;
use generic_array::GenericArray;
use hex_literal::hex;
use rand::{Rng, RngCore};
use randomness::{keccak256::PrngKeccak256, Prng};
use sha3::Sha3_256;

type TestFSVerifierChannel = FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256>;
type TestFSProverChannel = FSProverChannel<Felt252, PrngKeccak256, Sha3_256>;

type TestCommitmentSize = <PrngKeccak256 as Prng>::DigestSize;

const DIGEST_NUM_BYTES: usize = Felt252::MODULUS_BIT_SIZE.div_ceil(8) as usize;

fn generate_random_bytes(n_elements: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n_elements];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn generate_prover_channel() -> TestFSProverChannel {
    let prng = PrngKeccak256::new();
    TestFSProverChannel::new(prng)
}

fn generate_verifier_channel(proof: Vec<u8>) -> TestFSVerifierChannel {
    let prng = PrngKeccak256::new();
    TestFSVerifierChannel::new(prng, proof)
}

fn generate_commitment() -> GenericArray<u8, TestCommitmentSize> {
    let mut raw_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw_bytes);
    GenericArray::try_from_iter(raw_bytes.into_iter()).unwrap()
}

fn generate_random_felem() -> Felt252 {
    let mut raw_bytes = [0u8; DIGEST_NUM_BYTES];
    rand::thread_rng().fill_bytes(&mut raw_bytes);
    Felt252::from_be_bytes_mod_order(&raw_bytes)
}

#[test]
fn constant_keccak_channel() {
    let prng_p = PrngKeccak256::new_with_seed(&[0u8; 4]);
    let prng_v = PrngKeccak256::new_with_seed(&[0u8; 4]);
    let prover_channel = TestFSProverChannel::new(prng_p);
    let mut verifier_channel = TestFSVerifierChannel::new(prng_v, prover_channel.get_proof());

    // values are calculated from stone-prover/src/starkware/channel/noninteractive_channel_test.cc
    // - ConstantKeccakChannelTest
    let random_felem_v1 = verifier_channel.draw_felem();
    // Mont form of 0x7f097aaa40a3109067011986ae40f1ce97a01f4f1a72d80a52821f317504992_Z
    let expected_felem_v1 = Felt252::from_be_bytes_mod_order(&hex!(
        "01f75714e70bf7a81a472085588006caf99aa605bb0be098f25af56f9cb988dd"
    ));
    assert_eq!(random_felem_v1, expected_felem_v1);

    let random_felem_v2 = verifier_channel.draw_felem();
    // Mont form of 0x18bcafdd60fc70e5e8a9a18687135d0bf1a355d9882969a6b3619e56bf2d49d_Z
    let expected_felem_v2 = Felt252::from_be_bytes_mod_order(&hex!(
        "060b22b317393ca6509829cf22b8379cd9607c232836ff64ac34f89d0cc6b679"
    ));
    assert_eq!(random_felem_v2, expected_felem_v2);

    let random_felem_v3 = verifier_channel.draw_felem();
    // Mont form of 0x2f06b17e08bc409b945b951de8102653dc48a143b87d09b6c95587679816d02_Z
    let expected_felem_v3 = Felt252::from_be_bytes_mod_order(&hex!(
        "06225ab6b4b37edbb3bb2d694ff09fda59ae3daeafb23c93db11ddfb7511a59b"
    ));
    assert_eq!(random_felem_v3, expected_felem_v3);

    let random_number_v1 = verifier_channel.draw_number(1 << 10);
    let expected_number_v1 = 851;
    assert_eq!(random_number_v1, expected_number_v1);
}

#[test]
fn sending_felts_consistent_with_receiving() {
    let num_felts = 20;
    let random_vec: Vec<Felt252> = (0..num_felts).map(|_| generate_random_felem()).collect();

    let mut prover_channel = generate_prover_channel();
    let result = prover_channel.send_felts(&random_vec);
    assert!(result.is_ok());
    let random_num_p = prover_channel.draw_number(1000);
    let proof = prover_channel.get_proof();

    let mut verifier_channel = generate_verifier_channel(proof);
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

    let mut prover_channel = generate_prover_channel();
    let _ = prover_channel.send_bytes(&pdata1);
    let _ = prover_channel.send_bytes(&pdata2);

    let proof = prover_channel.get_proof();
    let mut verifier_channel = generate_verifier_channel(proof);

    let vdata1 = verifier_channel.recv_bytes(8).unwrap();
    let vdata2 = verifier_channel.recv_bytes(4).unwrap();

    assert_eq!(vdata1, pdata1);
    assert_eq!(vdata2, pdata2);
}

#[test]
fn proof_of_work() {
    let mut prover_channel = generate_prover_channel();

    let work_bits = 15;
    let _ = prover_channel.apply_proof_of_work(work_bits);
    let pow_value = prover_channel.draw_number(1 << 24);

    let mut verifier_channel = generate_verifier_channel(prover_channel.get_proof());

    let _ = verifier_channel.apply_proof_of_work(work_bits);
    assert_eq!(verifier_channel.draw_number(1 << 24), pow_value);

    let mut verifier_channel_bad_1 = generate_verifier_channel(prover_channel.get_proof());
    assert!(verifier_channel_bad_1
        .apply_proof_of_work(work_bits + 1)
        .is_err());

    let mut verifier_channel_bad2 = generate_verifier_channel(prover_channel.get_proof());
    assert!(verifier_channel_bad2
        .apply_proof_of_work(work_bits - 1)
        .is_err());

    let mut nonpow_prover_channel = generate_prover_channel();
    assert_ne!(nonpow_prover_channel.draw_number(1 << 24), pow_value);
}

#[test]
fn proof_of_work_depends_on_state() {
    let mut prng = PrngKeccak256::new();

    let mut prover_channel_1 = generate_prover_channel();
    let mut pdata1 = vec![0; 8];
    prng.random_bytes(&mut pdata1);
    let _ = prover_channel_1.send_bytes(&pdata1);

    let work_bits = 15;
    let _ = prover_channel_1.apply_proof_of_work(work_bits);
    let pow_value_1 = prover_channel_1.draw_number(1 << 24);

    let mut prover_channel_2 = generate_prover_channel();
    let mut pdata2 = vec![0; 8];
    prng.random_bytes(&mut pdata2);
    let _ = prover_channel_2.send_bytes(&pdata2);

    let _ = prover_channel_2.apply_proof_of_work(work_bits);
    let pow_value_2 = prover_channel_2.draw_number(1 << 24);

    assert_ne!(pow_value_1, pow_value_2);
}

#[test]
fn proof_of_work_zero_bits() {
    let mut prover_channel_1 = generate_prover_channel();

    let _ = prover_channel_1.apply_proof_of_work(0);
    let pow_value_1 = prover_channel_1.draw_number(1 << 24);

    let mut prover_channel_2 = generate_prover_channel();
    let pow_value_2 = prover_channel_2.draw_number(1 << 24);

    assert_eq!(pow_value_1, pow_value_2);

    let proof = prover_channel_1.get_proof();
    let mut verifier_channel = generate_verifier_channel(proof);

    let _ = verifier_channel.apply_proof_of_work(0);
    let pow_value_3 = verifier_channel.draw_number(1 << 24);
    assert_eq!(pow_value_1, pow_value_3);
}

#[test]
fn sending_consistent_with_receiving_random_bytes() {
    let mut prover_channel = generate_prover_channel();
    let mut bytes_sent = Vec::new();

    for _ in 0..100 {
        let random_num = rand::thread_rng().gen_range(0..=128);
        let bytes_to_send = generate_random_bytes(random_num);
        let _ = prover_channel.send_bytes(&bytes_to_send);
        bytes_sent.push(bytes_to_send);
    }

    let proof = prover_channel.get_proof();
    let mut verifier_channel = generate_verifier_channel(proof);
    for bytes in bytes_sent {
        assert_eq!(verifier_channel.recv_bytes(bytes.len()).unwrap(), bytes);
    }
}

#[test]
fn fri_flow_simulation() {
    let mut prover_channel = generate_prover_channel();

    let pcommitment1 = generate_commitment();

    // First FRI layer
    let _ = prover_channel.send_commit_hash(pcommitment1);
    // first evaluation point
    let ptest_field_element1 = prover_channel.draw_felem();
    // second evaluation point
    let ptest_field_element2 = prover_channel.draw_felem();

    // expected last layer const
    let pexpected_last_layer_const = generate_random_felem();
    let _ = prover_channel.send_felts(&[pexpected_last_layer_const]);

    // query index#1 first layer
    let pnumber1 = prover_channel.draw_number(8);
    // query index#2 first layer
    let pnumber2 = prover_channel.draw_number(8);

    let mut pdecommitment1 = Vec::new();
    for _ in 0..15 {
        let node = generate_commitment();
        // FRI layer
        let _ = prover_channel.send_decommit_node(node);
        pdecommitment1.push(node);
    }

    let proof = prover_channel.get_proof();
    let mut verifier_channel = generate_verifier_channel(proof);

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
