use super::fs_prover_channel::FSProverChannel;
use super::fs_verifier_channel::FSVerifierChannel;
use super::{Channel, FSChannel, ProverChannel, VerifierChannel};
use ark_ff::PrimeField;
use felt::Felt252;
use generic_array::GenericArray;
use hex_literal::hex;
use randomness::{keccak256::PrngKeccak256, poseidon3::PrngPoseidon3, Prng, PrngOnlyForTest};
use sha3::Sha3_256;

type TestFSVerifierChannel = FSVerifierChannel<Felt252, PrngPoseidon3, Sha3_256>;
type TestFSProverChannel = FSProverChannel<Felt252, PrngPoseidon3, Sha3_256>;

type TestCommitmentSize = <PrngPoseidon3 as Prng>::CommitmentSize;

const DIGEST_NUM_BYTES: usize = Felt252::MODULUS_BIT_SIZE.div_ceil(8) as usize;

fn generate_commitment(prng: &mut PrngPoseidon3) -> GenericArray<u8, TestCommitmentSize> {
    let mut raw_bytes = [0u8; DIGEST_NUM_BYTES];
    prng.random_bytes(&mut raw_bytes);
    GenericArray::try_from_iter(raw_bytes.into_iter()).unwrap()
}

fn generate_random_felem<P: Prng>(prng: &mut P) -> Felt252 {
    let mut raw_bytes = [0u8; DIGEST_NUM_BYTES];
    prng.random_bytes(&mut raw_bytes);
    Felt252::from_be_bytes_mod_order(&raw_bytes)
}

fn generate_random_felem_as_bytes<P: Prng>(prng: &mut P, n_elements: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..n_elements {
        bytes.extend(prng.random_bytes_vec(DIGEST_NUM_BYTES));
    }
    bytes
}

#[test]
fn constant_poseidon_channel() {
    let init_state_bytes: <TestFSProverChannel as Channel>::Commitment = GenericArray::default();

    let prng_p = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let prng_v = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let prover_channel = TestFSProverChannel::new(prng_p);
    let mut verifier_channel = TestFSVerifierChannel::new(prng_v, prover_channel.get_proof());

    let random_felem_v1 = verifier_channel.draw_felem();
    let expected_felem_v1 = Felt252::from_be_bytes_mod_order(&hex!(
        "0293d3e8a80f400daaaffdd5932e2bcc8814bab8f414a75dcacf87318f8b14c5"
    ));
    assert_eq!(random_felem_v1, expected_felem_v1);

    let random_felem_v2 = verifier_channel.draw_felem();
    let expected_felem_v2 = Felt252::from_be_bytes_mod_order(&hex!(
        "05134197931125e849424475aa20cd6ca0ce8603b79177c3f76e2119c8f98c53"
    ));
    assert_eq!(random_felem_v2, expected_felem_v2);

    let random_felem_v3 = verifier_channel.draw_felem();
    let expected_felem_v3 = Felt252::from_be_bytes_mod_order(&hex!(
        "01b33d104778bd3334a98cf66bf4dce1b919b153d40801bb98416077bc58843a"
    ));
    assert_eq!(random_felem_v3, expected_felem_v3);

    let random_number_v1 = verifier_channel.draw_number(1 << 10);
    let expected_number_v1 = 617;
    assert_eq!(random_number_v1, expected_number_v1);
}

#[test]
fn sending_consistent_with_receiving_bytes() {
    let mut prng = PrngKeccak256::new();
    let mut init_state_bytes: <TestFSProverChannel as Channel>::Commitment =
        GenericArray::default();
    prng.random_bytes(&mut init_state_bytes);

    let pdata1 = generate_random_felem_as_bytes(&mut prng, 1);
    let pdata2 = generate_random_felem_as_bytes(&mut prng, 2);

    let prng_p = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel = TestFSProverChannel::new(prng_p);

    let _ = prover_channel.send_bytes(&pdata1);
    let _ = prover_channel.send_bytes(&pdata2);
    let pdata3 = prover_channel.draw_felem();

    let proof = prover_channel.get_proof();
    let prng_v = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut verifier_channel = TestFSVerifierChannel::new(prng_v, proof);

    let vdata1 = verifier_channel.recv_bytes(DIGEST_NUM_BYTES).unwrap();
    let vdata2 = verifier_channel.recv_bytes(DIGEST_NUM_BYTES * 2).unwrap();
    let vdata3 = verifier_channel.draw_felem();

    assert_eq!(vdata1, pdata1);
    assert_eq!(vdata2, pdata2);
    assert_eq!(pdata3, vdata3);
}

#[test]
fn proof_of_work() {
    let init_state_bytes: <TestFSProverChannel as Channel>::Commitment = GenericArray::default();

    let prng_p = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel = TestFSProverChannel::new(prng_p);

    let work_bits = 15;
    let _ = prover_channel.apply_proof_of_work(work_bits);
    let pow_value = prover_channel.draw_number(1 << 24);

    let proof = prover_channel.get_proof();
    let prng_v = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut verifier_channel = TestFSVerifierChannel::new(prng_v, proof.clone());

    let _ = verifier_channel.apply_proof_of_work(work_bits);
    assert_eq!(verifier_channel.draw_number(1 << 24), pow_value);

    let prng_vbad_1 = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut verifier_channel_bad_1 = TestFSVerifierChannel::new(prng_vbad_1, proof.clone());
    assert!(verifier_channel_bad_1
        .apply_proof_of_work(work_bits + 1)
        .is_err());

    let prng_vbad_2 = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut verifier_channel_bad2 = TestFSVerifierChannel::new(prng_vbad_2, proof.clone());
    assert!(verifier_channel_bad2
        .apply_proof_of_work(work_bits - 1)
        .is_err());

    let prng_p2 = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut nonpow_prover_channel = TestFSProverChannel::new(prng_p2);
    assert_ne!(nonpow_prover_channel.draw_number(1 << 24), pow_value);
}

#[test]
fn proof_of_work_depends_on_state() {
    let mut prng = PrngKeccak256::new();
    let init_state_bytes: <TestFSProverChannel as Channel>::Commitment = GenericArray::default();

    let prng_p1 = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel_1 = TestFSProverChannel::new(prng_p1);
    let mut pdata1 = vec![0; 8];
    prng.random_bytes(&mut pdata1);
    let _ = prover_channel_1.send_bytes(&pdata1);

    let work_bits = 15;
    let _ = prover_channel_1.apply_proof_of_work(work_bits);
    let pow_value_1 = prover_channel_1.draw_number(1 << 24);

    let prng_p2 = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel_2 = TestFSProverChannel::new(prng_p2);
    let mut pdata2 = vec![0; 8];
    prng.random_bytes(&mut pdata2);
    let _ = prover_channel_2.send_bytes(&pdata2);

    let _ = prover_channel_2.apply_proof_of_work(work_bits);
    let pow_value_2 = prover_channel_2.draw_number(1 << 24);

    assert_ne!(pow_value_1, pow_value_2);
}

#[test]
fn proof_of_work_zero_bits() {
    let init_state_bytes: <TestFSProverChannel as Channel>::Commitment = GenericArray::default();
    let prng_p1 = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel_1 = TestFSProverChannel::new(prng_p1);

    let _ = prover_channel_1.apply_proof_of_work(0);
    let pow_value_1 = prover_channel_1.draw_number(1 << 24);

    let prng_p2 = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel_2 = TestFSProverChannel::new(prng_p2);
    let pow_value_2 = prover_channel_2.draw_number(1 << 24);

    assert_eq!(pow_value_1, pow_value_2);

    let proof = prover_channel_1.get_proof();
    let prng_v = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut verifier_channel = TestFSVerifierChannel::new(prng_v, proof);

    let _ = verifier_channel.apply_proof_of_work(0);
    let pow_value_3 = verifier_channel.draw_number(1 << 24);
    assert_eq!(pow_value_1, pow_value_3);
}

#[test]
fn sending_consistent_with_receiving_random_bytes() {
    let mut prng = PrngKeccak256::new();
    let init_state_bytes: <TestFSProverChannel as Channel>::Commitment = GenericArray::default();
    let prng_p = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel = TestFSProverChannel::new(prng_p);
    let mut bytes_sent = Vec::new();

    for _ in 0..100 {
        let random_num = prng.uniform_int(0..=128) as usize;
        let mut bytes_to_send = vec![0; random_num];
        prng.random_bytes(&mut bytes_to_send);
        let _ = prover_channel.send_bytes(&bytes_to_send);
        bytes_sent.push(bytes_to_send);
    }

    let proof = prover_channel.get_proof();
    let prng_v = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut verifier_channel = TestFSVerifierChannel::new(prng_v, proof);
    for bytes in bytes_sent {
        assert_eq!(verifier_channel.recv_bytes(bytes.len()).unwrap(), bytes);
    }
}

#[test]
fn fri_flow_simulation() {
    let init_state_bytes: <TestFSProverChannel as Channel>::Commitment = GenericArray::default();

    let prng_p = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut prover_channel = TestFSProverChannel::new(prng_p);

    let mut prng = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let pcommitment1 = generate_commitment(&mut prng);

    // First FRI layer
    let _ = prover_channel.send_commit_hash(pcommitment1);
    // first evaluation point
    let ptest_field_element1 = prover_channel.draw_felem();
    // second evaluation point
    let ptest_field_element2 = prover_channel.draw_felem();

    // expected last layer const
    let pexpected_last_layer_const = generate_random_felem(&mut prng);
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
    let prng_v = PrngPoseidon3::new_with_seed(&init_state_bytes);
    let mut verifier_channel = TestFSVerifierChannel::new(prng_v, proof);

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
