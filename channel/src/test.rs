use super::fs_prover_channel::FSProverChannel;
use super::fs_verifier_channel::FSVerifierChannel;
use super::{Channel, FSChannel, ProverChannel, VerifierChannel};
use ark_ff::PrimeField;
use blake2::Blake2s256;
use felt::Felt252;
use generic_array::typenum::U32;
use generic_array::{ArrayLength, GenericArray};
use hex_literal::hex;
use paste::paste;
use rand::{Rng, RngCore};
use randomness::Prng;
use sha3::{Digest, Sha3_256};

struct TestFixtureConstants<F: PrimeField> {
    seed: Vec<u8>,
    expected_felems: Vec<F>,
    expected_random_numbers: Vec<u64>,
}

trait TestFixtures {
    type Prng: Prng;
    type VerifierChannel: VerifierChannel<Field = Self::TestField, Commitment = GenericArray<u8, Self::DigestSize>>
        + FSChannel;
    type ProverChannel: ProverChannel<Field = Self::TestField, Commitment = GenericArray<u8, Self::DigestSize>>
        + FSChannel;
    type DigestSize: ArrayLength<u8>;
    type TestField: PrimeField;

    const TEST_DIGEST_NUM_BYTES: usize;

    fn get_constants() -> TestFixtureConstants<Self::TestField>;

    fn default_seed() -> Vec<u8>;
    fn generate_prover_channel(initia_state_bytes: &[u8]) -> Self::ProverChannel;
    fn generate_verifier_channel(
        initia_state_bytes: &[u8],
        proof: Vec<u8>,
    ) -> Self::VerifierChannel;

    fn generate_initial_state_bytes() -> GenericArray<u8, Self::DigestSize> {
        let mut bytes = GenericArray::default();
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    fn generate_random_bytes(n_elements: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; n_elements];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    // XXX : Do same functionality as generate_initial_state_bytes, but left this function for clarity
    fn generate_commitment() -> GenericArray<u8, Self::DigestSize> {
        Self::generate_initial_state_bytes()
    }

    fn generate_random_felem() -> Self::TestField {
        let mut raw_bytes =
            vec![0u8; <Self::TestField as PrimeField>::MODULUS_BIT_SIZE.div_ceil(8) as usize];
        rand::thread_rng().fill_bytes(&mut raw_bytes);
        Self::TestField::from_be_bytes_mod_order(&raw_bytes)
    }
}

struct Poseidon3TestTypes<W: Digest>(std::marker::PhantomData<W>);

impl<W: Digest> TestFixtures for Poseidon3TestTypes<W> {
    type Prng = randomness::poseidon3::PrngPoseidon3;
    type VerifierChannel = FSVerifierChannel<Felt252, Self::Prng, W>;
    type ProverChannel = FSProverChannel<Felt252, Self::Prng, W>;
    type DigestSize = U32;
    type TestField = Felt252;

    const TEST_DIGEST_NUM_BYTES: usize =
        <Self::TestField as PrimeField>::MODULUS_BIT_SIZE.div_ceil(8) as usize;

    fn get_constants() -> TestFixtureConstants<Self::TestField> {
        TestFixtureConstants {
            seed: vec![0u8; Self::TEST_DIGEST_NUM_BYTES],
            expected_felems: vec![
                Felt252::from_be_bytes_mod_order(&hex!(
                    "0293d3e8a80f400daaaffdd5932e2bcc8814bab8f414a75dcacf87318f8b14c5"
                )),
                Felt252::from_be_bytes_mod_order(&hex!(
                    "05134197931125e849424475aa20cd6ca0ce8603b79177c3f76e2119c8f98c53"
                )),
                Felt252::from_be_bytes_mod_order(&hex!(
                    "01b33d104778bd3334a98cf66bf4dce1b919b153d40801bb98416077bc58843a"
                )),
            ],
            expected_random_numbers: vec![617],
        }
    }

    fn default_seed() -> Vec<u8> {
        vec![0u8; Self::TEST_DIGEST_NUM_BYTES]
    }

    fn generate_prover_channel(initia_state_bytes: &[u8]) -> Self::ProverChannel {
        let prng = Self::Prng::new_with_seed(initia_state_bytes);
        Self::ProverChannel::new(prng)
    }

    fn generate_verifier_channel(
        initia_state_bytes: &[u8],
        proof: Vec<u8>,
    ) -> Self::VerifierChannel {
        let prng = Self::Prng::new_with_seed(initia_state_bytes);
        Self::VerifierChannel::new(prng, proof)
    }
}

struct Keccak256TestTypes;

impl TestFixtures for Keccak256TestTypes {
    type Prng = randomness::keccak256::PrngKeccak256;
    type VerifierChannel = FSVerifierChannel<Felt252, Self::Prng, Sha3_256>;
    type ProverChannel = FSProverChannel<Felt252, Self::Prng, Sha3_256>;
    type DigestSize = U32;
    type TestField = Felt252;

    const TEST_DIGEST_NUM_BYTES: usize =
        <Self::TestField as PrimeField>::MODULUS_BIT_SIZE.div_ceil(8) as usize;

    fn get_constants() -> TestFixtureConstants<Self::TestField> {
        TestFixtureConstants {
            seed: vec![0u8; 4],
            // values are calculated from stone-prover/src/starkware/channel/noninteractive_channel_test.cc
            expected_felems: vec![
                // Mont form of 0x7f097aaa40a3109067011986ae40f1ce97a01f4f1a72d80a52821f317504992_Z
                Felt252::from_be_bytes_mod_order(&hex!(
                    "01f75714e70bf7a81a472085588006caf99aa605bb0be098f25af56f9cb988dd"
                )),
                // Mont form of 0x18bcafdd60fc70e5e8a9a18687135d0bf1a355d9882969a6b3619e56bf2d49d_Z
                Felt252::from_be_bytes_mod_order(&hex!(
                    "060b22b317393ca6509829cf22b8379cd9607c232836ff64ac34f89d0cc6b679"
                )),
                // Mont form of 0x2f06b17e08bc409b945b951de8102653dc48a143b87d09b6c95587679816d02_Z
                Felt252::from_be_bytes_mod_order(&hex!(
                    "06225ab6b4b37edbb3bb2d694ff09fda59ae3daeafb23c93db11ddfb7511a59b"
                )),
            ],
            expected_random_numbers: vec![851],
        }
    }

    fn default_seed() -> Vec<u8> {
        vec![]
    }

    fn generate_prover_channel(initia_state_bytes: &[u8]) -> Self::ProverChannel {
        let prng = Self::Prng::new_with_seed(initia_state_bytes);
        Self::ProverChannel::new(prng)
    }

    fn generate_verifier_channel(
        initia_state_bytes: &[u8],
        proof: Vec<u8>,
    ) -> Self::VerifierChannel {
        let prng = Self::Prng::new_with_seed(initia_state_bytes);
        Self::VerifierChannel::new(prng, proof)
    }

    fn generate_random_bytes(n_elements: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; n_elements];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}

fn test_constant_channel<T: TestFixtures>() {
    let seed = T::get_constants().seed;
    let prover_channel = T::generate_prover_channel(&seed);
    let mut verifier_channel = T::generate_verifier_channel(&seed, prover_channel.get_proof());

    for expected_felem in T::get_constants().expected_felems {
        let random_felem = verifier_channel.draw_felem();
        assert_eq!(random_felem, expected_felem);
    }

    for expected_random_number in T::get_constants().expected_random_numbers {
        let random_number = verifier_channel.draw_number(1 << 10);
        assert_eq!(random_number, expected_random_number);
    }
}

fn sending_consistent_with_receiving<T: TestFixtures>() {
    let num_felts = 20;
    let random_vec: Vec<T::TestField> =
        (0..num_felts).map(|_| T::generate_random_felem()).collect();

    let mut prover_channel = T::generate_prover_channel(&T::default_seed());
    let result = prover_channel.send_felts(&random_vec);
    assert!(result.is_ok());
    let random_num_p = prover_channel.draw_number(1000);
    let proof = prover_channel.get_proof();

    let mut verifier_channel = T::generate_verifier_channel(&T::default_seed(), proof);
    let verifier_output = verifier_channel.recv_felts(num_felts).unwrap();
    let random_num_v = verifier_channel.draw_number(1000);

    assert_eq!(random_vec, verifier_output);
    assert_eq!(random_num_p, random_num_v);
}

fn sending_consistent_with_receiving_bytes<T: TestFixtures>() {
    let pdata1 = T::generate_random_bytes(T::TEST_DIGEST_NUM_BYTES);
    let pdata2 = T::generate_random_bytes(T::TEST_DIGEST_NUM_BYTES * 2);

    let mut prover_channel = T::generate_prover_channel(&T::default_seed());
    let _ = prover_channel.send_bytes(&pdata1);
    let _ = prover_channel.send_bytes(&pdata2);

    let proof = prover_channel.get_proof();
    let mut verifier_channel = T::generate_verifier_channel(&T::default_seed(), proof);

    let vdata1 = verifier_channel
        .recv_bytes(T::TEST_DIGEST_NUM_BYTES)
        .unwrap();
    let vdata2 = verifier_channel
        .recv_bytes(T::TEST_DIGEST_NUM_BYTES * 2)
        .unwrap();

    assert_eq!(vdata1, pdata1);
    assert_eq!(vdata2, pdata2);
}

fn proof_of_work<T: TestFixtures>() {
    let init_state_bytes = T::generate_initial_state_bytes();
    let mut prover_channel = T::generate_prover_channel(&init_state_bytes);

    let work_bits = 15;
    let _ = prover_channel.apply_proof_of_work(work_bits);
    let pow_value = prover_channel.draw_number(1 << 24);

    let mut verifier_channel =
        T::generate_verifier_channel(&init_state_bytes, prover_channel.get_proof());

    let _ = verifier_channel.apply_proof_of_work(work_bits);
    assert_eq!(verifier_channel.draw_number(1 << 24), pow_value);

    let mut verifier_channel_bad_1 =
        T::generate_verifier_channel(&init_state_bytes, prover_channel.get_proof());
    assert!(verifier_channel_bad_1
        .apply_proof_of_work(work_bits + 1)
        .is_err());

    let mut verifier_channel_bad2 =
        T::generate_verifier_channel(&init_state_bytes, prover_channel.get_proof());
    assert!(verifier_channel_bad2
        .apply_proof_of_work(work_bits - 1)
        .is_err());

    let mut nonpow_prover_channel = T::generate_prover_channel(&init_state_bytes);
    assert_ne!(nonpow_prover_channel.draw_number(1 << 24), pow_value);
}

fn proof_of_work_depends_on_state<T: TestFixtures>() {
    let init_state_bytes = T::generate_initial_state_bytes();
    let pdata1 = T::generate_random_bytes(T::TEST_DIGEST_NUM_BYTES);
    let pdata2 = T::generate_random_bytes(T::TEST_DIGEST_NUM_BYTES);

    let mut prover_channel_1 = T::generate_prover_channel(&init_state_bytes);
    let _ = prover_channel_1.send_bytes(&pdata1);

    let work_bits = 15;
    let _ = prover_channel_1.apply_proof_of_work(work_bits);
    let pow_value_1 = prover_channel_1.draw_number(1 << 24);

    let mut prover_channel_2 = T::generate_prover_channel(&init_state_bytes);
    let _ = prover_channel_2.send_bytes(&pdata2);

    let _ = prover_channel_2.apply_proof_of_work(work_bits);
    let pow_value_2 = prover_channel_2.draw_number(1 << 24);

    assert_ne!(pow_value_1, pow_value_2);
}

fn proof_of_work_zero_bits<T: TestFixtures>() {
    let init_state_bytes = T::generate_initial_state_bytes();
    let mut prover_channel_1 = T::generate_prover_channel(&init_state_bytes);

    let _ = prover_channel_1.apply_proof_of_work(0);
    let pow_value_1 = prover_channel_1.draw_number(1 << 24);

    let mut prover_channel_2 = T::generate_prover_channel(&init_state_bytes);
    let pow_value_2 = prover_channel_2.draw_number(1 << 24);

    assert_eq!(pow_value_1, pow_value_2);

    let mut verifier_channel =
        T::generate_verifier_channel(&init_state_bytes, prover_channel_1.get_proof());

    let _ = verifier_channel.apply_proof_of_work(0);
    let pow_value_3 = verifier_channel.draw_number(1 << 24);
    assert_eq!(pow_value_1, pow_value_3);
}

fn sending_consistent_with_receiving_random_bytes<T: TestFixtures>() {
    let init_state_bytes = T::generate_initial_state_bytes();
    let mut prover_channel = T::generate_prover_channel(&init_state_bytes);
    let mut bytes_sent = Vec::new();

    for _ in 0..100 {
        let random_num = rand::thread_rng().gen_range(0..=20);
        let bytes_to_send = T::generate_random_bytes(random_num * T::Prng::bytes_chunk_size());
        let _ = prover_channel.send_bytes(&bytes_to_send);
        bytes_sent.push(bytes_to_send);
    }

    let proof = prover_channel.get_proof();
    let mut verifier_channel = T::generate_verifier_channel(&init_state_bytes, proof);
    for bytes in bytes_sent {
        assert_eq!(verifier_channel.recv_bytes(bytes.len()).unwrap(), bytes);
    }
}

fn fri_flow_simulation<T: TestFixtures>() {
    let init_state_bytes = T::generate_initial_state_bytes();
    let mut prover_channel = T::generate_prover_channel(&init_state_bytes);

    let pcommitment1 = T::generate_commitment();

    // First FRI layer
    let _ = prover_channel.send_commit_hash(pcommitment1.clone());
    // first evaluation point
    let ptest_field_element1 = prover_channel.draw_felem();
    // second evaluation point
    let ptest_field_element2 = prover_channel.draw_felem();

    // expected last layer const
    let pexpected_last_layer_const = T::generate_random_felem();
    let _ = prover_channel.send_felts(&[pexpected_last_layer_const]);

    // query index#1 first layer
    let pnumber1 = prover_channel.draw_number(8);
    // query index#2 first layer
    let pnumber2 = prover_channel.draw_number(8);

    let mut pdecommitment1 = Vec::new();
    for _ in 0..15 {
        let node = T::generate_commitment();
        // FRI layer
        let _ = prover_channel.send_decommit_node(node.clone());
        pdecommitment1.push(node);
    }

    let proof = prover_channel.get_proof();
    let mut verifier_channel = T::generate_verifier_channel(&init_state_bytes, proof);

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

macro_rules! generate_tests {
    ($($name:ident: $type:ty),*) => {
        paste! {
            $(
                #[test]
                fn [<constant_sanity_$name>]() {
                    test_constant_channel::<$type>();
                }

                #[test]
                fn [<sending_consistent_with_receiving_$name >]() {
                    sending_consistent_with_receiving::<$type>();
                }

                #[test]
                fn [<sending_consistent_with_receiving_bytes_$name >]() {
                    sending_consistent_with_receiving_bytes::<$type>();
                }

                #[test]
                fn [<proof_of_work_$name>]() {
                    proof_of_work::<$type>();
                }

                #[test]
                fn [<proof_of_work_depends_on_state_$name>]() {
                    proof_of_work_depends_on_state::<$type>();
                }

                #[test]
                fn [<proof_of_work_zero_bits_$name>]() {
                    proof_of_work_zero_bits::<$type>();
                }

                #[test]
                fn [<sending_consistent_with_receiving_random_bytes_$name>]() {
                    sending_consistent_with_receiving_random_bytes::<$type>();
                }

                #[test]
                fn [<fri_flow_simulation_$name>]() {
                    fri_flow_simulation::<$type>();
                }
            )*
        }

    }
}

generate_tests!(
    poseidon3_pow_keccak256_channel: Poseidon3TestTypes<Sha3_256>,
    poseidon3_pow_blake2s_channel: Poseidon3TestTypes<Blake2s256>,
    keccak256_pow_keccak256_channel: Keccak256TestTypes
);
