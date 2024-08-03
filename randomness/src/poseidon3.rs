use crate::Prng;
use ark_ff::{BigInteger, Field, PrimeField};
use felt::Felt252;
use generic_array::typenum::U32;
use poseidon::FieldHasher;
use poseidon::Poseidon3;
use std::vec::Vec;

pub use sha3::Sha3_256;

pub struct PrngPoseidon3 {
    pub state: Felt252,
    pub counter: Felt252,
}

impl Prng for PrngPoseidon3 {
    type CommitmentSize = U32;

    fn new() -> Self {
        PrngPoseidon3 {
            state: Felt252::ZERO,
            counter: Felt252::ZERO,
        }
    }

    fn new_with_seed(seed: &[u8]) -> Self {
        let mut chunks = seed.chunks_exact(Felt252::MODULUS_BIT_SIZE.div_ceil(8) as usize);
        assert!(chunks.len() == 1, "seed must be 1 field element");
        PrngPoseidon3 {
            state: Felt252::from_be_bytes_mod_order(chunks.next().unwrap()),
            counter: Felt252::ZERO,
        }
    }

    fn random_bytes(&mut self, random_bytes_out: &mut [u8]) {
        let bytes = self.random_bytes_vec(random_bytes_out.len());
        random_bytes_out.copy_from_slice(&bytes);
    }

    fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8> {
        assert!(
            n_elements == Felt252::MODULUS_BIT_SIZE.div_ceil(8) as usize,
            "n_elements must be the number of bytes in the field size"
        );

        let hash_result = Poseidon3::<Felt252>::pair(self.state, self.counter);
        self.counter += Felt252::ONE;
        hash_result.into_bigint().to_bytes_be()
    }

    fn random_number(&mut self, upper_bound: u64) -> u64 {
        let raw_bytes = self.random_bytes_vec(Felt252::MODULUS_BIT_SIZE.div_ceil(8) as usize);

        assert!(
            upper_bound < 0x0001_0000_0000_0000,
            "Random number with too high an upper bound"
        );

        let number = Felt252::from_be_bytes_mod_order(&raw_bytes);
        let big_int = number.into_bigint();
        // get first u64 element of the big int
        let first_u64: u64 = big_int.as_ref()[0];
        first_u64 % upper_bound
    }

    fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8]) {
        let mut felts = Vec::with_capacity(raw_bytes.len() + 1);

        felts.push(self.state + Felt252::ONE);
        for chunk in raw_bytes.chunks(Felt252::MODULUS_BIT_SIZE.div_ceil(8) as usize) {
            let felt = Felt252::from_be_bytes_mod_order(chunk);
            felts.push(felt);
        }

        self.state = Poseidon3::<Felt252>::hash(&felts);
        self.counter = Felt252::ZERO;
    }

    fn prng_state(&self) -> Vec<u8> {
        // do not append counter to the state
        self.state.into_bigint().to_bytes_be()
    }

    fn hash_name() -> &'static str {
        "Poseidon3"
    }
}
