use crate::Prng;
use ark_ff::BigInteger;
use ark_ff::Field;
use ark_ff::PrimeField;
use felt::Felt252;
use generic_array::typenum::U32;
use poseidon::FieldHasher;
use poseidon::Poseidon3;
use std::vec::Vec;

pub use sha3::Sha3_256;

pub struct PrngPoseidon3<Felt252> {
    pub state: Felt252,
    pub counter: Felt252,
}

impl Prng<Felt252> for PrngPoseidon3<Felt252> {
    type CommitmentSize = U32;

    fn new() -> Self {
        PrngPoseidon3 {
            state: Felt252::ZERO,
            counter: Felt252::ZERO,
        }
    }

    fn new_with_seed(seed: &[Felt252]) -> Self {
        assert!(seed.len() == 2, "seed must be 2 felts");
        PrngPoseidon3 {
            state: seed[0],
            counter: seed[1],
        }
    }

    fn random_bytes(&mut self, random_bytes_out: &mut [u8]) {
        let bytes = self.random_bytes_vec(random_bytes_out.len());
        random_bytes_out.copy_from_slice(&bytes);
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

    fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8> {
        assert!(
            n_elements == Felt252::MODULUS_BIT_SIZE.div_ceil(8) as usize,
            "n_elements must be the number of bytes in the field size"
        );

        let hash_result = Poseidon3::<Felt252>::pair(self.state, self.counter);
        hash_result.into_bigint().to_bytes_be()
    }
}
