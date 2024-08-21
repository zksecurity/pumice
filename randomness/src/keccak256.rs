use crate::hash_chain::HashChain;
use crate::Prng;
use std::vec::Vec;

pub use sha3::Sha3_256;

const INCREMENT_SEED: u64 = 1;

pub struct PrngKeccak256 {
    hash_chain: HashChain,
}

impl Prng for PrngKeccak256 {
    fn new() -> Self {
        let seed = [0u8; 32];
        PrngKeccak256 {
            hash_chain: HashChain::new_with_public_input(&seed),
        }
    }

    fn new_with_seed(seed: &[u8]) -> Self {
        PrngKeccak256 {
            hash_chain: HashChain::new_with_public_input(seed),
        }
    }

    fn random_bytes(&mut self, random_bytes_out: &mut [u8]) {
        self.hash_chain.random_bytes(random_bytes_out);
    }

    fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8> {
        let mut return_vec = vec![0u8; n_elements];
        self.random_bytes(&mut return_vec);
        return_vec
    }

    fn random_number(&mut self, upper_bound: u64) -> u64 {
        let raw_bytes = self.random_bytes_vec(std::mem::size_of::<u64>());
        let number = u64::from_be_bytes(raw_bytes.try_into().unwrap());

        assert!(
            upper_bound < 0x0001_0000_0000_0000,
            "Random number with too high an upper bound"
        );

        number % upper_bound
    }

    fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8]) {
        self.hash_chain
            .mix_seed_with_bytes(raw_bytes, INCREMENT_SEED);
    }

    fn prng_state(&self) -> Vec<u8> {
        self.hash_chain.get_hash_chain_state().to_vec()
    }

    fn hash_name() -> &'static str {
        "Keccak256"
    }

    fn digest_size() -> usize {
        32
    }

    fn bytes_chunk_size() -> usize {
        1
    }
}
