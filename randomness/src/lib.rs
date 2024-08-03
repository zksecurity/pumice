mod hash_chain;
pub mod keccak256;
pub mod poseidon3;

use generic_array::ArrayLength;
use std::vec::Vec;

pub trait Prng {
    type DigestSize: ArrayLength;

    fn new() -> Self;
    fn new_with_seed(seed: &[u8]) -> Self;

    fn random_bytes(&mut self, random_bytes_out: &mut [u8]);
    fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8>;
    fn random_number(&mut self, upper_bound: u64) -> u64;
    fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8]);
    fn prng_state(&self) -> Vec<u8>;
    fn hash_name() -> &'static str;

    fn bytes_chunk_size() -> usize;
}
