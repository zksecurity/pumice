mod hash_chain;
pub mod keccak256;
pub mod poseidon3;

use ark_ff::BigInteger;
use ark_ff::PrimeField;
use sha3::Digest;
use std::collections::HashSet;
use std::vec::Vec;

pub trait Prng<T = u8> {
    type DigestType: Digest;

    fn new() -> Self;
    fn new_with_seed(seed: &[T]) -> Self;

    fn random_bytes(&mut self, random_bytes_out: &mut [u8]);
    fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8]);
    fn prng_state(&self) -> Vec<u8>;
    fn hash_name() -> &'static str;
    fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8>;
}

pub trait PrngOnlyForTest: Prng {
    fn uniform_int(&mut self, range: std::ops::RangeInclusive<u64>) -> u64 {
        let (min, max) = (*range.start(), *range.end());
        assert!(min <= max, "Invalid interval");
        let mut buf = [0u8; 8];
        self.random_bytes(&mut buf);
        let random_value = u64::from_le_bytes(buf);

        if min == 0 && max == u64::MAX {
            random_value
        } else {
            min + (random_value % (max - min + 1))
        }
    }

    fn uniform_int_vec(
        &mut self,
        range: std::ops::RangeInclusive<u64>,
        n_elements: usize,
    ) -> Vec<u64> {
        assert!(range.start() <= range.end(), "Invalid interval");
        let mut return_vec = Vec::with_capacity(n_elements);
        for _ in 0..n_elements {
            return_vec.push(self.uniform_int(range.clone()));
        }
        return_vec
    }

    fn uniform_distinct_int_vec(
        &mut self,
        range: std::ops::RangeInclusive<u64>,
        n_elements: usize,
    ) -> Vec<u64> {
        assert!(range.start() <= range.end(), "Invalid interval");
        let n_elements_max = if range.is_empty() {
            0
        } else {
            ((range.end() - range.start()) / 2) as usize
        };

        assert!(
            n_elements <= n_elements_max,
            "Number of elements must be less than or equal to half the number of elements in the interval"
        );
        let mut return_vec = Vec::with_capacity(n_elements);
        let mut current_set = HashSet::new();
        while current_set.len() < n_elements {
            let value = self.uniform_int(range.clone());
            if current_set.insert(value) {
                return_vec.push(value);
            }
        }
        return_vec
    }

    // XXX : dumb implementation. should reduce calls to uniform_int_vec
    fn uniform_bool_vec(&mut self, n_elements: usize) -> Vec<bool> {
        let bits = self.uniform_int_vec(0..=1, n_elements);
        bits.into_iter().map(|bit| bit != 0).collect()
    }

    fn uniform_bigint<B: BigInteger>(&mut self, min: B, max: B) -> B;
    fn random_felem<F: PrimeField>(&mut self) -> F;
    fn random_felts_vec<F: PrimeField>(&mut self, n_elements: usize) -> Vec<F>;
    fn seed_from_system_time() -> [u8; 8];
}
