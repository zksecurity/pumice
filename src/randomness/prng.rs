use crate::randomness::hash_chain::HashChain;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;

const INCREMENT_SEED: u64 = 1;

pub trait Prng {
    fn new() -> Self;
    fn new_with_seed(seed: &[u8]) -> Self;

    fn random_bytes(&mut self, random_bytes_out: &mut [u8]);
    fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8]);
    fn prng_state(&self) -> Vec<u8>;
    fn hash_name() -> &'static str;
    fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8>;
}

pub trait PrngOnlyForTest: Prng {
    // TODO : implement numeric generic version e.g u8, u16, i32
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
    fn random_felts_vec<F: PrimeField>(&mut self, n_elements: usize) -> Vec<F>;
    fn seed_from_system_time() -> [u8; 8];
}

pub struct PrngKeccak256 {
    hash_chain: HashChain,
}

// TODO : Implement Rng trait
impl Prng for PrngKeccak256 {
    fn new() -> Self {
        let seed = [0u8; 32];
        PrngKeccak256 {
            hash_chain: HashChain::new_with_public_input(&seed),
        }
    }

    fn new_with_seed(seed: &[u8]) -> Self {
        PrngKeccak256 {
            hash_chain: HashChain::new_with_public_input(&seed),
        }
    }

    fn random_bytes(&mut self, random_bytes_out: &mut [u8]) {
        self.hash_chain.random_bytes(random_bytes_out);
    }

    // template <typename OtherHashT>
    // OtherHashT RandomHash() {
    //   return OtherHashT::InitDigestTo(RandomByteVector(OtherHashT::kDigestNumBytes));
    // }

    // pub fn random_other_hash

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

    fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8> {
        let mut return_vec = vec![0u8; n_elements];
        self.random_bytes(&mut return_vec);
        return_vec
    }
}

impl PrngOnlyForTest for PrngKeccak256 {
    fn uniform_bigint<B: BigInteger>(&mut self, min: B, max: B) -> B {
        assert!(min <= max, "Invalid interval");
        let mut range = max.clone();
        range.sub_with_borrow(&min);
        let mut random_value: B;

        let num_bits = range.num_bits() as usize;

        loop {
            let mut bytes = vec![0u8; B::NUM_LIMBS * std::mem::size_of::<u64>()]; // B::NUM_LIMBS * sizeof(u64)
            self.random_bytes(&mut bytes);

            // Mask unnecessary bits
            let full_bytes = num_bits / std::mem::size_of::<u64>();
            let remaining_bits = num_bits % std::mem::size_of::<u64>();

            if remaining_bits != 0 {
                bytes[full_bytes] &= (1 << remaining_bits) - 1;
            }
            for i in (full_bytes + 1)..bytes.len() {
                bytes[i] = 0;
            }

            // modify bytes to bool array
            let mut bits = Vec::with_capacity(B::NUM_LIMBS * std::mem::size_of::<u64>() * 8);
            for byte in &bytes {
                for bit in 0..8 {
                    bits.push((byte >> bit) & 1 == 1);
                }
            }

            // then make it to BigInteger
            random_value = B::from_bits_le(&bits);
            if random_value <= range {
                break;
            }
        }
        random_value.add_with_carry(&min);
        random_value
    }

    fn random_felts_vec<F: PrimeField>(&mut self, n_elements: usize) -> Vec<F> {
        let mut return_vec: Vec<F> = Vec::with_capacity(n_elements);
        let min = F::BigInt::from(0u64);

        let mut max = F::MODULUS;
        max.sub_with_borrow(&F::BigInt::from(1u64));
        // or we can use F::MODULUS_MINUS_ONE_DIV_TWO * 2

        for _ in 0..n_elements {
            let value = self.uniform_bigint(min, max);
            return_vec.push(F::from_bigint(value).unwrap());
        }
        return_vec
    }

    fn seed_from_system_time() -> [u8; 8] {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let seed = duration.as_nanos() as u64;
        seed.to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::biginteger::BigInt;
    use std::collections::HashSet;

    #[test]
    fn test_two_invocations_are_not_identical() {
        let mut prng = PrngKeccak256::new();
        let a = prng.uniform_int(0..=u64::MAX);
        let b = prng.uniform_int(0..=u64::MAX);
        assert_ne!(a, b);
    }

    #[test]
    fn test_vector_invocation() {
        let mut prng = PrngKeccak256::new();
        let v = prng.uniform_int_vec(0..=u64::MAX, 10);
        let w = prng.uniform_int_vec(0..=u64::MAX, 10);

        assert_eq!(v.len(), 10);
        assert_eq!(w.len(), 10);
        for i in 0..10 {
            assert_ne!(v[i], w[i]);
        }
    }

    #[test]
    fn test_bool_vector() {
        let mut prng = PrngKeccak256::new();
        let size = 1000;
        let v = prng.uniform_bool_vec(size);
        let w = prng.uniform_bool_vec(size);

        assert_eq!(v.len(), size);
        assert_eq!(w.len(), size);
        assert_ne!(v, w);

        let false_count_v = v.iter().filter(|&&x| !x).count();
        let false_count_w = w.iter().filter(|&&x| !x).count();
        assert!((false_count_v as f64 - size as f64 / 2.0).abs() < size as f64 / 10.0);
        assert!((false_count_w as f64 - size as f64 / 2.0).abs() < size as f64 / 10.0);
    }

    #[test]
    fn test_reseeding_with_same_seed_yields_same_randomness() {
        let size = 100;
        let seed = [1, 2, 3, 4, 5];
        let mut prng = PrngKeccak256::new_with_seed(&seed);
        let vals: Vec<u64> = (0..size).map(|_| prng.uniform_int(0..=u64::MAX)).collect();
        let mut prng2 = PrngKeccak256::new_with_seed(&seed);
        for val in vals {
            let new_val = prng2.uniform_int(0..=u64::MAX);
            assert_eq!(val, new_val);
        }
    }

    #[test]
    fn test_uniform_distinct_int_vector_assert() {
        let mut prng = PrngKeccak256::new();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || prng.uniform_distinct_int_vec(0..=10, 6)
        ))
        .is_err());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prng
                .uniform_distinct_int_vec(
                    0..=u16::MAX as u64,
                    (u16::MAX as u64 / 2 + 2) as usize
                )))
            .is_err()
        );
    }

    #[test]
    fn test_uniform_distinct_int_vector_small() {
        let mut prng = PrngKeccak256::new();
        let size_zero_vec = prng.uniform_distinct_int_vec(0..=u64::MAX, 0);
        assert_eq!(size_zero_vec.len(), 0);
        let size_one_vec = prng.uniform_distinct_int_vec(0..=u64::MAX, 1);
        assert_eq!(size_one_vec.len(), 1);
    }

    #[test]
    fn test_uniform_distinct_int_vector_unique() {
        let mut prng = PrngKeccak256::new();
        for _ in 0..50 {
            let mut vec = prng.uniform_distinct_int_vec(0..=30, 10);
            vec.sort();
            let unique_vec: HashSet<_> = vec.iter().cloned().collect();
            assert_eq!(vec.len(), unique_vec.len());
        }
    }

    #[test]
    fn test_uniform_bigint() {
        let mut prng = PrngKeccak256::new();
        type ValueType = BigInt<4>;
        let sqrt_n_tries = 16;
        let n_tries = sqrt_n_tries * sqrt_n_tries;

        let range_a = ValueType::from(0u64);
        let range_b = ValueType::from(u64::MAX);
        let mut mid = range_b.clone();
        mid.div2();

        let mut count = 0;

        assert_eq!(
            prng.uniform_bigint(range_a.clone(), range_a.clone()),
            range_a
        );
        assert_eq!(
            prng.uniform_bigint(range_b.clone(), range_b.clone()),
            range_b
        );

        for _ in 0..n_tries {
            if prng.uniform_bigint(range_a.clone(), range_b.clone()) > mid {
                count += 1;
            }
        }

        assert!((count as f64 - n_tries as f64 / 2.0).abs() < 5.0 * sqrt_n_tries as f64 / 2.0);
    }
}
