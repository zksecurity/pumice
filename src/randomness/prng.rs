use std::collections::HashSet;
use std::vec::Vec;
use crate::randomness::hash_chain::HashChain;
use ark_ff::biginteger::BigInt;
use ark_ff::BigInteger;
use ark_ff::PrimeField;

pub struct Prng {
    hash_chain: HashChain,
}

impl Prng {
    pub fn new() -> Self {
        let initial_seed = vec![0u8; 32];
        Prng {
            hash_chain: HashChain::new_with_public_input(&initial_seed),
        }
    }

    pub fn reseed(&mut self, bytes: &[u8]) {
        self.hash_chain.reseed(bytes);
    }

    pub fn random_bytes(&mut self, random_bytes_out: &mut [u8]) {
        self.hash_chain.random_bytes(random_bytes_out);
    }

    // template <typename OtherHashT>
    // OtherHashT RandomHash() {
    //   return OtherHashT::InitDigestTo(RandomByteVector(OtherHashT::kDigestNumBytes));
    // }
  
    // pub fn random_other_hash

    pub fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8]) {
        let seed_increment: u64 = 1;

        self.hash_chain.mix_seed_with_bytes(raw_bytes, seed_increment);
    }

    pub fn prng_state(&self) -> Vec<u8> {
        self.hash_chain.get_hash_chain_state().to_vec()
    }

    pub fn hash_name() -> &'static str {
        "Keccak256"
    }

    pub fn random_bytes_vec(&mut self, n_elements: usize) -> Vec<u8> {
        let mut return_vec = vec![0u8; n_elements];
        self.random_bytes(&mut return_vec);
        return_vec
    }

    // TODO : implement numeric generic version
    pub fn uniform_int(&mut self, min: u64, max: u64) -> u64 {
        assert!(min <= max, "Invalid interval");
        let mut buf = [0u8; 8];
        self.random_bytes(&mut buf);
        let random_value = u64::from_le_bytes(buf);
        min + (random_value % (max - min + 1))
    }

    pub fn uniform_int_vec(&mut self, min: u64, max: u64, n_elements: usize) -> Vec<u64> {
        assert!(min <= max, "Invalid interval");
        let mut return_vec = Vec::with_capacity(n_elements);
        for _ in 0..n_elements {
            return_vec.push(self.uniform_int(min, max));
        }
        return_vec
    }
    
    pub fn uniform_distinct_int_vec(&mut self, min: u64, max: u64, n_elements: usize) -> Vec<u64> {
        assert!(min <= max, "Invalid interval");
        assert!(
            n_elements <= ((max - min + 1) / 2) as usize,
            "Number of elements must be less than or equal to half the number of elements in the interval"
        );
        let mut return_vec = Vec::with_capacity(n_elements);
        let mut current_set = HashSet::new();
        while current_set.len() < n_elements {
            let value = self.uniform_int(min, max);
            if current_set.insert(value) {
                return_vec.push(value);
            }
        }
        return_vec
    }

    // XXX : dumb implementation. should reduce calls to uniform_int_vec
    pub fn uniform_bool_vec(&mut self, n_elements: usize) -> Vec<bool> {
        let bits = self.uniform_int_vec(0, 1, n_elements);
        bits.into_iter().map(|bit| bit != 0).collect()
    }

    pub fn uniform_bigint<B: BigInteger>(&mut self, min: B, max: B) -> B {
        assert!(min <= max, "Invalid interval");
        let mut range = max.clone();
        range.sub_with_borrow(&min);
        let mut random_value: B;

        let num_bits = range.num_bits() as usize;

        loop {
            let mut bytes = vec![0u8; B::NUM_LIMBS * 8]; // B::NUM_LIMBS * sizeof(u64)
            self.random_bytes(&mut bytes);

            // Mask unnecessary bits
            let full_bytes = num_bits / 8;
            let remaining_bits = num_bits % 8;

            if remaining_bits != 0 {
                bytes[full_bytes] &= (1 << remaining_bits) - 1;
            }
            for i in (full_bytes + 1)..bytes.len() {
                bytes[i] = 0;
            }

            // modify bytes to bool array
            let mut bits = Vec::with_capacity(B::NUM_LIMBS * 64);
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

    pub fn random_felts_vec<F: PrimeField>(&mut self, n_elements: usize) -> Vec<F> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::biginteger::BigInt;

    #[test]
    fn test_uniform_bigint() {
        let mut prng = Prng::new();
        let min = BigInt::<4>::from(10u64);
        let max = BigInt::<4>::from(100u64);

        for _ in 0..1000 {
            let result = prng.uniform_bigint(min.clone(), max.clone());
            assert!(result >= min && result <= max, "Result out of bounds");
        }
    }
}
