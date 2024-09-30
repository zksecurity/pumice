use sha3::{Digest, Keccak256};

macro_rules! keccak256 {
    ( $($input:expr),* ) => {{
        let mut hsh = Keccak256::new();
        $(
            hsh.update($input);
        )*
        let out: [u8; KECCAK256_DIGEST_NUM_BYTES] = hsh.finalize().into();
        out
    }};
}

const KECCAK256_DIGEST_NUM_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct HashChain {
    digest: [u8; KECCAK256_DIGEST_NUM_BYTES],
    spare_bytes: [u8; KECCAK256_DIGEST_NUM_BYTES * 2],
    num_spare_bytes: usize,
    counter: u64,
}

impl Default for HashChain {
    fn default() -> Self {
        Self {
            digest: [0u8; KECCAK256_DIGEST_NUM_BYTES],
            spare_bytes: [0u8; KECCAK256_DIGEST_NUM_BYTES * 2],
            num_spare_bytes: 0,
            counter: 0,
        }
    }
}

impl HashChain {
    pub fn new_with_public_input(public_input: &[u8]) -> Self {
        Self {
            digest: keccak256!(public_input),
            ..Default::default()
        }
    }

    // pub fn reseed(&mut self, public_input: &[u8]) {
    //     let result = keccak256!(public_input);
    //     let mut hash_bytes = [0u8; KECCAK256_DIGEST_NUM_BYTES];
    //     hash_bytes.copy_from_slice(&result);
    //     self.digest = hash_bytes;
    //     self.num_spare_bytes = 0;
    //     self.counter = 0;
    // }

    pub fn random_bytes(&mut self, random_bytes_out: &mut [u8]) {
        for chunk in random_bytes_out.chunks_mut(KECCAK256_DIGEST_NUM_BYTES) {
            if chunk.len() <= self.num_spare_bytes {
                // if there are enough spare bytes, use them
                chunk.copy_from_slice(&self.spare_bytes[..chunk.len()]);
                self.num_spare_bytes -= chunk.len();
                self.spare_bytes.copy_within(chunk.len().., 0);
            } else {
                // otherwise, generate new random bytes
                self.fill_random_bytes(chunk);
            }
        }
    }

    fn fill_random_bytes(&mut self, out: &mut [u8]) {
        let num_bytes: usize = out.len();
        assert!(
            num_bytes <= KECCAK256_DIGEST_NUM_BYTES,
            "Asked to get more bytes than one digest size"
        );

        let prandom_bytes = self.next_hash();
        out.copy_from_slice(&prandom_bytes[..num_bytes]);

        // if any bytes remain, put them into spare bytes
        let remain_bytes = KECCAK256_DIGEST_NUM_BYTES - num_bytes;
        if remain_bytes > 0 {
            assert!(
                self.num_spare_bytes + remain_bytes <= KECCAK256_DIGEST_NUM_BYTES,
                "Not enough room in spare bytes buffer. Have {} bytes and want to add {} bytes",
                self.num_spare_bytes,
                remain_bytes
            );

            self.spare_bytes[self.num_spare_bytes..self.num_spare_bytes + (remain_bytes)]
                .copy_from_slice(&prandom_bytes[num_bytes..]);
            self.num_spare_bytes += remain_bytes;
        }
    }

    fn next_hash(&mut self) -> [u8; KECCAK256_DIGEST_NUM_BYTES] {
        // TODO: below code is not efficient, but it works for now
        let mut bytes_with_counter = [0u8; KECCAK256_DIGEST_NUM_BYTES * 2];
        bytes_with_counter[..KECCAK256_DIGEST_NUM_BYTES].copy_from_slice(&self.digest);

        // Copy the counter's serialized 64bit onto the MSB end of the buffer (stone-prover PR #875 decision).
        // Serialized counter is in big-endian format.
        bytes_with_counter[KECCAK256_DIGEST_NUM_BYTES * 2 - 8..]
            .copy_from_slice(&self.counter.to_be_bytes());

        let result = keccak256!(&bytes_with_counter);

        // increment counter
        self.counter += 1;
        let mut hash_bytes = [0u8; KECCAK256_DIGEST_NUM_BYTES];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    #[allow(dead_code)]
    pub fn update_hash_chain(&mut self, raw_bytes: &[u8]) {
        let seed_increment: u64 = 0;
        self.mix_seed_with_bytes(raw_bytes, seed_increment);
    }

    pub fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8], seed_increment: u64) {
        let mut big_int = [0u8; 32];
        big_int.copy_from_slice(&self.digest);

        let seed_increment_bytes = seed_increment.to_be_bytes();
        let mut carry = 0u8;

        for (i, byte) in seed_increment_bytes.iter().rev().enumerate() {
            let idx = 31 - i;
            let (sum, carry1) = big_int[idx].overflowing_add(*byte);
            let (sum, carry2) = sum.overflowing_add(carry);
            big_int[idx] = sum;
            carry = (carry1 | carry2) as u8;
        }

        // Hash the mixed_bytes to update the digest
        let result = keccak256!(&big_int, &raw_bytes);
        self.digest.copy_from_slice(&result);

        self.num_spare_bytes = 0;
        self.counter = 0;
    }

    pub fn get_hash_chain_state(&self) -> &[u8; KECCAK256_DIGEST_NUM_BYTES] {
        &self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM_BYTES_1ST_KECCAK256_TEST: [u8; 8] =
        [0x07, 0x7C, 0xE2, 0x30, 0x83, 0x44, 0x67, 0xE7];
    const RANDOM_BYTES_1000TH_KECCAK256_TEST: [u8; 8] =
        [0xD1, 0x74, 0x78, 0xD2, 0x31, 0xC2, 0xAF, 0x63];
    const RANDOM_BYTES_1001ST_KECCAK256_TEST: [u8; 8] =
        [0xA0, 0xDA, 0xBD, 0x71, 0xEE, 0xAB, 0x82, 0xAC];

    lazy_static::lazy_static! {
        static ref EXPECTED_RANDOM_BYTES_KECCAK256_TEST: std::collections::HashMap<usize, Vec<u8>> = {
            let mut m = std::collections::HashMap::new();
            m.insert(1, RANDOM_BYTES_1ST_KECCAK256_TEST.to_vec());
            m.insert(1000, RANDOM_BYTES_1000TH_KECCAK256_TEST.to_vec());
            m.insert(1001, RANDOM_BYTES_1001ST_KECCAK256_TEST.to_vec());
            m
        };
    }

    // TODO : not fully implemented yet
    #[test]
    fn test_hash_chain_get_randoms() {
        let mut bytes_1 = [0u8; 8];
        let mut bytes_2 = [0u8; 8];
        let mut hash_ch_1 = HashChain::new_with_public_input(&bytes_1);
        let mut hash_ch_2 = HashChain::new_with_public_input(&bytes_2);

        let stat1 = hash_ch_1.get_hash_chain_state().clone();
        hash_ch_1.random_bytes(&mut bytes_1);
        hash_ch_2.random_bytes(&mut bytes_2);

        for _ in 0..1000 {
            hash_ch_1.random_bytes(&mut bytes_1);
            hash_ch_2.random_bytes(&mut bytes_2);
        }

        assert_eq!(stat1, *hash_ch_1.get_hash_chain_state());
        assert_eq!(stat1, *hash_ch_2.get_hash_chain_state());
        assert_eq!(bytes_1, bytes_2);
    }

    #[test]
    fn test_py_hash_chain_update_parity() {
        let dead_beef_bytes = [0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let daba_daba_da_bytes = [0x00, 0x00, 0x00, 0xDA, 0xBA, 0xDA, 0xBA, 0xDA];

        let mut bytes_1 = [0u8; 8];
        let mut hash_ch = HashChain::new_with_public_input(&dead_beef_bytes);

        hash_ch.random_bytes(&mut bytes_1);
        assert_eq!(
            EXPECTED_RANDOM_BYTES_KECCAK256_TEST.get(&1).unwrap(),
            &bytes_1.to_vec()
        );

        for _ in 1..1000 {
            hash_ch.random_bytes(&mut bytes_1);
        }
        assert_eq!(
            EXPECTED_RANDOM_BYTES_KECCAK256_TEST.get(&1000).unwrap(),
            &bytes_1.to_vec()
        );

        hash_ch.update_hash_chain(&daba_daba_da_bytes);
        hash_ch.random_bytes(&mut bytes_1);
        assert_eq!(
            EXPECTED_RANDOM_BYTES_KECCAK256_TEST.get(&1001).unwrap(),
            &bytes_1.to_vec()
        );
    }

    #[test]
    fn test_hash_chain_init_update() {
        let hello_world = b"Hello World!";
        let hash_ch_1 = HashChain::new_with_public_input(hello_world);
        let hash_ch_2 = HashChain::default();

        assert_ne!(
            hash_ch_2.get_hash_chain_state(),
            hash_ch_1.get_hash_chain_state()
        );

        let exp_hw_hash = [
            0x3E, 0xA2, 0xF1, 0xD0, 0xAB, 0xF3, 0xFC, 0x66, 0xCF, 0x29, 0xEE, 0xBB, 0x70, 0xCB,
            0xD4, 0xE7, 0xFE, 0x76, 0x2E, 0xF8, 0xA0, 0x9B, 0xCC, 0x06, 0xC8, 0xED, 0xF6, 0x41,
            0x23, 0x0A, 0xFE, 0xC0,
        ];
        assert_eq!(exp_hw_hash, *hash_ch_1.get_hash_chain_state());
    }
}
