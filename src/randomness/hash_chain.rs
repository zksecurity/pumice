use std::ops::Add;

use ethnum::U256;
use sha3::{Digest, Keccak256};

const KECCAK256_DIGEST_NUM_BYTES: usize = 32;

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
    pub fn new_with_digest(digest: &[u8; KECCAK256_DIGEST_NUM_BYTES]) -> Self {
        Self {
            digest: *digest,
            spare_bytes: [0u8; KECCAK256_DIGEST_NUM_BYTES * 2],
            num_spare_bytes: 0,
            counter: 0,
        }
    }

    pub fn new_with_public_input(public_input: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(public_input);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; KECCAK256_DIGEST_NUM_BYTES];
        hash_bytes.copy_from_slice(&result);
        Self {
            digest: hash_bytes,
            spare_bytes: [0u8; KECCAK256_DIGEST_NUM_BYTES * 2],
            num_spare_bytes: 0,
            counter: 0,
        }
    }

    pub fn random_bytes(&mut self, random_bytes_out: &mut [u8]) {
        let num_bytes = random_bytes_out.len();
        let num_full_blocks = num_bytes / KECCAK256_DIGEST_NUM_BYTES;

        for offset in
            (0..num_full_blocks * KECCAK256_DIGEST_NUM_BYTES).step_by(KECCAK256_DIGEST_NUM_BYTES)
        {
            self.fill_random_bytes(
                &mut random_bytes_out[offset..offset + KECCAK256_DIGEST_NUM_BYTES],
            );
        }

        // If there are any bytes left, copy them from the spare bytes, otherwise get more random bytes
        let num_tail_bytes = num_bytes % KECCAK256_DIGEST_NUM_BYTES;
        if num_tail_bytes <= self.num_spare_bytes {
            random_bytes_out[num_full_blocks * KECCAK256_DIGEST_NUM_BYTES..num_bytes]
                .copy_from_slice(&self.spare_bytes[..num_tail_bytes]);
            self.num_spare_bytes -= num_tail_bytes;

            // Shift the spare bytes to the left to remove the bytes we just copied
            self.spare_bytes.copy_within(num_tail_bytes.., 0);
        } else {
            self.fill_random_bytes(
                &mut random_bytes_out[num_full_blocks * KECCAK256_DIGEST_NUM_BYTES..num_bytes],
            );
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

        assert!(
            self.num_spare_bytes < KECCAK256_DIGEST_NUM_BYTES + num_bytes,
            "Not enough room in spare bytes buffer. Have {} bytes and want to add {} bytes",
            self.num_spare_bytes,
            KECCAK256_DIGEST_NUM_BYTES - num_bytes
        );

        self.spare_bytes
            [self.num_spare_bytes..self.num_spare_bytes + (KECCAK256_DIGEST_NUM_BYTES - num_bytes)]
            .copy_from_slice(&prandom_bytes[num_bytes..]);
        self.num_spare_bytes += KECCAK256_DIGEST_NUM_BYTES - num_bytes;
        self.counter += 1;
    }

    fn next_hash(&self) -> [u8; KECCAK256_DIGEST_NUM_BYTES] {
        // TODO: below code is not efficient, but it works for now
        let mut bytes_with_counter = [0u8; KECCAK256_DIGEST_NUM_BYTES * 2];
        bytes_with_counter[..KECCAK256_DIGEST_NUM_BYTES].copy_from_slice(&self.digest);
        // Copy the counter's serialized 64bit onto the MSB end of the buffer (stone-prover PR #875 decision).
        bytes_with_counter[KECCAK256_DIGEST_NUM_BYTES * 2 - 8..]
            .copy_from_slice(&self.counter.to_le_bytes());

        let mut hasher = Keccak256::new();
        hasher.update(bytes_with_counter);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; KECCAK256_DIGEST_NUM_BYTES];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    pub fn update_hash_chain(&mut self, raw_bytes: &[u8]) {
        let seed_increment: u64 = 0;
        self.mix_seed_with_bytes(raw_bytes, seed_increment);
    }

    pub fn mix_seed_with_bytes(&mut self, raw_bytes: &[u8], seed_increment: u64) {
        let mut mixed_bytes = vec![0u8; KECCAK256_DIGEST_NUM_BYTES + raw_bytes.len()];

        // Deserialize the current digest into a u64 array
        let big_int = U256::from_be_bytes(self.digest).add(U256::from(seed_increment));

        // Serialize the incremented big_int back into the mixed_bytes
        mixed_bytes[..KECCAK256_DIGEST_NUM_BYTES].copy_from_slice(&big_int.to_be_bytes());

        // Copy the raw_bytes into the mixed_bytes
        mixed_bytes[KECCAK256_DIGEST_NUM_BYTES..].copy_from_slice(raw_bytes);

        // Hash the mixed_bytes to update the digest
        let mut hasher = Keccak256::new();
        hasher.update(&mixed_bytes);
        let result = hasher.finalize();
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

        for i in 1..10 {
            hash_ch.random_bytes(&mut bytes_1);
            dbg!(i);
            dbg!(bytes_1);
        }
        // assert_eq!(
        //     EXPECTED_RANDOM_BYTES_KECCAK256_TEST.get(&1000).unwrap(),
        //     &bytes_1.to_vec()
        // );

        // hash_ch.update_hash_chain(&daba_daba_da_bytes);
        // hash_ch.random_bytes(&mut bytes_1);
        // assert_eq!(
        //     EXPECTED_RANDOM_BYTES_KECCAK256_TEST.get(&1001).unwrap(),
        //     &bytes_1.to_vec()
        // );
    }

    #[test]
    fn test_keccak256_hash_chain_init_update() {
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
