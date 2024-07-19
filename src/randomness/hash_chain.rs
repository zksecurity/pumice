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
    pub fn new(digest: &[u8; KECCAK256_DIGEST_NUM_BYTES]) -> Self {
        Self {
            digest: *digest,
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
        let mut hasher = Keccak256::new();
        hasher.update(&self.digest);
        hasher.update(&self.counter.to_le_bytes());
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

    const RANDOM_BYTES_1ST_KECCAK256: [u8; 8] = [0x07, 0x7C, 0xE2, 0x30, 0x83, 0x44, 0x67, 0xE7];
    const RANDOM_BYTES_1000TH_KECCAK256: [u8; 8] = [0xD1, 0x74, 0x78, 0xD2, 0x31, 0xC2, 0xAF, 0x63];
    const RANDOM_BYTES_1001ST_KECCAK256: [u8; 8] = [0xA0, 0xDA, 0xBD, 0x71, 0xEE, 0xAB, 0x82, 0xAC];

    lazy_static::lazy_static! {
        static ref RANDOM_BYTES_KECCAK256: std::collections::HashMap<usize, Vec<u8>> = {
            let mut m = std::collections::HashMap::new();
            m.insert(1, RANDOM_BYTES_1ST_KECCAK256.to_vec());
            m.insert(1000, RANDOM_BYTES_1000TH_KECCAK256.to_vec());
            m.insert(1001, RANDOM_BYTES_1001ST_KECCAK256.to_vec());
            m
        };

        static ref EXPECTED_RANDOM_BYTE_VECTORS: std::collections::HashMap<usize, std::collections::HashMap<usize, Vec<u8>>> = {
            let mut m = std::collections::HashMap::new();
            m.insert(1,RANDOM_BYTES_KECCAK256.clone());
            m
        };
    }    
    
    #[test]
    fn test_hash_chain_get_randoms() {
        let mut bytes_1: [u8; 8] = [0u8; 8];
        let mut bytes_2 = [0u8; 8];

        let mut hash_ch_1 = HashChain::new(&[0u8; 32]);
        let mut hash_ch_2 = HashChain::new(&[0u8; 32]);
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

}
