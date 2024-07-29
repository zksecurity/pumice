use sha3::digest::{Digest, OutputSizeUser};
use std::vec::Vec;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
};

pub struct ProofOfWorkProver<D: Digest> {
    _hash: std::marker::PhantomData<D>,
}

impl<D: Digest> Default for ProofOfWorkProver<D> {
    fn default() -> Self {
        Self {
            _hash: std::marker::PhantomData,
        }
    }
}

impl<D: Digest> ProofOfWorkProver<D> {
    // TODO : Implement task manager
    pub fn prove(
        &self,
        seed: &[u8],
        work_bits: usize,
        try_thread_count: usize,
        log_chunk_size: u64,
    ) -> Vec<u8> {
        assert!(work_bits > 0, "At least one bits of work requires.");
        assert!(work_bits <= 64, "Too many bits of work requested");

        let init_hash = self.init_hash(seed, work_bits);
        let output_size = <D as OutputSizeUser>::output_size();

        let mut bytes = vec![0u8; output_size + 8];
        bytes[..output_size].copy_from_slice(&init_hash.finalize());

        let work_limit = 1u64 << (64 - work_bits);
        let chunk_size = 1u64 << log_chunk_size;
        let thread_count = if work_bits > log_chunk_size.try_into().unwrap() {
            // TODO : use taskmgr threads count
            try_thread_count
        } else {
            1
        };

        let nonce_bound = thread_count as u64 * chunk_size;
        let next_chunk_to_search = Arc::new(AtomicU64::new(nonce_bound));
        let lowest_nonce_found = Arc::new(AtomicU64::new(u64::MAX));

        let mut handles = vec![];
        for thread_id in 0..thread_count {
            let next_chunk_to_search = Arc::clone(&next_chunk_to_search);
            let lowest_nonce_found = Arc::clone(&lowest_nonce_found);
            let mut thread_bytes: Vec<u8> = bytes.clone();

            handles.push(thread::spawn(move || {
                let mut nonce_start = thread_id as u64 * chunk_size;
                loop {
                    if let Some(nonce) =
                        search_chunk::<D>(nonce_start, chunk_size, &mut thread_bytes, work_limit)
                    {
                        let mut curr_nonce = lowest_nonce_found.load(Ordering::Relaxed);
                        while nonce < curr_nonce {
                            match lowest_nonce_found.compare_exchange(
                                curr_nonce,
                                nonce,
                                Ordering::SeqCst,
                                Ordering::Relaxed,
                            ) {
                                Ok(_) => break,
                                Err(actual) => curr_nonce = actual,
                            }
                        }
                    }
                    nonce_start = next_chunk_to_search.fetch_add(chunk_size, Ordering::SeqCst);
                    if nonce_start >= lowest_nonce_found.load(Ordering::Relaxed)
                        || nonce_start < nonce_bound
                    {
                        break;
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let nonce_as_u64 = lowest_nonce_found.load(Ordering::Relaxed);
        assert!(nonce_as_u64 != u64::MAX, "No nonce was found.");
        nonce_as_u64.to_be_bytes().to_vec()
    }

    fn init_hash(&self, seed: &[u8], work_bits: usize) -> D {
        let mut hasher = D::new();
        hasher.update([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xed]);
        hasher.update(seed);
        hasher.update([work_bits as u8]);
        hasher
    }
}

fn search_chunk<D: Digest>(
    nonce_start: u64,
    chunk_size: u64,
    thread_bytes: &mut [u8],
    work_limit: u64,
) -> Option<u64> {
    let thread_len = thread_bytes.len();
    for nonce in nonce_start..nonce_start + chunk_size {
        thread_bytes[thread_len - 8..].copy_from_slice(&nonce.to_be_bytes());

        let hash = D::new().chain_update(&thread_bytes).finalize();
        let digest_word = u64::from_be_bytes(hash.as_slice()[..8].try_into().unwrap());
        if digest_word < work_limit {
            return Some(nonce);
        }
    }
    None
}

pub struct ProofOfWorkVerifier<D: Digest> {
    _hash: std::marker::PhantomData<D>,
}

impl<D: Digest> Default for ProofOfWorkVerifier<D> {
    fn default() -> Self {
        Self {
            _hash: std::marker::PhantomData,
        }
    }
}

impl<D: Digest> ProofOfWorkVerifier<D> {
    pub const NONCE_BYTES: usize = std::mem::size_of::<u64>();

    pub fn verify(&self, seed: &[u8], work_bits: usize, nonce_bytes: &[u8]) -> bool {
        assert!(work_bits > 0, "At least one bits of work requires.");
        assert!(work_bits <= 64, "Too many bits of work requested");

        let init_hash = self.init_hash(seed, work_bits);
        let output_size = <D as OutputSizeUser>::output_size();

        let mut bytes = vec![0u8; output_size + 8];
        bytes[..output_size].copy_from_slice(&init_hash.finalize());
        bytes[output_size..].copy_from_slice(nonce_bytes);

        let work_limit = 1u64 << (64 - work_bits);

        let hash = D::new().chain_update(&bytes).finalize();
        let digest_word = u64::from_be_bytes(hash.as_slice()[..8].try_into().unwrap());

        digest_word < work_limit
    }

    fn init_hash(&self, seed: &[u8], work_bits: usize) -> D {
        let mut hasher = D::new();
        hasher.update([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xed]);
        hasher.update(seed);
        hasher.update([work_bits as u8]);
        hasher
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use sha3::Keccak256;

    fn get_prng_state() -> Vec<u8> {
        let mut rng = StdRng::from_entropy();
        let mut state = vec![0u8; 32];
        rng.fill(&mut state[..]);
        state
    }

    #[test]
    fn test_completeness() {
        let pow_prover = ProofOfWorkProver::<Keccak256> {
            _hash: std::marker::PhantomData,
        };
        let pow_verifier = ProofOfWorkVerifier::<Keccak256> {
            _hash: std::marker::PhantomData,
        };

        let work_bits = 15;
        let thread_count = 1;
        let log_chunk_size = 20;
        let seed = get_prng_state();
        let witness = pow_prover.prove(&seed, work_bits, thread_count, log_chunk_size);

        assert!(pow_verifier.verify(&seed, work_bits, &witness));
    }

    #[test]
    fn test_soundness() {
        let pow_prover = ProofOfWorkProver::<Keccak256> {
            _hash: std::marker::PhantomData,
        };
        let pow_verifier = ProofOfWorkVerifier::<Keccak256> {
            _hash: std::marker::PhantomData,
        };

        let work_bits = 15;
        let thread_count = 1;
        let log_chunk_size = 20;
        let seed = get_prng_state();
        let witness = pow_prover.prove(&seed, work_bits, thread_count, log_chunk_size);

        assert!(!pow_verifier.verify(&seed, work_bits + 1, &witness));
        assert!(!pow_verifier.verify(&seed, work_bits - 1, &witness));
    }

    #[test]
    fn test_bit_change() {
        let pow_prover = ProofOfWorkProver::<Keccak256> {
            _hash: std::marker::PhantomData,
        };
        let pow_verifier = ProofOfWorkVerifier::<Keccak256> {
            _hash: std::marker::PhantomData,
        };

        let work_bits = 15;
        let thread_count = 1;
        let log_chunk_size = 20;
        let seed = get_prng_state();
        let mut witness = pow_prover.prove(&seed, work_bits, thread_count, log_chunk_size);

        for byte_index in 0..witness.len() {
            for bit_index in 0..8 {
                witness[byte_index] ^= 1 << bit_index;
                assert!(!pow_verifier.verify(&seed, work_bits, &witness));
                witness[byte_index] ^= 1 << bit_index;
            }
        }
    }

    #[test]
    fn test_parallel_completeness() {
        let pow_prover = ProofOfWorkProver::<Keccak256> {
            _hash: std::marker::PhantomData,
        };
        let pow_verifier = ProofOfWorkVerifier::<Keccak256> {
            _hash: std::marker::PhantomData,
        };

        let work_bits = 18;
        let thread_count = 10;
        let log_chunk_size = 15;
        let seed = get_prng_state();
        let witness = pow_prover.prove(&seed, work_bits, thread_count, log_chunk_size);

        assert!(pow_verifier.verify(&seed, work_bits, &witness));
    }
}
