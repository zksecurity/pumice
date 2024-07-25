use crate::channel::{Channel, ChannelStates, FSChannel, VerifierChannel};
use crate::randomness::prng::Prng;
use ark_ff::PrimeField;
use sha3::digest::generic_array::GenericArray;
use sha3::digest::{Digest, Output, OutputSizeUser};
use std::marker::PhantomData;

pub struct FSVerifierChannel<F: PrimeField, D: Digest, P: Prng> {
    pub _ph: PhantomData<(F, D)>,
    pub prng: P,
    // TODO : turn this into an iterator
    pub proof: Vec<u8>,
    pub proof_read_index: usize,
    pub states: ChannelStates,
}

impl<F: PrimeField, D: Digest, P: Prng> FSVerifierChannel<F, D, P> {
    pub fn new(prng: P, proof: Vec<u8>) -> Self {
        Self {
            _ph: PhantomData,
            prng,
            proof,
            proof_read_index: 0,
            states: Default::default(),
        }
    }
}

impl<F: PrimeField, D: Digest, P: Prng> Channel for FSVerifierChannel<F, D, P> {
    type Field = F;

    fn draw_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.states.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );

        let raw_bytes = self.draw_bytes(std::mem::size_of::<u64>());
        let number = u64::from_be_bytes(raw_bytes.try_into().unwrap());

        assert!(
            upper_bound < 0x0001_0000_0000_0000,
            "Random number with too high an upper bound"
        );

        number % upper_bound
    }

    #[inline]
    fn draw_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut raw_bytes = vec![0u8; n];
        self.prng.random_bytes(&mut raw_bytes);
        raw_bytes
    }
}

impl<F: PrimeField, D: Digest, P: Prng> FSChannel for FSVerifierChannel<F, D, P> {
    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        if security_bits == 0 {
            return Ok(());
        }

        // TODO : apply proof of work
        //let prev_state = self.prng.clone();

        Ok(())
    }

    fn is_end_of_proof(&self) -> bool {
        self.proof_read_index >= self.proof.len()
    }
}

impl<F: PrimeField, D: Digest, P: Prng> VerifierChannel for FSVerifierChannel<F, D, P> {
    type Digest = D;

    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error> {
        let mut felts = Vec::with_capacity(n);
        let chunk_bytes_size = ((Self::Field::MODULUS_BIT_SIZE + 7) / 8) as usize;
        let raw_bytes: Vec<u8> = self.recv_bytes(n * chunk_bytes_size).unwrap();

        for chunk in raw_bytes.chunks_exact(chunk_bytes_size) {
            let felt = Self::Field::from_be_bytes_mod_order(&chunk);
            felts.push(felt);
        }

        Ok(felts)
    }

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error> {
        assert!(
            self.proof_read_index + n <= self.proof.len(),
            "Proof too short."
        );

        let raw_bytes = &self.proof[self.proof_read_index..self.proof_read_index + n];
        self.proof_read_index += n;
        if !self.states.is_query_phase() {
            self.prng.mix_seed_with_bytes(&raw_bytes);
        }
        self.states.increment_byte_count(raw_bytes.len());
        Ok(raw_bytes.to_vec())
    }

    fn recv_commit_hash(&mut self) -> Result<Output<Self::Digest>, anyhow::Error> {
        let size = <Self::Digest as OutputSizeUser>::output_size();
        let bytes = self.recv_bytes(size).unwrap();

        let commitment = GenericArray::clone_from_slice(&bytes.as_slice());

        self.states.increment_commitment_count();
        self.states.increment_hash_count();
        Ok(commitment)
    }
}
