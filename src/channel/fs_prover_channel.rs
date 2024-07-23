use crate::channel::{Channel, ChannelStates, ProverChannel};
use crate::randomness::prng::Prng;
use ark_ff::Field;
use sha3::Digest;
use std::marker::PhantomData;

use super::FSChannel;

pub struct FSProverChannel<F: Field, D: Digest, P: Prng> {
    pub _ph: PhantomData<(F, D)>,
    pub prng: P,
    pub proof: Vec<u8>,
    pub states: ChannelStates,
}

impl<F: Field, D: Digest, P: Prng> FSProverChannel<F, D, P> {
    pub fn new(prng: P) -> Self {
        Self {
            _ph: PhantomData,
            prng,
            proof: vec![],
            states: Default::default(),
        }
    }
}

impl<F: Field, D: Digest, P: Prng> Channel for FSProverChannel<F, D, P> {
    type Field = F;

    // draw a number from the PRNG [0, upper_bound)
    fn draw_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.states.is_query_phase(),
            "Prover can't receive randomness after query phase has begun."
        );

        let raw_bytes = self.draw_bytes();
        let number = u64::from_le_bytes(raw_bytes);

        assert!(
            upper_bound < 0x0001_0000_0000_0000,
            "Random number with too high an upper bound"
        );

        number % upper_bound
    }

    fn draw_felem(&mut self) -> Self::Field {
        assert!(
            !self.states.is_query_phase(),
            "Prover can't receive randomness after query phase has begun."
        );

        let mut raw_bytes = self.draw_bytes();
        let field_element = F::from_random_bytes(&mut raw_bytes).unwrap();

        field_element
    }

    fn draw_felems(&mut self, n: usize) -> Vec<Self::Field> {
        let mut field_elements = Vec::with_capacity(n);

        for _ in 0..n {
            field_elements.push(self.draw_felem());
        }

        field_elements
    }

    #[inline]
    fn draw_bytes(&mut self) -> [u8; std::mem::size_of::<u64>()] {
        let mut raw_bytes = [0u8; std::mem::size_of::<u64>()];
        self.prng.random_bytes(&mut raw_bytes);
        raw_bytes
    }
}

impl<F: Field, D: Digest, P: Prng> FSChannel for FSProverChannel<F, D, P> {
    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        Ok(())
    }

    fn is_end_of_proof(&self) -> bool {
        true
    }
}

impl<F: Field, D: Digest, P: Prng> ProverChannel for FSProverChannel<F, D, P> {
    type Digest = D;

    // TODO :
    fn send_felts(&mut self, felts: Vec<Self::Field>) -> Result<(), anyhow::Error> {
        // for f in &felts {
        //     self.proof.push();
        // }

        self.states.increment_field_element_count(felts.len());
        Ok(())
    }

    fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), anyhow::Error> {
        for b in &bytes {
            self.proof.push(*b);
        }

        if !self.states.is_query_phase() {
            let mut temp_bytes: Vec<u8> = bytes.clone();
            self.prng.mix_seed_with_bytes(&mut temp_bytes);
        }

        Ok(())
    }

    fn send_commit_hash(&mut self, hash: Self::Digest) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
