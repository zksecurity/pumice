use crate::channel::{Channel, ChannelStates, FSChannel, ProverChannel};
use crate::randomness::prng::Prng;
use ark_ff::Field;
use sha3::digest::{Digest, Output};
use std::marker::PhantomData;

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

    fn send_felts(&mut self, felts: Vec<Self::Field>) -> Result<(), anyhow::Error> {
        // TODO : get the size of the field element in bytes
        // let elem_size_in_bytes = 8;
        // let mut bytes = vec![0u8; elem_size_in_bytes * felts.len()];
        // for (i, f) in felts.iter().enumerate() {
        //     f.to_big_endian(&mut bytes[i * elem_size_in_bytes..(i + 1) * elem_size_in_bytes]);
        // }

        Ok(())
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error> {
        self.proof.extend_from_slice(bytes);

        if !self.states.is_query_phase() {
            self.prng.mix_seed_with_bytes(&bytes);
        }

        Ok(())
    }

    fn send_commit_hash(&mut self, digest: Output<Self::Digest>) -> Result<(), anyhow::Error> {
        self.send_bytes(digest.as_slice())?;
        self.states.increment_commitment_count();
        self.states.increment_hash_count();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::channel::fs_prover_channel::{Channel, FSProverChannel};
    use crate::felt252::Felt252;
    use crate::randomness::prng::{Prng, PrngKeccak256};
    use ark_ff::Zero;
    use sha3::Sha3_256;

    type MyFSProverChannel = FSProverChannel<Felt252, Sha3_256, PrngKeccak256>;

    #[test]
    fn test_draw_number() {
        let prng = PrngKeccak256::new();
        let mut channel = MyFSProverChannel::new(prng);

        let upper_bound = 100;
        let number = channel.draw_number(upper_bound);
        assert!(number < upper_bound);
    }

    #[test]
    fn test_draw_felem() {
        let prng = PrngKeccak256::new();
        let mut channel = MyFSProverChannel::new(prng);

        let felem = channel.draw_felem();
        assert!(!felem.is_zero());
    }

    #[test]
    fn test_draw_felems() {
        let prng = PrngKeccak256::new();
        let mut channel = MyFSProverChannel::new(prng);

        let n = 5;
        let felems = channel.draw_felems(n);
        assert_eq!(felems.len(), n);
        for felem in felems {
            assert!(!felem.is_zero());
        }
    }
}
