use crate::channel::Channel;
use crate::channel::ChannelStates;
use crate::hashutil::TempHashContainer;
use ark_ff::Field;

use rand_chacha::rand_core::RngCore;
use rand_chacha::ChaCha20Rng;

use super::VerifierChannel;

pub struct FSVerifierChannel<F: Field> {
    prng: ChaCha20Rng,
    proof: Vec<u8>,
    proof_read_index: usize,
    states: ChannelStates,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> AsMut<ChannelStates> for FSVerifierChannel<F> {
    fn as_mut(&mut self) -> &mut ChannelStates {
        &mut self.states
    }
}

impl<F: Field> AsRef<ChannelStates> for FSVerifierChannel<F> {
    fn as_ref(&self) -> &ChannelStates {
        &self.states
    }
}

impl<F: Field> Channel for FSVerifierChannel<F> {
    type Field = F;

    fn recv_felem(&mut self, felem: Self::Field) -> Result<Self::Field, anyhow::Error> {
        Ok(felem)
    }

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error> {
        assert!(
            self.proof_read_index + n <= self.proof.len(),
            "Proof too short."
        );
        let raw_bytes = self.proof[self.proof_read_index..self.proof_read_index + n].to_vec();
        self.proof_read_index += n;
        if !self.is_query_phase() {
            // TODO : Mix seed with bytes
        }
        self.increment_byte_count(raw_bytes.len());
        Ok(raw_bytes)
    }

    fn random_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );

        // TODO : change bytes size dynamically
        let mut raw_bytes = [0u8; std::mem::size_of::<u64>()];
        self.prng.fill_bytes(&mut raw_bytes);
        let number = u64::from_le_bytes(raw_bytes);

        assert!(
            upper_bound < 0x0001_0000_0000_0000,
            "Random number with too high an upper bound"
        );

        number % upper_bound
    }

    fn random_field(&mut self) -> Self::Field {
        assert!(
            !self.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );

        let mut raw_bytes = [0u8; std::mem::size_of::<u64>()];
        self.prng.fill_bytes(&mut raw_bytes);
        let field_element = F::from_random_bytes(&raw_bytes).unwrap();

        field_element
    }

    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        if security_bits == 0 {
            return Ok(());
        }

        // TODO : apply proof of work
        let prev_state = self.prng.clone();

        Ok(())
    }

    fn is_end_of_proof(&self) -> bool {
        self.proof_read_index >= self.proof.len()
    }
}

// 
impl<H: TempHashContainer, F: Field> VerifierChannel for FSVerifierChannel<F> {
    type HashT = H;

}
