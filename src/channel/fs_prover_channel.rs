use crate::channel::{Channel, ChannelStates, ProverChannel};
use crate::hashutil::TempHashContainer;
use ark_ff::Field;
use std::marker::PhantomData;

use rand_chacha::rand_core::RngCore;
use rand_chacha::ChaCha20Rng;

pub struct FSProverChannel<F: Field, H: TempHashContainer> {
    pub _ph: PhantomData<(F, H)>,
    pub prng: ChaCha20Rng,
    pub proof: Vec<u8>,
    pub states: ChannelStates,
}

impl<F: Field, H: TempHashContainer> FSProverChannel<F, H> {
    pub fn new(prng: ChaCha20Rng) -> Self {
        Self {
            _ph: PhantomData,
            prng,
            proof: vec![],
            states: Default::default(),
        }
    }
}

impl<F: Field, H: TempHashContainer> AsMut<ChannelStates> for FSProverChannel<F, H> {
    fn as_mut(&mut self) -> &mut ChannelStates {
        &mut self.states
    }
}

impl<F: Field, H: TempHashContainer> AsRef<ChannelStates> for FSProverChannel<F, H> {
    fn as_ref(&self) -> &ChannelStates {
        &self.states
    }
}


impl<F: Field, H: TempHashContainer> Channel for FSProverChannel<F, H> {
    type Field = F;

    fn recv_felem(&mut self, felem: Self::Field) -> Result<Self::Field, anyhow::Error> {
        // TODO
        Ok(felem)
    }

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error> {
        assert!(
            !self.is_query_phase(),
            "Prover can't receive randomness after query phase has begun."
        );

        let mut bytes = vec![0u8; n];
        self.prng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    // receive random number from verifier
    fn random_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.is_query_phase(),
            "Prover can't receive randomness after query phase has begun."
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
            "Prover can't receive randomness after query phase has begun."
        );

        let mut raw_bytes = [0u8; std::mem::size_of::<u64>()];
        self.prng.fill_bytes(&mut raw_bytes);
        let field_element = F::from_random_bytes(&raw_bytes).unwrap();

        field_element
    }

    // TODO : refactor
    fn is_end_of_proof(&self) -> bool {
        true
    }
}

impl<H: TempHashContainer, F: Field> ProverChannel for FSProverChannel<F, H> {
    type HashT = H;

    // TODO : 
    fn send_felts(&mut self, felts: Vec<Self::Field>) -> Result<(), anyhow::Error> {
        // for f in &felts {
        //     self.proof.push();
        // }

        self.increment_field_element_count(felts.len());
        Ok(())
    }

    fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), anyhow::Error> {
        for b in &bytes {
            self.proof.push(*b);
        }

        if !self.is_query_phase() {
            let mut temp_bytes = bytes.clone();
            self.prng.fill_bytes(&mut temp_bytes);
        }

        Ok(())
    }
}
