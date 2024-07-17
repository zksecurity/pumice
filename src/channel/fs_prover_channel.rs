use crate::channel::{Channel, ChannelStates, ProverChannel}; // ProverChannel 추가
use crate::hashutil::TempHashContainer;
use ark_ff::Field;
use std::marker::PhantomData;

use rand_chacha::rand_core::RngCore;
use rand_chacha::ChaCha20Rng;

pub struct FSProverChannel<F: Field, H: TempHashContainer> {
    _ph: PhantomData<(F, H)>,
    prng: ChaCha20Rng,
    proof: Vec<u8>,
    states: ChannelStates,
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

    // TODO : refactor
    fn is_end_of_proof(&self) -> bool {
        true
    }
}

impl<H: TempHashContainer, F: Field> ProverChannel for FSProverChannel<F, H> {
    type HashT = H;

    fn send_felts(&mut self, felts: Vec<Self::Field>) -> Result<(), anyhow::Error> {
        // Implement the logic to send field elements
        Ok(())
    }

    fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), anyhow::Error> {
        // Implement the logic to send bytes
        Ok(())
    }
}
