pub mod channel_states;

use ark_ff::Field;
use channel_states::ChannelStates;
use std::convert::{AsMut, AsRef};
use crate::hashutil::TempHashContainer;

#[allow(dead_code)]
trait Channel: AsRef<ChannelStates> + AsMut<ChannelStates> {
    type Field: Field;

    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error>;

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn random_number(&mut self, bound: u64) -> u64;

    fn random_field(&mut self) -> Self::Field;

    /// Only relevant for non-interactive channels. Changes the channel seed to a "safer" seed.
    ///
    /// This function guarantees that randomness fetched from the channel after calling this function
    /// and before sending data from the prover to the channel, is "safe": A malicious
    /// prover will have to perform 2^security_bits operations for each attempt to randomize the fetched
    /// randomness.
    ///
    /// Increases the amount of work a malicious prover needs to perform, in order to fake a proof.
    #[allow(unused_variables)]
    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        Err(anyhow::Error::msg("Not a fs-channel"))
    }

    fn is_query_phase(&self) -> bool {
        AsRef::<ChannelStates>::as_ref(self).is_query_phase
    }

    fn begin_query_phase(&mut self) {
        AsMut::<ChannelStates>::as_mut(self).is_query_phase = true;
    }

    fn increment_byte_count(&mut self, n: usize) {
        AsMut::<ChannelStates>::as_mut(self).byte_count += n;
    }

    fn increment_commitment_count(&mut self) {
        AsMut::<ChannelStates>::as_mut(self).commitment_count += 1;
    }

    fn increment_hash_count(&mut self) {
        AsMut::<ChannelStates>::as_mut(self).hash_count += 1;
    }
}

trait VerifierChannel: Channel {
    fn recv_commit_hash<HashT: TempHashContainer>(&mut self) -> Result<HashT, anyhow::Error> {
        let bytes = self.recv_bytes(HashT::size())?;
        let mut hash = HashT::init_empty();
        hash.update(&bytes);
        self.increment_commitment_count();
        self.increment_hash_count();
        Ok(hash)
    }
}

trait ProverChannel: Channel {
    fn send_felts(&mut self, felts: Vec<Self::Field>) -> Result<(), anyhow::Error>;

    fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), anyhow::Error>;

    fn send_commit_hash<HashT: TempHashContainer>(&mut self, hash: HashT) -> Result<(), anyhow::Error> {
        self.send_bytes(hash.hash())?;
        self.increment_commitment_count();
        self.increment_hash_count();
        Ok(())
    }
}
