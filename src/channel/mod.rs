pub mod channel_states;
//pub mod fs_verifier_channel;
pub mod fs_prover_channel;

#[cfg(test)]
pub mod tests;

use ark_ff::Field;
use channel_states::ChannelStates;
use sha3::Digest;

#[allow(dead_code)]
trait Channel {
    type Field: Field;

    fn draw_number(&mut self, bound: u64) -> u64;

    fn draw_felem(&mut self) -> Self::Field;

    fn draw_felems(&mut self, n: usize) -> Vec<Self::Field>;

    fn draw_bytes(&mut self) -> [u8; std::mem::size_of::<u64>()];
}

trait FSChannel: Channel {
    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error>;

    fn is_end_of_proof(&self) -> bool;
}

trait VerifierChannel: Channel {
    type Digest: Digest;

    fn recv_felem(&mut self, felem: Self::Field) -> Result<Self::Field, anyhow::Error>;

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn recv_commit_hash(&mut self) -> Result<Self::Digest, anyhow::Error>;
    //  {
    //     let bytes = self.recv_bytes(Self::HashT::size())?;
    //     let mut hash = Self::HashT::init_empty();
    //     hash.update(&bytes);
    //     self.increment_commitment_count();
    //     self.increment_hash_count();
    //     Ok(hash)
    // }
}

trait ProverChannel: Channel {
    type Digest: Digest;

    fn send_felts(&mut self, felts: Vec<Self::Field>) -> Result<(), anyhow::Error>;

    fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), anyhow::Error>;

    fn send_commit_hash(&mut self, hash: Self::Digest) -> Result<(), anyhow::Error>;
    //  {
    //     self.send_bytes(hash.hash())?;
    //     self.increment_commitment_count();
    //     self.increment_hash_count();
    //     Ok(())
    // }
}
