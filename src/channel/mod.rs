pub mod channel_states;
pub mod fs_prover_channel;
pub mod fs_verifier_channel;

use ark_ff::Field;
use channel_states::ChannelStates;
use sha3::digest::{Digest, Output};

#[allow(dead_code)]
trait Channel {
    type Field: Field;

    fn draw_number(&mut self, bound: u64) -> u64;

    fn draw_felem(&mut self) -> Self::Field;

    fn draw_felems(&mut self, n: usize) -> Vec<Self::Field> {
        let mut felems = Vec::with_capacity(n);
        for _ in 0..n {
            felems.push(self.draw_felem());
        }
        felems
    }

    fn draw_bytes(&mut self) -> [u8; std::mem::size_of::<u64>()];
}

trait FSChannel: Channel {
    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error>;

    fn is_end_of_proof(&self) -> bool;
}

trait VerifierChannel: Channel {
    type Digest: Digest;

    fn recv_felts(&mut self, felts: Vec<Self::Field>) -> Result<Vec<Self::Field>, anyhow::Error>;

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn recv_commit_hash(&mut self) -> Result<Output<Self::Digest>, anyhow::Error>;
}

trait ProverChannel: Channel {
    type Digest: Digest;

    fn send_felts(&mut self, felts: Vec<Self::Field>) -> Result<(), anyhow::Error>;

    fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error>;

    fn send_commit_hash(&mut self, digest: Output<Self::Digest>) -> Result<(), anyhow::Error>;
}
