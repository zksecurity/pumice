mod channel_states;
pub mod fs_prover_channel;
// pub mod fs_prover_felt_channel;
pub mod fs_verifier_channel;
pub mod pow;

#[cfg(test)]
mod tests;

use ark_ff::PrimeField;
use sha3::digest::{Digest, Output};

#[allow(dead_code)]
trait Channel {
    type Field: PrimeField;
    type FieldHash: Digest;

    fn draw_number(&mut self, bound: u64) -> u64;

    fn draw_felem(&mut self) -> Self::Field;

    fn draw_bytes(&mut self, n: usize) -> Vec<u8>;
}

#[allow(dead_code)]
trait FSChannel: Channel {
    type PowHash;

    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error>;
}

#[allow(dead_code)]
trait VerifierChannel: Channel {
    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error>;

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn recv_data(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn recv_commit_hash(&mut self) -> Result<Output<Self::FieldHash>, anyhow::Error>;

    fn recv_decommit_node(&mut self) -> Result<Output<Self::FieldHash>, anyhow::Error>;
}

#[allow(dead_code)]
trait ProverChannel: Channel {
    fn send_felts(&mut self, felts: &[Self::Field]) -> Result<(), anyhow::Error>;

    fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error>;

    fn send_data(&mut self, data: &[u8]) -> Result<(), anyhow::Error>;

    fn send_commit_hash(
        &mut self,
        commmitment: Output<Self::FieldHash>,
    ) -> Result<(), anyhow::Error>;

    fn send_decommit_node(
        &mut self,
        decommitment: Output<Self::FieldHash>,
    ) -> Result<(), anyhow::Error>;

    fn get_proof(&self) -> Vec<u8>;
}
