mod channel_states;
pub mod fs_prover_channel;
pub mod fs_verifier_channel;
pub mod pow;

#[cfg(test)]
mod test;

use ark_ff::PrimeField;

#[allow(dead_code)]
trait Channel {
    type Field: PrimeField;

    fn draw_number(&mut self, bound: u64) -> u64;

    fn draw_felem(&mut self) -> Self::Field;
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

    fn recv_commit_hash_default(&mut self) -> Result<Vec<u8>, anyhow::Error>;

    fn recv_commit_hash(&mut self, size: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn recv_decommit_node_default(&mut self) -> Result<Vec<u8>, anyhow::Error>;

    fn recv_decommit_node(&mut self, size: usize) -> Result<Vec<u8>, anyhow::Error>;
}

#[allow(dead_code)]
trait ProverChannel: Channel {
    fn send_felts(&mut self, felts: &[Self::Field]) -> Result<(), anyhow::Error>;

    fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error>;

    fn send_data(&mut self, data: &[u8]) -> Result<(), anyhow::Error>;

    fn send_commit_hash<T: AsRef<[u8]>>(&mut self, commitment: T) -> Result<(), anyhow::Error>;

    fn send_decommit_node<T: AsRef<[u8]>>(&mut self, decommitment: T) -> Result<(), anyhow::Error>;

    fn get_proof(&self) -> Vec<u8>;
}
