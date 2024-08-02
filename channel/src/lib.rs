mod channel_states;
pub mod fs_prover_channel;
// pub mod fs_prover_felt_channel;
pub mod fs_verifier_channel;
pub mod pow;

#[cfg(test)]
mod test_keccak_channel;
// #[cfg(test)]
// mod test_poseidon3_channel;

use ark_ff::PrimeField;

#[allow(dead_code)]
trait Channel {
    type Field: PrimeField;
    type Commitment;

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

    fn recv_commit_hash(&mut self) -> Result<Self::Commitment, anyhow::Error>;

    fn recv_decommit_node(&mut self) -> Result<Self::Commitment, anyhow::Error>;
}

#[allow(dead_code)]
trait ProverChannel: Channel {
    fn send_felts(&mut self, felts: &[Self::Field]) -> Result<(), anyhow::Error>;

    fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error>;

    fn send_data(&mut self, data: &[u8]) -> Result<(), anyhow::Error>;

    fn send_commit_hash(&mut self, commmitment: Self::Commitment) -> Result<(), anyhow::Error>;

    fn send_decommit_node(&mut self, decommitment: Self::Commitment) -> Result<(), anyhow::Error>;

    fn get_proof(&self) -> Vec<u8>;
}
