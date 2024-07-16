use crate::channel::VerifierChannel;

pub struct FSVerifierChannel {
    prng: Unique<SomeRng>,
    proof: Vector<u8>,
    proof_read_index: usize,
    states: ChannelStates,
}

#[derive(Default)]
impl FSVerifierChannel {}

impl VerifierChannel for FSVerifierChannel {
    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error> {
        // TODO : get n felts from prng
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
        raw_bytes
    }

    fn random_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );
        // TODO : get random number with prng
    }

    fn random_field(&mut self, field: &Field) -> FieldElement {
        assert!(
            !self.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );
        // TODO : get field random element with prng
    }

    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        if security_bits == 0 {
            return Ok(());
        }

        // TODO : apply proof of work
    }

    fn is_end_of_proof(&self) -> bool {
        self.proof_read_index >= self.proof.len()
    }
}
