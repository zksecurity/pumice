use ark_ff::Field;

#[allow(dead_code)]
trait Channel {
    type Field: Field;

    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error>;

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn random_number(&mut self, bound: u64) -> u64;

    fn random_field(&mut self) -> Self::Field;
}
