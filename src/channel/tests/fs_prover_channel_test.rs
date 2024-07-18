use crate::channel::fs_prover_channel::FSProverChannel;
use crate::channel::ProverChannel;
use crate::felt252::Felt252;
use crate::hashutil::TempHashContainer;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

struct DummyHashContainer;

impl TempHashContainer for DummyHashContainer {
    fn init_empty() -> Self {
        DummyHashContainer
    }

    fn init_digest(_data: &Vec<u8>) -> Self {
        DummyHashContainer
    }

    fn update(&mut self, _data: &Vec<u8>) {}

    fn hash(&self) -> Vec<u8> {
        vec![]
    }

    fn size() -> usize {
        0
    }
}

#[test]
fn test_send_bytes() {
    let seed = [0u8; 32];
    let prng = ChaCha20Rng::from_seed(seed);
    let mut channel = FSProverChannel::<Felt252, DummyHashContainer>::new(prng);

    let bytes = vec![1, 2, 3, 4];
    let result = channel.send_bytes(bytes.clone());
    assert!(result.is_ok());
    assert_eq!(channel.proof, bytes);
}
