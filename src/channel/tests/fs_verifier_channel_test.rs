use crate::channel::fs_verifier_channel::FSVerifierChannel;
use crate::channel::{VerifierChannel, Channel};
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
fn test_recv_felem() {
    let seed = [0u8; 32];
    let prng = ChaCha20Rng::from_seed(seed);
    let mut channel = FSVerifierChannel::<Felt252, DummyHashContainer>::new(prng);

    // let felem = Felt252::rand(&mut channel.prng);
    // channel.proof = felem.to_bytes().to_vec();
    // let result = channel.recv_felem().unwrap();
    // assert_eq!(result, felem);
}

#[test]
fn test_recv_bytes() {
    let seed = [0u8; 32];
    let prng = ChaCha20Rng::from_seed(seed);
    let mut channel = FSVerifierChannel::<Felt252, DummyHashContainer>::new(prng);

    let bytes = vec![1, 2, 3, 4];
    channel.proof = bytes.clone();
    let result = channel.recv_bytes(4);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), bytes);
}

#[test]
fn test_random_number() {
    let seed = [0u8; 32];
    let prng = ChaCha20Rng::from_seed(seed);
    let mut channel = FSVerifierChannel::<Felt252, DummyHashContainer>::new(prng);

    let upper_bound = 100;
    let number = channel.random_number(upper_bound);
    assert!(number < upper_bound);
}

#[test]
fn test_random_field() {
    let seed = [0u8; 32];
    let prng = ChaCha20Rng::from_seed(seed);
    let mut channel = FSVerifierChannel::<Felt252, DummyHashContainer>::new(prng);

    let field_element = channel.random_field();
    assert_ne!(field_element, Felt252::from(0));
}

#[test]
fn test_recv_commit_hash() {
    let seed = [0u8; 32];
    let prng = ChaCha20Rng::from_seed(seed);
    let mut channel = FSVerifierChannel::<Felt252, DummyHashContainer>::new(prng);

    let commit_hash = vec![0xde, 0xad, 0xbe, 0xef];
    channel.proof = commit_hash.clone();
    let result = channel.recv_commit_hash();
    assert!(result.is_ok());
    //assert_eq!(result.unwrap(), commit_hash);
    // TODO : implement
}