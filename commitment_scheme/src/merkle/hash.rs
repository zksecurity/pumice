use ark_ff::{BigInteger, PrimeField};
use blake2::{Blake2s256, Digest};
use felt::Felt252;
use poseidon::{FieldHasher, Poseidon3};
use sha3::Keccak256;
use std::{fmt::Debug, marker::PhantomData};

// Define the Hasher trait
pub trait Hasher<F: PrimeField> {
    // length of digest in bytes
    const DIGEST_NUM_BYTES: usize;

    // digest output
    type Output: Clone + Eq + Default + Debug + AsRef<[u8]>;

    // compress a list of internal nodes into a single internal node
    fn node(input: &[Self::Output]) -> Self::Output;

    // compress a list of leaves into a single leaf
    fn leaf(input: &[F]) -> Self::Output;

    // compress a list of bytes into a single internal node
    fn hash_bytes(data: &[u8]) -> Self::Output;
}

pub struct Blake2s256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Blake2s256Hasher<F> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = Vec<u8>;

    fn leaf(input: &[F]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        input
            .iter()
            .for_each(|f| hasher.update(f.into_bigint().to_bytes_be()));
        let hash = hasher.finalize().to_vec();
        assert_eq!(hash.len(), Self::DIGEST_NUM_BYTES);
        hash
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        input.iter().for_each(|f| {
            assert_eq!(f.len(), Self::DIGEST_NUM_BYTES);
            hasher.update(f)
        });
        let hash = hasher.finalize().to_vec();
        assert_eq!(hash.len(), Self::DIGEST_NUM_BYTES);
        hash
    }

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        assert_eq!(hash.len(), Self::DIGEST_NUM_BYTES);
        hash
    }
}

pub struct Keccak256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Keccak256Hasher<F> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = Vec<u8>;

    fn leaf(input: &[F]) -> Self::Output {
        let mut hasher = Keccak256::new();
        input
            .iter()
            .for_each(|f| hasher.update(f.into_bigint().to_bytes_be()));
        let hash = hasher.finalize().to_vec();
        assert_eq!(hash.len(), Self::DIGEST_NUM_BYTES);
        hash
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let mut hasher = Keccak256::new();
        input.iter().for_each(|f| {
            assert_eq!(f.len(), Self::DIGEST_NUM_BYTES);
            hasher.update(f)
        });
        let hash = hasher.finalize().to_vec();
        assert_eq!(hash.len(), Self::DIGEST_NUM_BYTES);
        hash
    }

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        assert_eq!(hash.len(), Self::DIGEST_NUM_BYTES);
        hash
    }
}

impl Hasher<Felt252> for Poseidon3<Felt252> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = Vec<u8>;

    fn leaf(input: &[Felt252]) -> Self::Output {
        let hash = Poseidon3::hash(input).into_bigint().to_bytes_be();

        let mut array = [0u8; 32];
        array[..hash.len()].copy_from_slice(&hash);
        array.to_vec()
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        assert_eq!(input.len(), 2);
        let input0 = Felt252::from_be_bytes_mod_order(&input[0]);
        let input1 = Felt252::from_be_bytes_mod_order(&input[1]);
        let hash = Poseidon3::pair(input0, input1).into_bigint().to_bytes_be();

        let mut array = [0u8; 32];
        array[..hash.len()].copy_from_slice(&hash);
        array.to_vec()
    }

    fn hash_bytes(_data: &[u8]) -> Self::Output {
        unimplemented!()
    }
}
