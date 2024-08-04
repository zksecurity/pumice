use ark_ff::{BigInteger, PrimeField};
use blake2::{Blake2s256, Digest};
use felt::Felt252;
use poseidon::{FieldHasher, Poseidon3};
use sha3::Keccak256;
use std::{fmt::Debug, marker::PhantomData};

pub trait Hasher<F: PrimeField> {
    type Output: Clone + Eq + Default + Debug;

    // compress a list of internal nodes into a single internal node
    fn node(input: &[Self::Output]) -> Self::Output;

    // compress a list of leaves into a single leaf
    fn leaf(input: &[F]) -> Self::Output;
}

pub struct Blake2s256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Blake2s256Hasher<F> {
    type Output = [u8; 32];

    fn leaf(input: &[F]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        input
            .iter()
            .for_each(|f| hasher.update(f.into_bigint().to_bytes_be()));
        hasher.finalize().into()
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        input.iter().for_each(|f| hasher.update(f));
        hasher.finalize().into()
    }
}

pub struct Keccak256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Keccak256Hasher<F> {
    type Output = [u8; 32];

    fn leaf(input: &[F]) -> Self::Output {
        let mut hasher = Keccak256::new();
        input
            .iter()
            .for_each(|f| hasher.update(f.into_bigint().to_bytes_be()));
        hasher.finalize().into()
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let mut hasher = Keccak256::new();
        input.iter().for_each(|f| hasher.update(f));
        hasher.finalize().into()
    }
}

impl Hasher<Felt252> for Poseidon3<Felt252> {
    type Output = Felt252;

    fn leaf(input: &[Felt252]) -> Self::Output {
        Poseidon3::hash(input)
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        assert_eq!(input.len(), 2);
        Poseidon3::pair(input[0], input[1])
    }
}
