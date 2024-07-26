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
        let input_bytes: Vec<u8> = input
            .iter()
            .flat_map(|f| f.into_bigint().to_bytes_be())
            .collect();
        let mut hasher = Blake2s256::new();
        hasher.update(input_bytes);
        hasher.finalize().into()
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let input_bytes: Vec<u8> = input.iter().flat_map(|&array| array).collect::<Vec<u8>>();
        let mut hasher = Blake2s256::new();
        hasher.update(input_bytes);
        hasher.finalize().into()
    }
}

pub struct Keccak256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Keccak256Hasher<F> {
    type Output = [u8; 32];

    fn leaf(input: &[F]) -> Self::Output {
        let input_bytes: Vec<u8> = input
            .iter()
            .flat_map(|f| f.into_bigint().to_bytes_be())
            .collect();
        let mut hasher = Keccak256::new();
        hasher.update(input_bytes);
        hasher.finalize().into()
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let input_bytes: Vec<u8> = input.iter().flat_map(|&array| array).collect::<Vec<u8>>();
        let mut hasher = Keccak256::new();
        hasher.update(input_bytes);
        hasher.finalize().into()
    }
}

impl Hasher<Felt252> for Poseidon3<Felt252> {
    type Output = Felt252;

    fn leaf(input: &[Felt252]) -> Self::Output {
        Poseidon3::hash(input)
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        Poseidon3::hash(input)
    }
}
