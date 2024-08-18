use ark_ff::{BigInteger, PrimeField};
use blake2::{Blake2s256, Digest};
use felt::Felt252;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use poseidon::{FieldHasher, Poseidon3};
use sha3::Keccak256;
use std::{fmt::Debug, marker::PhantomData};

// Define the Hasher trait
pub trait Hasher<F: PrimeField> {
    // length of digest in bytes
    const DIGEST_NUM_BYTES: usize;

    // digest output
    type Output: Clone + Eq + Default + Debug;

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

    type Output = GenericArray<u8, U32>;

    fn leaf(input: &[F]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        input
            .iter()
            .for_each(|f| hasher.update(f.into_bigint().to_bytes_be()));
        hasher.finalize()
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        input.iter().for_each(|f| hasher.update(f));
        hasher.finalize()
    }

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        hasher.update(data);
        hasher.finalize()
    }
}

pub struct Keccak256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Keccak256Hasher<F> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = GenericArray<u8, U32>;

    fn leaf(input: &[F]) -> Self::Output {
        let mut hasher = Keccak256::new();
        input
            .iter()
            .for_each(|f| hasher.update(f.into_bigint().to_bytes_be()));
        hasher.finalize()
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let mut hasher = Keccak256::new();
        input.iter().for_each(|f| hasher.update(f));
        hasher.finalize()
    }

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Hasher<Felt252> for Poseidon3<Felt252> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = GenericArray<u8, U32>;

    fn leaf(input: &[Felt252]) -> Self::Output {
        vec_to_generic_array(Poseidon3::hash(input).into_bigint().to_bytes_be())
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        assert_eq!(input.len(), 2);
        let input0 = Felt252::from_be_bytes_mod_order(&input[0]);
        let input1 = Felt252::from_be_bytes_mod_order(&input[1]);
        vec_to_generic_array(Poseidon3::pair(input0, input1).into_bigint().to_bytes_be())
    }

    fn hash_bytes(_data: &[u8]) -> Self::Output {
        unimplemented!()
    }
}

pub fn vec_to_generic_array(vec: Vec<u8>) -> GenericArray<u8, U32> {
    assert_eq!(vec.len(), 32);
    let mut array = GenericArray::<u8, U32>::default();
    array.clone_from_slice(&vec);
    array
}
