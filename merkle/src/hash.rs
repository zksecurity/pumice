use std::marker::PhantomData;
use ark_ff::{BigInteger, PrimeField};
use blake2::{Blake2s256, Digest};

pub trait Hasher<F: PrimeField> {
    type Output: Clone + Eq;

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
        let input_bytes: Vec<u8> = input.iter().flat_map(|f| f.into_bigint().to_bytes_be()).collect();
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