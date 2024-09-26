use ark_ff::{BigInteger, PrimeField};
use blake2::{Blake2s256, Digest};
use felt::Felt252;
use num_bigint::BigUint;
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
    fn node(input: &[Self::Output]) -> Self::Output {
        assert_eq!(input.len(), 2);
        assert_eq!(input[0].as_ref().len(), 32);
        assert_eq!(input[1].as_ref().len(), 32);
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(input[0].as_ref());
        combined.extend_from_slice(input[1].as_ref());
        Self::hash_bytes(&combined)
    }

    // compress a list of leaves into a single leaf
    fn leaf(input: &[F]) -> Self::Output {
        let input_bytes: Vec<u8> = input
            .iter()
            .flat_map(|f| f.into_bigint().to_bytes_be())
            .collect();
        Self::hash_bytes(&input_bytes)
    }

    // compress a list of bytes into a single internal node
    fn hash_bytes(data: &[u8]) -> Self::Output;
}

#[derive(Debug)]
pub struct Blake2s256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Blake2s256Hasher<F> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = [u8; 32];

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let mut hasher = Blake2s256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[derive(Debug)]
pub struct Keccak256Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Keccak256Hasher<F> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = [u8; 32];

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[derive(Debug)]
pub struct Poseidon3Hasher<F: PrimeField> {
    _ph: PhantomData<F>,
}

impl<F: PrimeField> Hasher<F> for Poseidon3Hasher<F> {
    const DIGEST_NUM_BYTES: usize = 32;

    type Output = [u8; 32];

    fn leaf(input: &[F]) -> Self::Output {
        let input_felts: Vec<Felt252> = input
            .iter()
            .map(|f| {
                let bytes = f.into_bigint().to_bytes_be();
                Felt252::from_be_bytes_mod_order(&bytes)
            })
            .collect();
        let hash = Poseidon3::hash(&input_felts).into_bigint().to_bytes_be();

        let mut array = [0u8; 32];
        array[..hash.len()].copy_from_slice(&hash);
        array
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        assert_eq!(input.len(), 2);
        let input0_int = BigUint::from_bytes_be(&input[0]);
        let input1_int = BigUint::from_bytes_be(&input[1]);

        let input0 = input0_int.into();
        let input1 = input1_int.into();
        let hash = Poseidon3::pair(input0, input1).into_bigint().to_bytes_be();

        let mut array = [0u8; 32];
        array[..hash.len()].copy_from_slice(&hash);
        array
    }

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let hash = Poseidon3::hash_bytes_to_field(data)
            .into_bigint()
            .to_bytes_be();

        let mut array = [0u8; 32];
        array[..hash.len()].copy_from_slice(&hash);
        array
    }
}

// MaskedHash implementation for Blake2s256Hasher and Keccak256Hasher
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedHash<
    F: PrimeField,
    H: Hasher<F>,
    const NUM_EFFECTIVE_BYTES: usize,
    const IS_MSB: bool,
> {
    _ph: PhantomData<(F, H)>,
}

// Implement Hasher trait for MaskedHash
impl<
        F: PrimeField,
        H: Hasher<F, Output = [u8; 32]>,
        const NUM_EFFECTIVE_BYTES: usize,
        const IS_MSB: bool,
    > Hasher<F> for MaskedHash<F, H, NUM_EFFECTIVE_BYTES, IS_MSB>
{
    const DIGEST_NUM_BYTES: usize = H::DIGEST_NUM_BYTES;

    type Output = [u8; 32];

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let hash = H::hash_bytes(data);
        Self::mask_hash(&hash)
    }
}

impl<F: PrimeField, H: Hasher<F>, const NUM_EFFECTIVE_BYTES: usize, const IS_MSB: bool>
    MaskedHash<F, H, NUM_EFFECTIVE_BYTES, IS_MSB>
{
    fn mask_hash(digest: &[u8]) -> [u8; 32] {
        let mut buffer = [0u8; 32];

        if IS_MSB {
            buffer[..NUM_EFFECTIVE_BYTES].copy_from_slice(&digest[..NUM_EFFECTIVE_BYTES]);
        } else {
            buffer[32 - NUM_EFFECTIVE_BYTES..]
                .copy_from_slice(&digest[digest.len() - NUM_EFFECTIVE_BYTES..]);
        }

        assert_eq!(buffer.len(), H::DIGEST_NUM_BYTES);
        buffer
    }
}

#[cfg(test)]
mod tests {
    use felt::Felt252;

    use super::{Hasher, Keccak256Hasher, MaskedHash};
    use crate::merkle::tests::hex_to_b32;

    fn as_masked(data: Vec<u8>, is_msb: bool, mask_bytes: usize) -> Vec<u8> {
        assert!(data.len() >= mask_bytes);
        let mut output = data.clone();
        let len = data.len();
        let mask_len = len - mask_bytes;

        if is_msb {
            for i in mask_bytes..len {
                output[i] = 0;
            }
        } else {
            for i in 0..mask_len {
                output[i] = 0;
            }
        }

        output
    }

    type MaskedKeccak20True = MaskedHash<Felt252, Keccak256Hasher<Felt252>, 20, true>;

    #[test]
    fn test_masked_hash() {
        let hash = MaskedKeccak20True::hash_bytes(&[]);
        let exp = hex_to_b32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hash.to_vec(), as_masked(exp.to_vec(), true, 20));

        let testing_string = b"testing";
        let expected_hash: [u8; 32] = [
            0x5f, 0x16, 0xf4, 0xc7, 0xf1, 0x49, 0xac, 0x4f, 0x95, 0x10, 0xd9, 0xcf, 0x8c, 0xf3,
            0x84, 0x03, 0x8a, 0xd3, 0x48, 0xb3, 0xbc, 0xdc, 0x01, 0x91, 0x5f, 0x95, 0xde, 0x12,
            0xdf, 0x9d, 0x1b, 0x02,
        ];
        let hash = MaskedKeccak20True::hash_bytes(testing_string);
        assert_eq!(hash.to_vec(), as_masked(expected_hash.to_vec(), true, 20));

        let testing_string = b"testing";
        let h1 = MaskedKeccak20True::hash_bytes(testing_string);
        let mut buf = Vec::with_capacity(2 * MaskedKeccak20True::DIGEST_NUM_BYTES);
        buf.extend_from_slice(&h1);
        buf.extend_from_slice(&h1);
        let hash_buf = MaskedKeccak20True::hash_bytes(&buf);
        let hash_h1_h1 = MaskedKeccak20True::node(&[h1.clone(), h1]);
        assert_eq!(hash_buf, hash_h1_h1);
    }
}
