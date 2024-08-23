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

#[derive(Debug)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedHash<
    F: PrimeField,
    H: Hasher<F>,
    const NUM_EFFECTIVE_BYTES: usize,
    const IS_MSB: bool,
> {
    _ph: PhantomData<(F, H)>,
}

impl<
        F: PrimeField,
        H: Hasher<F, Output = Vec<u8>>,
        const NUM_EFFECTIVE_BYTES: usize,
        const IS_MSB: bool,
    > Hasher<F> for MaskedHash<F, H, NUM_EFFECTIVE_BYTES, IS_MSB>
{
    const DIGEST_NUM_BYTES: usize = H::DIGEST_NUM_BYTES;

    type Output = Vec<u8>;

    fn leaf(input: &[F]) -> Self::Output {
        let hash = H::leaf(input);
        Self::mask_hash(&hash)
    }

    fn node(input: &[Self::Output]) -> Self::Output {
        let mut extended_input = Vec::new();
        for vec in input {
            extended_input.extend(vec);
        }

        let hash = H::hash_bytes(&extended_input);
        Self::mask_hash(&hash)
    }

    fn hash_bytes(data: &[u8]) -> Self::Output {
        let hash = H::hash_bytes(data);
        Self::mask_hash(&hash)
    }
}

impl<F: PrimeField, H: Hasher<F>, const NUM_EFFECTIVE_BYTES: usize, const IS_MSB: bool>
    MaskedHash<F, H, NUM_EFFECTIVE_BYTES, IS_MSB>
{
    fn mask_hash(digest: &[u8]) -> Vec<u8> {
        let digest_bytes = H::DIGEST_NUM_BYTES;
        let mut buffer = vec![0u8; digest_bytes]; // Initialize with zeros of the required size

        if IS_MSB {
            buffer[..NUM_EFFECTIVE_BYTES].copy_from_slice(&digest[..NUM_EFFECTIVE_BYTES]);
        } else {
            buffer[digest_bytes - NUM_EFFECTIVE_BYTES..]
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
    use crate::merkle::tests::hex_to_vec;

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
        let exp = hex_to_vec("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hash, as_masked(exp, true, 20));

        let testing_string = b"testing";
        let expected_hash: [u8; 32] = [
            0x5f, 0x16, 0xf4, 0xc7, 0xf1, 0x49, 0xac, 0x4f, 0x95, 0x10, 0xd9, 0xcf, 0x8c, 0xf3,
            0x84, 0x03, 0x8a, 0xd3, 0x48, 0xb3, 0xbc, 0xdc, 0x01, 0x91, 0x5f, 0x95, 0xde, 0x12,
            0xdf, 0x9d, 0x1b, 0x02,
        ];
        let hash = MaskedKeccak20True::hash_bytes(testing_string);
        assert_eq!(hash, as_masked(expected_hash.to_vec(), true, 20));

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
