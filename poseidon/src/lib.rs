mod constants;

use constants::{
    RATE,
    ROUNDS_FULL,
    ROUNDS_PARTIAL,
    ROUND_KEYS_COMPRESSED,
    WIDTH, // total width of the state
};

use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use felt::Felt252;
use hex::decode;
use std::marker::PhantomData;

pub trait FieldHasher<F: Field> {
    fn hash(input: &[F]) -> F;

    fn pair(left: F, right: F) -> F;

    fn hash_bytes_to_field(bytes: &[u8]) -> F;
}

pub struct Poseidon3<F: Field> {
    _ph: PhantomData<F>,
}

#[inline]
fn s_box<F: Field>(x: F) -> F {
    x.square() * x
}

impl Poseidon3<Felt252> {
    fn mix(st: &mut [Felt252; WIDTH]) {
        // linear layer: mix state
        // M = (
        //  ( 3, 1, 1),
        //  ( 1,-1, 1),
        //  ( 1, 1, -2)
        // )
        // see:
        // https://github.com/starkware-industries/poseidon/blob/main/poseidon3.txt
        let t0 = st[0] + st[1];
        let t1 = t0 + st[2];
        st[0] = t1 + st[0].double();
        st[1] = t1 - st[1].double();
        st[2] = t0 - st[2].double();
    }

    fn round_partial<'a>(st: &mut [Felt252; WIDTH], key: &mut impl Iterator<Item = &'a Felt252>) {
        // add round constant
        st[2] += key.next().unwrap();

        // apply S-box
        st[2] = s_box(st[2]);

        // linear layer
        Self::mix(st);
    }

    fn round_full<'a>(st: &mut [Felt252; WIDTH], key: &mut impl Iterator<Item = &'a Felt252>) {
        // add full round constant
        st[0] += key.next().unwrap();
        st[1] += key.next().unwrap();
        st[2] += key.next().unwrap();

        // apply S-box
        st[0] = s_box(st[0]);
        st[1] = s_box(st[1]);
        st[2] = s_box(st[2]);

        // linear layer
        Self::mix(st);
    }

    fn perm(mut st: [Felt252; WIDTH]) -> [Felt252; WIDTH] {
        let mut keys = ROUND_KEYS_COMPRESSED.iter();
        debug_assert_eq!(ROUNDS_FULL % 2, 0);
        debug_assert_eq!(
            ROUND_KEYS_COMPRESSED.len(),
            ROUNDS_FULL * 3 + ROUNDS_PARTIAL
        );

        // initial full rounds
        for _ in 0..ROUNDS_FULL / 2 {
            Self::round_full(&mut st, &mut keys);
        }

        // middle partial rounds
        for _ in 0..ROUNDS_PARTIAL {
            Self::round_partial(&mut st, &mut keys);
        }

        // final full rounds
        for _ in 0..ROUNDS_FULL / 2 {
            Self::round_full(&mut st, &mut keys);
        }

        // ensure we consumed all keys
        debug_assert_eq!(keys.next(), None);
        st
    }
}

impl FieldHasher<Felt252> for Poseidon3<Felt252> {
    fn hash(input: &[Felt252]) -> Felt252 {
        // initialize state
        let mut st = [Felt252::ZERO; WIDTH];
        let mut iter = input.chunks_exact(RATE);

        // handle regular chunks
        for chunk in iter.by_ref() {
            st[0] += chunk[0];
            st[1] += chunk[1];
            st = Self::perm(st);
        }

        // handle remainer and padding
        match iter.remainder() {
            [last] => {
                st[0] += *last;
                st[1] += Felt252::ONE;
            }
            [] => {
                st[0] += Felt252::ONE;
            }
            _ => unreachable!(),
        }

        // apply the final permutation
        st = Self::perm(st);
        st[0]
    }

    /// Observe that:
    ///
    /// pair(x, y) != hash([x, y])
    fn pair(left: Felt252, right: Felt252) -> Felt252 {
        const PAD: Felt252 = Felt252::new(BigInt([0x2, 0x0, 0x0, 0x0]));
        let st = Self::perm([left, right, PAD]);
        st[0]
    }

    fn hash_bytes_to_field(bytes: &[u8]) -> Felt252 {
        assert!(bytes.len() % 32 == 0);

        let mut felts = Vec::new();

        for chunk in bytes.chunks(32) {
            felts.push(bytes_to_field(chunk))
        }

        Self::hash(&felts)
    }
}

fn bytes_to_field(bytes: &[u8]) -> Felt252 {
    let bits = {
        let mut bits = Vec::new();
        for byte in bytes {
            for i in (0..8).rev() {
                bits.push(byte & (1 << i) != 0);
            }
        }
        bits
    };
    let big_int = <BigInt<4> as BigInteger>::from_bits_be(&bits);
    assert!(big_int < Felt252::MODULUS);
    Felt252::from_bigint(big_int).expect("conversion fail")
}

pub fn hex_to_vec(hex_str: &str) -> Vec<u8> {
    let mut hex_str = String::from(hex_str);
    let padding_length = 64_i32.saturating_sub(hex_str.len() as i32);
    if padding_length > 0 {
        let padding = "0".repeat(padding_length as usize);
        hex_str.insert_str(0, &padding);
    }
    let mut bytes = decode(hex_str).unwrap();

    let padding_length = 32_i32.saturating_sub(bytes.len() as i32);
    if padding_length > 0 {
        let mut padding = vec![0u8; padding_length as usize];
        padding.append(&mut bytes);
        bytes = padding;
    }
    assert_eq!(bytes.len(), 32);

    bytes
}

#[test]
fn test_poseidon3_hash_empty_input() {
    assert_eq!(
        Poseidon3::hash(&[]),
        felt::hex("0x2272be0f580fd156823304800919530eaa97430e972d7213ee13f4fbf7a5dbc")
    );
}

#[test]
fn test_poseidon3_hash_many_single_input() {
    assert_eq!(
        Poseidon3::hash(&[
            //
            felt::hex("0x23a77118133287637ebdcd9e87a1613e443df789558867f5ba91faf7a024204",)
        ]),
        felt::hex("0x7d1f569e0e898982de6515c20132703410abca88ee56100e02df737fc4bf10e")
    );
}

#[test]
fn test_poseidon3_hash_many_two_inputs() {
    assert_eq!(
        Poseidon3::hash(&[
            felt::hex("0x259f432e6f4590b9a164106cf6a659eb4862b21fb97d43588561712e8e5216a"),
            felt::hex("0x5487ce1af19922ad9b8a714e61a441c12e0c8b2bad640fb19488dec4f65d4d9"),
        ]),
        felt::hex("0x70869d36570fc0b364777c9322373fb7e15452d2282ebdb5b4f3212669f2e7")
    );
}

#[test]
fn test_poseidon3_pair() {
    let lhs = felt::hex("0x23a77118133287637ebdcd9e87a1613e443df789558867f5ba91faf7a024204");
    let rhs = felt::hex("0x259f432e6f4590b9a164106cf6a659eb4862b21fb97d43588561712e8e5216a");
    let hsh = felt::hex("0x4be9af45b942b4b0c9f04a15e37b7f34f8109873ef7ef20e9eef8a38a3011e1");
    assert_eq!(Poseidon3::pair(lhs, rhs), hsh);
}

#[test]
fn test_poseidon3_permutation() {
    let input = [
        felt::hex("0x0000000000000000000000000000000000000000000000000000000000000000"),
        felt::hex("0x0000000000000000000000000000000000000000000000000000000000000000"),
        felt::hex("0x0000000000000000000000000000000000000000000000000000000000000000"),
    ];
    let output = [
        felt::hex("0x079e8d1e78258000a28fc9d49e233bc6852357968577b1e386550ed6a9086133"),
        felt::hex("0x03840d003d0f3f96dbb796ff6aa6a63be5b5404b91ccaabca256154cbb6fb984"),
        felt::hex("0x01eb39da3f7d3b04142d0ac83d9da00c9325a61fb2ef326e50b70eaa8a3c7cc7"),
    ];
    assert_eq!(Poseidon3::<Felt252>::perm(input), output);
}
