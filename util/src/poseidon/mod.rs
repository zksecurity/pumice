use std::{marker::PhantomData, slice::Windows};

use ark_ff::{BigInt, Field};
use consts::{CAPACITY, ROUNDS_FULL, ROUNDS_PARTIAL, ROUND_CONSTANTS, WIDTH};

use felt::Felt252;

mod consts;

trait FieldHasher<F: Field> {
    fn hash(&self, input: &[F]) -> F;

    /// Possibly optimized version of `hash` for pairs.
    fn pair(&self, left: F, right: F) -> F {
        self.hash(&[left, right])
    }
}

struct Poseidon<F: Field> {
    _ph: PhantomData<F>,
}

impl Poseidon<Felt252> {
    fn round(st: &mut [Felt252; WIDTH], constants: &[Felt252; WIDTH], full: bool) {
        // add round constant
        st[0] += constants[0];
        st[1] += constants[1];
        st[2] += constants[2];

        // apply S-box
        #[inline]
        fn cube<F: Field>(x: F) -> F {
            x.square() * x
        }

        st[2] = cube(st[2]);
        if full {
            st[0] = cube(st[0]);
            st[1] = cube(st[1]);
        }

        // mix state
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

        println!("st: {:#?}", st);
    }

    fn perm(mut st: [Felt252; WIDTH]) -> [Felt252; WIDTH] {
        let mut ctx = ROUND_CONSTANTS.iter();
        assert_eq!(ROUNDS_FULL % 2, 0);

        // initial full rounds
        for _ in 0..ROUNDS_FULL / 2 {
            Self::round(&mut st, ctx.next().unwrap(), true);
        }

        // middle partial rounds
        for _ in 0..ROUNDS_PARTIAL {
            Self::round(&mut st, ctx.next().unwrap(), false);
        }

        // final full rounds
        for _ in 0..ROUNDS_FULL / 2 {
            Self::round(&mut st, ctx.next().unwrap(), true);
        }

        st
    }
}

impl FieldHasher<Felt252> for Poseidon<Felt252> {
    fn hash(&self, input: &[Felt252]) -> Felt252 {
        // initialize state
        let mut st = [Felt252::ZERO; WIDTH];
        let mut iter = input.chunks_exact(CAPACITY);

        // handle regular chunks
        while let Some(chunk) = iter.next() {
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
}

#[test]
fn test_hash() {}

#[test]
fn test_permutation() {
    let input = [
        Felt252::new(BigInt([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ])),
        Felt252::new(BigInt([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ])),
        Felt252::new(BigInt([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ])),
    ];

    let output = [
        Felt252::new(BigInt([
            0x86550ed6a9086133,
            0x852357968577b1e3,
            0xa28fc9d49e233bc6,
            0x079e8d1e78258000,
        ])),
        Felt252::new(BigInt([
            0xa256154cbb6fb984,
            0xe5b5404b91ccaabc,
            0xdbb796ff6aa6a63b,
            0x03840d003d0f3f96,
        ])),
        Felt252::new(BigInt([
            0x50b70eaa8a3c7cc7,
            0x9325a61fb2ef326e,
            0x142d0ac83d9da00c,
            0x01eb39da3f7d3b04,
        ])),
    ];

    assert_eq!(Poseidon::<Felt252>::perm(input), output);
}
