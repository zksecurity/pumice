// use super::fs_prover_channel::FSProverChannel;
// use super::fs_verifier_channel::FSVerifierChannel;
// use super::{Channel, FSChannel, ProverChannel, VerifierChannel};
// use ark_ff::PrimeField;
// use blake2::Blake2s256;
// use felt::Felt252;
// use generic_array::GenericArray;
// use hex_literal::hex;
// use randomness::{keccak256::PrngKeccak256, poseidon3::PrngPoseidon3, Prng, PrngOnlyForTest};
// use sha3::{Digest, Sha3_256};

// trait TestTypes {
//     type VerifierChannel: Channel;
//     type ProverChannel: Channel;
// }

// struct TestTypesImpl<F, P, W>(std::marker::PhantomData<(F, P, W)>);

// impl<F, P, W> TestTypes for TestTypesImpl<F, P, W>
// where
//     F: PrimeField,
//     P: Prng,
//     W: Digest,
//     FSVerifierChannel<F, P, W>: Channel<Field = F>,
//     FSProverChannel<F, P, W>: Channel<Field = F>,
// {
//     type VerifierChannel = FSVerifierChannel<F, P, W>;
//     type ProverChannel = FSProverChannel<F, P, W>;
// }
