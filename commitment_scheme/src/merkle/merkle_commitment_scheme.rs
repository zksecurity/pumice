use crate::{
    merkle::{bytes_as_hash, Hasher},
    CommitmentSchemeProver, CommitmentSchemeVerifier,
};
use anyhow::{Error, Ok};
use ark_ff::PrimeField;
use channel::{
    fs_prover_channel::FSProverChannel, fs_verifier_channel::FSVerifierChannel, ProverChannel,
    VerifierChannel,
};
use randomness::Prng;
use sha3::Digest;
use std::collections::BTreeSet;
use std::{collections::BTreeMap, marker::PhantomData};

use super::MerkleTree;

pub struct MerkleCommitmentSchemeProver<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    n_elements: usize,
    tree: MerkleTree<F, H>,
    size_of_element: usize,
    queries: BTreeSet<usize>,
    phantom: PhantomData<(P, W)>,
}

impl<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> MerkleCommitmentSchemeProver<F, H, P, W> {
    /// Constructs a new MerkleCommitmentSchemeProver.
    pub fn new(n_elements: usize) -> Self {
        let tree = MerkleTree::new(n_elements);
        Self {
            n_elements,
            tree,
            size_of_element: H::DIGEST_NUM_BYTES,
            queries: BTreeSet::new(),
            phantom: PhantomData,
        }
    }
}

// Implement CommitmentSchemeProver trait for MerkleCommitmentSchemeProver
impl<F, H, P, W> CommitmentSchemeProver<F, P, W> for MerkleCommitmentSchemeProver<F, H, P, W>
where
    F: PrimeField,
    H: Hasher<F, Output = [u8; 32]>,
    P: Prng,
    W: Digest,
{
    fn num_segments(&self) -> usize {
        self.n_elements
    }

    fn segment_length_in_elements(&self) -> usize {
        1
    }

    fn element_length_in_bytes(&self) -> usize {
        self.size_of_element
    }

    fn add_segment_for_commitment(&mut self, segment_data: &[u8], segment_index: usize) {
        let segment_length = self.segment_length_in_elements();
        assert!(segment_data.len() == segment_length * self.size_of_element);
        self.tree.add_data(
            &bytes_as_hash::<F, H>(segment_data, self.size_of_element),
            segment_index * segment_length,
        );
    }

    fn commit(&mut self, channel: &mut FSProverChannel<F, P, W>) -> Result<(), Error> {
        let comm = self.tree.get_root();
        channel.send_commit_hash(comm)?;
        Ok(())
    }

    fn start_decommitment_phase(&mut self, queries: BTreeSet<usize>) -> Vec<usize> {
        self.queries = queries;
        vec![]
    }

    fn decommit(
        &mut self,
        elements_data: &[u8],
        channel: &mut FSProverChannel<F, P, W>,
    ) -> Result<(), Error> {
        assert!(elements_data.is_empty());
        self.tree.generate_decommitment(&self.queries, channel);
        Ok(())
    }

    fn get_proof(&self, channel: &mut FSProverChannel<F, P, W>) -> Vec<u8> {
        channel.get_proof()
    }
}

pub struct MerkleCommitmentSchemeVerifier<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    n_elements: usize,
    comm: H::Output,
    phantom: PhantomData<(P, W)>,
}

impl<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> MerkleCommitmentSchemeVerifier<F, H, P, W> {
    /// Constructs a new MerkleCommitmentSchemeVerifier.
    pub fn new(n_elements: usize) -> Self {
        Self {
            n_elements,
            comm: H::Output::default(),
            phantom: PhantomData,
        }
    }
}

// Implement CommitmentSchemeVerifier trait for MerkleCommitmentSchemeVerifier
impl<F: PrimeField, H: Hasher<F, Output = [u8; 32]>, P: Prng, W: Digest>
    CommitmentSchemeVerifier<F, P, W> for MerkleCommitmentSchemeVerifier<F, H, P, W>
{
    fn read_commitment(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
    ) -> Result<(), anyhow::Error> {
        let comm_vec = channel.recv_commit_hash(H::DIGEST_NUM_BYTES)?;
        assert_eq!(comm_vec.len(), 32);
        let mut comm_bytes = [0u8; 32];
        comm_bytes.copy_from_slice(&comm_vec);
        self.comm = comm_bytes;
        Ok(())
    }

    fn verify_integrity(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
        elements_to_verify: BTreeMap<usize, Vec<u8>>,
    ) -> Result<bool, Error> {
        let elements_to_verify = elements_to_verify
            .iter()
            .map(|(i, v)| {
                assert_eq!(v.len(), 32);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(v);
                (*i, bytes)
            })
            .collect();
        MerkleTree::<F, H>::verify_decommitment(
            self.comm,
            self.n_elements,
            &elements_to_verify,
            channel,
        )
    }

    fn num_of_elements(&self) -> usize {
        self.n_elements
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keccak256Hasher;
    use felt::Felt252;
    use randomness::keccak256::PrngKeccak256;
    use sha3::Sha3_256;

    fn test_completeness_with(
        size_of_element: usize,
        n_elements: usize,
        n_segments: usize,
        data: Vec<u8>,
        queries: BTreeSet<usize>,
        exp_proof: Vec<u8>,
        elements_to_verify: BTreeMap<usize, Vec<u8>>,
    ) {
        // Merkle Prover
        let channel_prng = PrngKeccak256::new();
        let mut prover_channel: FSProverChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(channel_prng.clone());
        let mut merkle_prover: MerkleCommitmentSchemeProver<
            Felt252,
            Keccak256Hasher<Felt252>,
            PrngKeccak256,
            Sha3_256,
        > = MerkleCommitmentSchemeProver::new(n_elements);
        for i in 0..n_segments {
            let segment = {
                let n_segment_bytes = size_of_element * (n_elements / n_segments);
                &data[i * n_segment_bytes..(i + 1) * n_segment_bytes]
            };
            merkle_prover.add_segment_for_commitment(segment, i);
        }
        merkle_prover.commit(&mut prover_channel).unwrap();
        let element_idxs = merkle_prover.start_decommitment_phase(queries);
        let elements_data: Vec<u8> = element_idxs
            .iter()
            .flat_map(|&idx| &data[idx * size_of_element..(idx + 1) * size_of_element])
            .cloned()
            .collect();
        merkle_prover
            .decommit(&elements_data, &mut prover_channel)
            .unwrap();
        let proof = merkle_prover.get_proof(&mut prover_channel);
        assert_eq!(proof, exp_proof);

        // Merkle Verifier
        let mut verifier_channel: FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(channel_prng, proof);
        let mut merkle_verifier: MerkleCommitmentSchemeVerifier<
            Felt252,
            Keccak256Hasher<Felt252>,
            PrngKeccak256,
            Sha3_256,
        > = MerkleCommitmentSchemeVerifier::new(n_elements);
        merkle_verifier
            .read_commitment(&mut verifier_channel)
            .unwrap();
        assert!(merkle_verifier
            .verify_integrity(&mut verifier_channel, elements_to_verify)
            .unwrap());
    }

    #[test]
    fn test_merkle_completeness() {
        let size_of_element = 32;
        let n_segments = 4;
        let n_elements = 4;
        let data: Vec<u8> = vec![
            1, 64, 168, 142, 254, 17, 77, 168, 157, 155, 158, 186, 182, 22, 253, 228, 217, 117, 53,
            169, 171, 40, 86, 199, 131, 2, 208, 92, 242, 159, 66, 241, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([0, 1, 2, 3]);
        let exp_proof = vec![
            212, 239, 97, 13, 230, 42, 90, 41, 159, 41, 138, 128, 61, 211, 76, 84, 21, 213, 89,
            126, 245, 99, 111, 30, 211, 238, 132, 64, 5, 175, 101, 197,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                0,
                vec![
                    1, 64, 168, 142, 254, 17, 77, 168, 157, 155, 158, 186, 182, 22, 253, 228, 217,
                    117, 53, 169, 171, 40, 86, 199, 131, 2, 208, 92, 242, 159, 66, 241,
                ],
            ),
            (1, [0; 32].to_vec()),
            (2, [0; 32].to_vec()),
            (3, [0; 32].to_vec()),
        ]);
        test_completeness_with(
            size_of_element,
            n_elements,
            n_segments,
            data,
            queries,
            exp_proof,
            elements_to_verify,
        );

        let size_of_element = 32;
        let n_segments = 32;
        let n_elements = 32;
        let data: Vec<u8> = vec![
            0, 98, 61, 250, 54, 64, 0, 209, 129, 221, 170, 237, 77, 94, 38, 46, 28, 234, 161, 98,
            236, 124, 193, 37, 121, 84, 174, 94, 207, 101, 210, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let queries = BTreeSet::from([7, 9, 15, 28, 30]);
        let exp_proof = vec![
            133, 129, 31, 215, 128, 240, 158, 84, 221, 189, 102, 241, 194, 89, 254, 240, 255, 113,
            66, 21, 170, 154, 9, 4, 253, 170, 122, 7, 125, 126, 121, 217, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182, 118, 247, 211, 205, 66, 132, 165, 68, 63, 23,
            241, 150, 43, 54, 228, 145, 179, 10, 64, 178, 64, 88, 73, 229, 151, 186, 95, 181, 173,
            50, 40, 182, 118, 247, 211, 205, 66, 132, 165, 68, 63, 23, 241, 150, 43, 54, 228, 145,
            179, 10, 64, 178, 64, 88, 73, 229, 151, 186, 95, 181, 173, 50, 40, 182, 118, 247, 211,
            205, 66, 132, 165, 68, 63, 23, 241, 150, 43, 54, 228, 145, 179, 10, 64, 178, 64, 88,
            73, 229, 151, 186, 95, 181, 70, 73, 143, 240, 176, 76, 135, 120, 240, 102, 218, 47,
            189, 229, 250, 200, 187, 224, 214, 29, 156, 3, 195, 129, 151, 7, 41, 166, 182, 227, 10,
            130, 180, 193, 25, 81, 149, 124, 111, 143, 100, 44, 74, 246, 28, 214, 178, 70, 64, 254,
            198, 220, 127, 198, 7, 238, 130, 6, 169, 158, 146, 65, 13, 48, 33, 221, 185, 163, 86,
            129, 92, 63, 172, 16, 38, 182, 222, 197, 223, 49, 36, 175, 186, 219, 72, 92, 155, 165,
            163, 227, 57, 138, 4, 183, 186, 133,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                7,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                9,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                15,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                28,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                30,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        test_completeness_with(
            size_of_element,
            n_elements,
            n_segments,
            data,
            queries,
            exp_proof,
            elements_to_verify,
        );

        let size_of_element = 32;
        let n_segments = 1;
        let n_elements = 1;
        let data: Vec<u8> = vec![
            165, 136, 34, 214, 70, 164, 63, 137, 164, 186, 212, 74, 243, 53, 184, 114, 65, 100, 59,
            164, 146, 248, 102, 158, 100, 123, 46, 148, 238, 30, 8, 106,
        ];
        let queries = BTreeSet::from([0]);
        let exp_proof = vec![
            165, 136, 34, 214, 70, 164, 63, 137, 164, 186, 212, 74, 243, 53, 184, 114, 65, 100, 59,
            164, 146, 248, 102, 158, 100, 123, 46, 148, 238, 30, 8, 106,
        ];

        let elements_to_verify = BTreeMap::from([(
            0,
            vec![
                165, 136, 34, 214, 70, 164, 63, 137, 164, 186, 212, 74, 243, 53, 184, 114, 65, 100,
                59, 164, 146, 248, 102, 158, 100, 123, 46, 148, 238, 30, 8, 106,
            ],
        )]);
        test_completeness_with(
            size_of_element,
            n_elements,
            n_segments,
            data,
            queries,
            exp_proof,
            elements_to_verify,
        );
    }
}
