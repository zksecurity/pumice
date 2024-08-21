use crate::{
    merkle::{bytes_as_hash, Hasher},
    CommitmentSchemeProver, CommitmentSchemeVerifier,
};
use anyhow::Ok;
use ark_ff::PrimeField;
use channel::{
    fs_prover_channel::FSProverChannel, fs_verifier_channel::FSVerifierChannel, ProverChannel,
    VerifierChannel,
};
use randomness::Prng;
use sha3::Digest;

use super::MerkleTree;

#[allow(dead_code)]
pub struct MerkleCommitmentSchemeProver<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    n_elements: usize,
    channel: FSProverChannel<F, P, W>,
    tree: MerkleTree<F, H>,
    min_segment_bytes: usize,
    size_of_element: usize,
    queries: Vec<usize>,
}

impl<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> MerkleCommitmentSchemeProver<F, H, P, W> {
    #[allow(dead_code)]
    pub fn new(n_elements: usize, channel: FSProverChannel<F, P, W>) -> Self {
        let tree = MerkleTree::new(n_elements);
        Self {
            n_elements,
            channel,
            tree,
            min_segment_bytes: 2 * H::DIGEST_NUM_BYTES,
            size_of_element: H::DIGEST_NUM_BYTES,
            queries: vec![0],
        }
    }
}

impl<F: PrimeField, H: Hasher<F, Output = Vec<u8>>, P: Prng, W: Digest> CommitmentSchemeProver
    for MerkleCommitmentSchemeProver<F, H, P, W>
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
        assert!(segment_data.len() == self.segment_length_in_elements() * self.size_of_element);
        self.tree.add_data(
            &bytes_as_hash::<F, H>(segment_data, self.size_of_element),
            segment_index * self.segment_length_in_elements(),
        );
    }

    fn commit(&mut self) {
        let height = self.tree.data_length.ilog2() as usize;
        let comm = self
            .tree
            .get_root(height - self.segment_length_in_elements().ilog2() as usize);
        let _ = self.channel.send_commit_hash(comm);
    }

    fn start_decommitment_phase(&mut self, queries: Vec<usize>) -> Vec<usize> {
        self.queries = queries;
        vec![]
    }

    fn decommit(&mut self, elements_data: &[u8]) {
        assert!(elements_data.is_empty());
        self.tree
            .generate_decommitment(&self.queries, &mut self.channel);
    }
}

pub struct MerkleCommitmentSchemeVerifier<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    n_elements: usize,
    channel: FSVerifierChannel<F, P, W>,
    comm: H::Output,
}

impl<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> MerkleCommitmentSchemeVerifier<F, H, P, W> {
    #[allow(dead_code)]
    pub fn new(n_elements: usize, channel: FSVerifierChannel<F, P, W>) -> Self {
        Self {
            n_elements,
            channel,
            comm: H::Output::default(),
        }
    }
}

impl<F: PrimeField, H: Hasher<F, Output = Vec<u8>>, P: Prng, W: Digest> CommitmentSchemeVerifier
    for MerkleCommitmentSchemeVerifier<F, H, P, W>
{
    fn read_commitment(&mut self) -> Result<(), anyhow::Error> {
        self.comm = self.channel.recv_commit_hash(H::DIGEST_NUM_BYTES)?;
        Ok(())
    }

    fn verify_integrity(&mut self, elements_to_verify: &[(usize, Vec<u8>)]) -> Option<bool> {
        MerkleTree::<F, H>::verify_decommitment(
            self.comm.clone(),
            self.n_elements,
            elements_to_verify,
            &mut self.channel,
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
    use channel::ProverChannel;
    use felt::Felt252;
    use randomness::keccak256::PrngKeccak256;
    use sha3::Sha3_256;

    #[test]
    fn test_merkle_completeness() {
        // Data
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
        let queries: Vec<usize> = vec![0, 1, 2, 3];
        let exp_proof = vec![
            212, 239, 97, 13, 230, 42, 90, 41, 159, 41, 138, 128, 61, 211, 76, 84, 21, 213, 89,
            126, 245, 99, 111, 30, 211, 238, 132, 64, 5, 175, 101, 197,
        ];

        // Merkle Prover
        let channel_prng = PrngKeccak256::new();
        let prover_channel: FSProverChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(channel_prng.clone());
        let mut merkle_prover: MerkleCommitmentSchemeProver<
            Felt252,
            Keccak256Hasher<Felt252>,
            PrngKeccak256,
            Sha3_256,
        > = MerkleCommitmentSchemeProver::new(4, prover_channel.clone());
        for i in 0..n_segments {
            let segment = {
                let n_segment_bytes = size_of_element * (n_elements / n_segments);
                &data[i * n_segment_bytes..(i + 1) * n_segment_bytes]
            };
            merkle_prover.add_segment_for_commitment(segment, i);
        }
        merkle_prover.commit();
        let element_idxs = merkle_prover.start_decommitment_phase(queries);
        let elements_data: Vec<u8> = element_idxs
            .iter()
            .flat_map(|&idx| &data[idx * size_of_element..(idx + 1) * size_of_element])
            .cloned()
            .collect();
        merkle_prover.decommit(&elements_data);
        let proof = merkle_prover.channel.get_proof();
        assert_eq!(proof, exp_proof);

        // Merkle Verifier
        let elements_to_verify: [(usize, Vec<u8>); 4] = [
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
        ];
        let verifier_channel: FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(channel_prng, proof);
        let mut merkle_verifier: MerkleCommitmentSchemeVerifier<
            Felt252,
            Keccak256Hasher<Felt252>,
            PrngKeccak256,
            Sha3_256,
        > = MerkleCommitmentSchemeVerifier::new(4, verifier_channel);
        let _ = merkle_verifier.read_commitment();
        assert!(merkle_verifier
            .verify_integrity(&elements_to_verify)
            .unwrap());
    }
}
