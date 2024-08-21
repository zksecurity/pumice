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
