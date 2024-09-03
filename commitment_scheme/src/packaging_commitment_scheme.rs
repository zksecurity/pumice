use crate::merkle::hash::Hasher;
use crate::packer_hasher::PackerHasher;
use crate::{CommitmentSchemeProver, CommitmentSchemeVerifier};
use anyhow::{Error, Ok};
use ark_ff::PrimeField;
use channel::fs_prover_channel::FSProverChannel;
use channel::fs_verifier_channel::FSVerifierChannel;
use channel::ProverChannel;
use channel::VerifierChannel;
use randomness::Prng;
use sha3::Digest;
use std::collections::{BTreeMap, BTreeSet};

/// Prover of Packaging Commitment Scheme.
pub struct PackagingCommitmentSchemeProver<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    size_of_element: usize,
    n_elements_in_segment: usize,
    n_segments: usize,
    packer: PackerHasher<F, H>,
    inner_commitment_scheme: Box<dyn CommitmentSchemeProver<F, P, W>>,
    is_merkle_layer: bool,
    queries: BTreeSet<usize>,
    missing_element_queries: Vec<usize>,
    n_missing_elements_for_inner_layer: usize,
}

impl<F: PrimeField, H: Hasher<F, Output = [u8; 32]>, P: Prng, W: Digest>
    PackagingCommitmentSchemeProver<F, H, P, W>
{
    /// Constructs a new PackagingCommitmentSchemeProver.
    pub fn new(
        size_of_element: usize,
        n_elements_in_segment: usize,
        n_segments: usize,
        packer: PackerHasher<F, H>,
        inner_commitment_scheme: Box<dyn CommitmentSchemeProver<F, P, W>>,
        is_merkle_layer: bool,
    ) -> Self {
        if is_merkle_layer {
            assert!(packer.n_elements_in_package == 2);
            assert_eq!(
                2 * inner_commitment_scheme.segment_length_in_elements(),
                n_elements_in_segment
            );
        }

        Self {
            size_of_element,
            n_elements_in_segment,
            n_segments,
            packer,
            inner_commitment_scheme,
            is_merkle_layer,
            queries: BTreeSet::new(),
            missing_element_queries: vec![],
            n_missing_elements_for_inner_layer: 0,
        }
    }
}

// Implement CommitmentSchemeProver trait for PackagingCommitmentSchemeProver
impl<F: PrimeField, H: Hasher<F, Output = [u8; 32]>, P: Prng, W: Digest>
    CommitmentSchemeProver<F, P, W> for PackagingCommitmentSchemeProver<F, H, P, W>
{
    fn element_length_in_bytes(&self) -> usize {
        self.size_of_element
    }

    fn num_segments(&self) -> usize {
        self.n_segments
    }

    fn segment_length_in_elements(&self) -> usize {
        self.n_elements_in_segment
    }

    fn add_segment_for_commitment(&mut self, segment_data: &[u8], segment_index: usize) {
        assert_eq!(
            segment_data.len(),
            self.n_elements_in_segment * self.size_of_element
        );
        assert!(segment_index < self.num_segments());
        let packed = self
            .packer
            .pack_and_hash_internal(segment_data, self.is_merkle_layer);
        self.inner_commitment_scheme
            .add_segment_for_commitment(&packed, segment_index);
    }

    fn commit(&mut self, channel: &mut FSProverChannel<F, P, W>) -> Result<(), anyhow::Error> {
        self.inner_commitment_scheme.commit(channel)
    }

    fn start_decommitment_phase(&mut self, queries: BTreeSet<usize>) -> Vec<usize> {
        self.queries = queries;
        self.missing_element_queries = self
            .packer
            .elements_required_to_compute_hashes(&self.queries);

        let package_queries_to_inner_layer: BTreeSet<usize> = self
            .queries
            .iter()
            .map(|&q| q / self.packer.n_elements_in_package)
            .collect();

        let missing_package_queries_inner_layer = self
            .inner_commitment_scheme
            .start_decommitment_phase(package_queries_to_inner_layer);

        let missing_element_queries_to_inner_layer = self
            .packer
            .get_elements_in_packages(&missing_package_queries_inner_layer);

        self.n_missing_elements_for_inner_layer = missing_element_queries_to_inner_layer.len();

        let mut all_missing_elements = Vec::with_capacity(
            self.missing_element_queries.len() + self.n_missing_elements_for_inner_layer,
        );

        // Add elements from `missing_element_queries` and `missing_element_queries_to_inner_layer`.
        all_missing_elements.extend(self.missing_element_queries.iter().cloned());
        all_missing_elements.extend(missing_element_queries_to_inner_layer);

        all_missing_elements
    }

    fn decommit(
        &mut self,
        elements_data: &[u8],
        channel: &mut FSProverChannel<F, P, W>,
    ) -> Result<(), Error> {
        assert_eq!(
            elements_data.len(),
            self.size_of_element
                * (self.missing_element_queries.len() + self.n_missing_elements_for_inner_layer),
        );

        for i in 0..self.missing_element_queries.len() {
            let start = i * self.size_of_element;
            let end = start + self.size_of_element;
            let bytes_to_send = &elements_data[start..end];

            if self.is_merkle_layer {
                let digest = bytes_to_send.to_vec();
                channel.send_decommit_node(digest)?;
            } else {
                channel.send_data(bytes_to_send)?;
            }
        }

        let start = self.missing_element_queries.len() * self.size_of_element;
        let end = start + self.n_missing_elements_for_inner_layer * self.size_of_element;
        let data_for_inner_layer = self
            .packer
            .pack_and_hash_internal(&elements_data[start..end], self.is_merkle_layer);

        self.inner_commitment_scheme
            .decommit(&data_for_inner_layer, channel)?;
        Ok(())
    }

    fn get_proof(&self, channel: &mut FSProverChannel<F, P, W>) -> Vec<u8> {
        channel.get_proof()
    }
}

/// Verifier of Packaging Commitment Scheme.
pub struct PackagingCommitmentSchemeVerifier<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    size_of_element: usize,
    n_elements: usize,
    packer: PackerHasher<F, H>,
    inner_commitment_scheme: Box<dyn CommitmentSchemeVerifier<F, P, W>>,
    is_merkle_layer: bool,
}

impl<F: PrimeField, H: Hasher<F, Output = [u8; 32]>, P: Prng, W: Digest>
    PackagingCommitmentSchemeVerifier<F, H, P, W>
{
    /// Constructs a new PackagingCommitmentSchemeVerifier using the commitment scheme factory input.
    ///
    /// # Arguments
    ///
    /// - `size_of_element`: length of element in bytes.
    /// - `n_elements`: number of elements.
    /// - `channel`: Fiat-Shamir verifier channel
    /// - `inner_commitment_scheme`: commitment scheme verifier
    /// - `is_merkle_layer`: flag to indicate Merkle layer.
    ///
    /// # Returns
    ///
    /// - `Self`: PackagingCommitmentSchemeVerifier
    pub fn new(
        size_of_element: usize,
        n_elements: usize,
        packer: PackerHasher<F, H>,
        inner_commitment_scheme: Box<dyn CommitmentSchemeVerifier<F, P, W>>,
        is_merkle_layer: bool,
    ) -> Self {
        if is_merkle_layer {
            assert_eq!(packer.n_elements_in_package, 2);
            assert_eq!(2 * inner_commitment_scheme.num_of_elements(), n_elements);
        }

        Self {
            size_of_element,
            n_elements,
            packer,
            inner_commitment_scheme,
            is_merkle_layer,
        }
    }
}

/// Implement CommitmentSchemeVerifier trait for PackagingCommitmentSchemeVerifier
impl<F: PrimeField, H: Hasher<F, Output = [u8; 32]>, P: Prng, W: Digest>
    CommitmentSchemeVerifier<F, P, W> for PackagingCommitmentSchemeVerifier<F, H, P, W>
{
    fn num_of_elements(&self) -> usize {
        self.n_elements
    }

    fn read_commitment(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
    ) -> Result<(), anyhow::Error> {
        self.inner_commitment_scheme.read_commitment(channel)
    }

    fn verify_integrity(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
        elements_to_verify: BTreeMap<usize, Vec<u8>>,
    ) -> Result<bool, Error> {
        // Get missing elements required to compute hashes
        let keys: BTreeSet<usize> = elements_to_verify.keys().copied().collect();
        let missing_elements_idxs = self.packer.elements_required_to_compute_hashes(&keys);

        let mut full_data_to_verify = elements_to_verify.clone();

        for &missing_element_idx in &missing_elements_idxs {
            if self.is_merkle_layer {
                let result_array = channel.recv_decommit_node(H::DIGEST_NUM_BYTES)?;
                full_data_to_verify.insert(missing_element_idx, result_array.to_vec());
            } else {
                let data = channel.recv_data(self.size_of_element)?;
                full_data_to_verify.insert(missing_element_idx, data);
            }
        }

        // Convert data to hahses
        let bytes_to_verify = self
            .packer
            .pack_and_hash(&full_data_to_verify, self.is_merkle_layer);

        self.inner_commitment_scheme
            .verify_integrity(channel, bytes_to_verify)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::merkle::merkle_commitment_scheme::tests::{
        draw_data, draw_queries, get_sparse_data,
    };
    use crate::{
        make_commitment_scheme_prover, make_commitment_scheme_verifier, CommitmentHashes,
        SupportedHashes,
    };
    use felt::Felt252;
    use rand::Rng;
    use randomness::keccak256::PrngKeccak256;
    use sha3::Sha3_256;

    fn test_packaging_completeness_with(
        size_of_element: usize,
        n_segments: usize,
        n_elements: usize,
        n_verifier_friendly_commitment_layers: usize,
        exp_proof: Vec<u8>,
        data: Vec<u8>,
        queries: BTreeSet<usize>,
        elements_to_verify: BTreeMap<usize, Vec<u8>>,
        commitment_hashes: CommitmentHashes,
    ) {
        let channel_prng = PrngKeccak256::new();

        // Prover
        let mut prover_channel: FSProverChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(channel_prng.clone());
        let n_elements_in_segment = n_elements / n_segments;
        let mut prover = make_commitment_scheme_prover(
            size_of_element,
            n_elements_in_segment,
            n_segments,
            n_verifier_friendly_commitment_layers,
            commitment_hashes.clone(),
            1,
        );
        for i in 0..n_segments {
            let segment = {
                let n_segment_bytes = size_of_element * (n_elements / n_segments);
                &data[i * n_segment_bytes..(i + 1) * n_segment_bytes]
            };
            prover.add_segment_for_commitment(segment, i);
        }
        prover.commit(&mut prover_channel).unwrap();
        let element_idxs = prover.start_decommitment_phase(queries);
        let elements_data: Vec<u8> = element_idxs
            .iter()
            .flat_map(|&idx| &data[idx * size_of_element..(idx + 1) * size_of_element])
            .cloned()
            .collect();
        prover
            .decommit(&elements_data, &mut prover_channel)
            .unwrap();
        let proof = prover_channel.get_proof();
        assert_eq!(proof, exp_proof);

        // Verifier
        let mut verifier_channel: FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(channel_prng, proof);

        let mut verifier = make_commitment_scheme_verifier(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            commitment_hashes,
            1,
        );
        verifier.read_commitment(&mut verifier_channel).unwrap();
        assert!(verifier
            .verify_integrity(&mut verifier_channel, elements_to_verify)
            .unwrap());
    }

    fn test_verify_corrupted(
        size_of_element: usize,
        n_elements: usize,
        n_verifier_friendly_commitment_layers: usize,
        proof: Vec<u8>,
        elements_to_verify: BTreeMap<usize, Vec<u8>>,
        commitment_hashes: CommitmentHashes,
    ) {
        let channel_prng = PrngKeccak256::new();
        let mut verifier_channel: FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(channel_prng, proof);
        let mut verifier = make_commitment_scheme_verifier(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            commitment_hashes,
            1,
        );
        verifier.read_commitment(&mut verifier_channel).unwrap();
        assert!(!verifier
            .verify_integrity(&mut verifier_channel, elements_to_verify)
            .unwrap());
    }

    #[test]
    fn test_packaging_completeness() {
        let size_of_element = 1;
        let n_elements = 1;
        let n_segments = 1;
        let n_verifier_friendly_commitment_layers = 0;
        let data = vec![218];
        let queries = BTreeSet::from([0]);
        let exp_proof = vec![
            144, 179, 218, 100, 7, 139, 77, 94, 125, 120, 142, 246, 58, 51, 233, 222, 113, 197,
            164, 233, 90, 95, 203, 225, 80, 92, 226, 11, 38, 65, 75, 186,
        ];
        let elements_to_verify = BTreeMap::from([(0, vec![218])]);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Keccak256);
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 4;
        let n_segments = 2;
        let n_verifier_friendly_commitment_layers = 0;
        let data: Vec<u8> = vec![
            1, 35, 100, 184, 107, 167, 27, 153, 178, 178, 4, 16, 193, 139, 130, 53, 171, 152, 226,
            105, 245, 241, 72, 163, 50, 42, 211, 163, 168, 41, 209, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([2, 3]);
        let exp_proof: Vec<u8> = vec![
            30, 203, 180, 40, 198, 195, 135, 138, 82, 181, 102, 57, 157, 204, 229, 11, 171, 220,
            225, 49, 123, 125, 106, 107, 26, 60, 209, 112, 118, 253, 69, 144, 188, 211, 231, 5,
            196, 97, 64, 1, 86, 176, 99, 66, 246, 247, 210, 53, 232, 192, 90, 107, 229, 91, 72, 22,
            240, 95, 210, 204, 8, 248, 196, 107,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                2,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                3,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Keccak256);
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 9;
        let n_elements = 8;
        let n_segments = 1;
        let n_verifier_friendly_commitment_layers = 0;
        let data: Vec<u8> = vec![
            4, 90, 97, 132, 3, 36, 87, 219, 51, 182, 28, 167, 37, 233, 113, 129, 120, 66, 148, 157,
            113, 212, 10, 142, 81, 151, 47, 212, 110, 9, 191, 172, 184, 18, 38, 85, 28, 20, 113,
            33, 169, 7, 62, 125, 232, 129, 32, 248, 19, 171, 203, 4, 98, 161, 174, 222, 239, 94,
            124, 218, 67, 84, 16, 249, 51, 75, 2, 29, 214, 172, 247, 141,
        ];
        let queries = BTreeSet::from([0, 1, 2, 3, 4, 7]);
        let exp_proof: Vec<u8> = vec![
            227, 216, 27, 24, 119, 173, 119, 23, 6, 143, 172, 94, 211, 230, 252, 178, 181, 162,
            103, 224, 82, 199, 136, 76, 191, 61, 234, 103, 168, 121, 179, 118, 129, 32, 248, 19,
            171, 203, 4, 98, 161, 174, 222, 239, 94, 124, 218, 67, 84, 16,
        ];
        let elements_to_verify: BTreeMap<usize, Vec<u8>> = BTreeMap::from([
            (0, vec![4, 90, 97, 132, 3, 36, 87, 219, 51]),
            (1, vec![182, 28, 167, 37, 233, 113, 129, 120, 66]),
            (2, vec![148, 157, 113, 212, 10, 142, 81, 151, 47]),
            (3, vec![212, 110, 9, 191, 172, 184, 18, 38, 85]),
            (4, vec![28, 20, 113, 33, 169, 7, 62, 125, 232]),
            (7, vec![249, 51, 75, 2, 29, 214, 172, 247, 141]),
        ]);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Keccak256);
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof.clone(),
            data,
            queries,
            elements_to_verify.clone(),
            commitment_hashes.clone(),
        );

        // test corrupted_proof fails
        let mut corrupted_proof = exp_proof.clone();
        corrupted_proof[11] ^= 1;
        test_verify_corrupted(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            corrupted_proof,
            elements_to_verify.clone(),
            commitment_hashes.clone(),
        );

        // test corrupted_data fails
        let mut corrupted_data: BTreeMap<usize, Vec<u8>> = elements_to_verify.clone();
        corrupted_data.get_mut(&3).map(|v| v[0] = 99);
        test_verify_corrupted(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            corrupted_data,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 4;
        let n_segments = 1;
        let n_verifier_friendly_commitment_layers = 0;
        let data: Vec<u8> = vec![
            0, 244, 180, 10, 155, 113, 242, 248, 48, 242, 218, 212, 163, 250, 94, 65, 248, 34, 62,
            45, 135, 203, 137, 51, 226, 102, 52, 31, 183, 44, 63, 77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([0, 1, 2, 3]);
        let exp_proof: Vec<u8> = vec![
            226, 176, 114, 29, 157, 171, 34, 248, 182, 241, 254, 5, 43, 225, 0, 170, 122, 203, 186,
            188, 169, 218, 71, 145, 121, 80, 14, 246, 189, 160, 236, 130,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                0,
                vec![
                    0, 244, 180, 10, 155, 113, 242, 248, 48, 242, 218, 212, 163, 250, 94, 65, 248,
                    34, 62, 45, 135, 203, 137, 51, 226, 102, 52, 31, 183, 44, 63, 77,
                ],
            ),
            (
                1,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                2,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                3,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Keccak256);
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 4;
        let n_segments = 2;
        let n_verifier_friendly_commitment_layers = 0;
        let data: Vec<u8> = vec![
            0, 69, 9, 83, 116, 186, 114, 166, 162, 161, 5, 164, 38, 245, 112, 70, 202, 33, 63, 186,
            85, 163, 0, 139, 112, 108, 14, 98, 197, 219, 225, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([0]);
        let exp_proof: Vec<u8> = vec![
            146, 94, 184, 144, 65, 226, 66, 73, 78, 28, 77, 148, 37, 124, 200, 171, 209, 97, 100,
            196, 17, 231, 9, 39, 122, 53, 63, 43, 193, 194, 119, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182,
            118, 247, 211, 205, 66, 132, 165, 68, 63, 23, 241, 150, 43, 54, 228, 145, 179, 10, 64,
            178, 64, 88, 73, 229, 151, 186, 95, 181,
        ];
        let elements_to_verify = BTreeMap::from([(
            0,
            vec![
                0, 69, 9, 83, 116, 186, 114, 166, 162, 161, 5, 164, 38, 245, 112, 70, 202, 33, 63,
                186, 85, 163, 0, 139, 112, 108, 14, 98, 197, 219, 225, 74,
            ],
        )]);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Keccak256);
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof.clone(),
            data,
            queries,
            elements_to_verify.clone(),
            commitment_hashes.clone(),
        );

        // test corrupted_proof fails
        let mut corrupted_proof = exp_proof.clone();
        corrupted_proof[7] ^= 1;
        test_verify_corrupted(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            corrupted_proof,
            elements_to_verify.clone(),
            commitment_hashes.clone(),
        );

        // test corrupted_data fails
        let mut corrupted_data: BTreeMap<usize, Vec<u8>> = elements_to_verify.clone();
        corrupted_data.get_mut(&0).map(|v| v[5] = 109);
        test_verify_corrupted(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            corrupted_data,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 4;
        let n_segments = 2;
        let n_verifier_friendly_commitment_layers = 1;
        let data: Vec<u8> = vec![
            2, 129, 165, 248, 198, 144, 235, 236, 30, 71, 164, 35, 47, 38, 145, 108, 41, 53, 65,
            169, 165, 85, 179, 25, 169, 23, 109, 11, 38, 0, 206, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([0, 1, 2, 3]);
        let exp_proof: Vec<u8> = vec![
            148, 85, 7, 241, 56, 123, 72, 220, 51, 26, 148, 117, 239, 101, 123, 151, 113, 30, 182,
            47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                0,
                vec![
                    2, 129, 165, 248, 198, 144, 235, 236, 30, 71, 164, 35, 47, 38, 145, 108, 41,
                    53, 65, 169, 165, 85, 179, 25, 169, 23, 109, 11, 38, 0, 206, 20,
                ],
            ),
            (
                1,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                2,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                3,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Blake2s256Masked160Msb,
            SupportedHashes::Keccak256Masked160Msb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 4;
        let n_segments = 2;
        let n_verifier_friendly_commitment_layers = 1;
        let data: Vec<u8> = vec![
            6, 253, 243, 32, 167, 44, 209, 69, 4, 235, 114, 63, 109, 243, 205, 172, 86, 124, 152,
            43, 252, 153, 20, 15, 150, 124, 37, 19, 90, 90, 67, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([0, 1]);
        let exp_proof = vec![
            77, 253, 172, 222, 133, 197, 92, 214, 26, 4, 252, 10, 29, 34, 186, 18, 196, 230, 161,
            136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182, 118, 247, 211, 205, 66, 132,
            165, 68, 63, 23, 241, 150, 43, 54, 228, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                0,
                vec![
                    6, 253, 243, 32, 167, 44, 209, 69, 4, 235, 114, 63, 109, 243, 205, 172, 86,
                    124, 152, 43, 252, 153, 20, 15, 150, 124, 37, 19, 90, 90, 67, 4,
                ],
            ),
            (
                1,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Blake2s256Masked160Msb,
            SupportedHashes::Keccak256Masked160Msb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 64;
        let n_segments = 4;
        let n_verifier_friendly_commitment_layers = 3;
        let data = vec![
            5, 232, 237, 174, 93, 188, 164, 229, 182, 2, 128, 179, 44, 187, 71, 132, 176, 176, 140,
            160, 1, 240, 255, 110, 247, 22, 15, 142, 65, 87, 15, 250, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 141, 54,
            249, 121, 140, 78, 81, 125, 162, 239, 56, 1, 79, 23, 135, 32, 172, 110, 202, 8, 54, 95,
            155, 117, 33, 230, 243, 201, 77, 97, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([13, 49, 54, 59]);
        let exp_proof = vec![
            17, 175, 217, 238, 242, 6, 83, 8, 198, 201, 188, 40, 133, 58, 238, 12, 53, 151, 212,
            120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50,
            40, 182, 118, 247, 211, 205, 66, 132, 165, 68, 63, 23, 241, 150, 43, 54, 228, 145, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182, 118, 247, 211, 205, 66, 132, 165,
            68, 63, 23, 241, 150, 43, 54, 228, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50,
            40, 182, 118, 247, 211, 205, 66, 132, 165, 68, 63, 23, 241, 150, 43, 54, 228, 145, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182, 118, 247, 211, 205, 66, 132, 165,
            68, 63, 23, 241, 150, 43, 54, 228, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 93, 45,
            240, 89, 240, 28, 116, 132, 151, 245, 24, 242, 36, 208, 32, 23, 168, 220, 240, 203, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 93, 45, 240, 89, 240, 28, 116, 132, 151, 245, 24, 242,
            36, 208, 32, 23, 168, 220, 240, 203, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 86, 77,
            46, 15, 53, 141, 22, 6, 210, 148, 92, 94, 218, 225, 133, 228, 72, 184, 114, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 137, 241, 230, 89, 122, 228, 72, 155, 255, 123, 160, 215, 152,
            25, 205, 133, 21, 154, 86, 87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 56, 49, 60, 81, 107,
            50, 60, 244, 54, 30, 224, 21, 42, 197, 198, 191, 160, 172, 133, 90, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                13,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                49,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                54,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                59,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Blake2s256Masked160Msb,
            SupportedHashes::Keccak256Masked160Msb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 64;
        let n_segments = 4;
        let n_verifier_friendly_commitment_layers = 2;
        let data = vec![
            3, 201, 186, 225, 81, 215, 243, 89, 118, 154, 231, 57, 45, 88, 205, 242, 194, 148, 120,
            156, 153, 18, 99, 4, 233, 245, 72, 190, 7, 227, 9, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 230, 156,
            239, 206, 119, 116, 240, 45, 230, 91, 36, 212, 36, 176, 175, 180, 162, 116, 34, 119,
            64, 106, 181, 180, 172, 183, 46, 108, 213, 89, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([16, 21, 61]);
        let exp_proof = vec![
            237, 198, 151, 95, 18, 160, 125, 96, 36, 131, 148, 10, 144, 115, 33, 81, 132, 225, 252,
            105, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182,
            118, 247, 211, 205, 66, 132, 165, 68, 63, 23, 241, 150, 43, 54, 228, 145, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182, 118, 247, 211, 205, 66, 132, 165, 68, 63, 23,
            241, 150, 43, 54, 228, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 173, 50, 40, 182, 118,
            247, 211, 205, 66, 132, 165, 68, 63, 23, 241, 150, 43, 54, 228, 145, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 93, 45, 240, 89, 240, 28, 116, 132, 151, 245, 24, 242, 36, 208, 32,
            23, 168, 220, 240, 203, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 220, 163, 97, 65, 215,
            148, 173, 246, 163, 69, 66, 191, 118, 55, 180, 188, 167, 56, 55, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 8, 220, 163, 97, 65, 215, 148, 173, 246, 163, 69, 66, 191, 118, 55, 180,
            188, 167, 56, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 209, 207, 71, 110, 209, 250, 73,
            147, 92, 134, 105, 184, 181, 249, 184, 187, 226, 250, 17, 35, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 248, 87, 155, 137, 172, 174, 41, 80, 56, 22, 205, 145, 203, 71, 168, 43,
            221, 79, 227, 149, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                16,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                21,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                61,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Blake2s256Masked160Msb,
            SupportedHashes::Keccak256Masked160Msb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 64;
        let n_segments = 4;
        let n_verifier_friendly_commitment_layers = 3;
        let data = vec![
            4, 62, 165, 207, 178, 161, 255, 94, 234, 135, 162, 93, 45, 235, 250, 23, 66, 110, 137,
            7, 49, 49, 148, 11, 192, 167, 100, 199, 177, 152, 22, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 8, 200,
            215, 53, 197, 50, 15, 152, 40, 153, 218, 198, 171, 240, 32, 85, 20, 104, 159, 59, 76,
            235, 169, 136, 142, 170, 198, 173, 18, 151, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([0, 4, 21, 22, 36, 37, 41, 45, 62]);
        let exp_proof = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 156, 54, 64, 65, 75, 26, 56, 40, 245, 224, 208,
            216, 200, 6, 163, 221, 71, 152, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155,
            184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138,
            180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155,
            184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138,
            180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155,
            184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138,
            180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6,
            191, 235, 111, 177, 255, 136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 52, 166, 127, 203, 9, 189, 226, 6, 237, 115, 217, 45, 228, 68, 79, 6, 133, 75,
            147, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6, 191,
            235, 111, 177, 255, 136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 233, 90, 129, 43, 243, 205, 62, 98, 225, 128, 14, 71, 11, 180, 174, 33, 214, 121,
            18, 154, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 233, 90, 129, 43, 243, 205, 62, 98, 225,
            128, 14, 71, 11, 180, 174, 33, 214, 121, 18, 154, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            233, 90, 129, 43, 243, 205, 62, 98, 225, 128, 14, 71, 11, 180, 174, 33, 214, 121, 18,
            154,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                0,
                vec![
                    4, 62, 165, 207, 178, 161, 255, 94, 234, 135, 162, 93, 45, 235, 250, 23, 66,
                    110, 137, 7, 49, 49, 148, 11, 192, 167, 100, 199, 177, 152, 22, 86,
                ],
            ),
            (
                4,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                21,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                22,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                36,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                37,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                41,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                45,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                62,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Keccak256Masked160Lsb,
            SupportedHashes::Blake2s256Masked160Lsb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 64;
        let n_segments = 4;
        let n_verifier_friendly_commitment_layers = 3;
        let data = vec![
            6, 131, 174, 83, 201, 249, 197, 17, 243, 232, 9, 66, 33, 131, 135, 181, 199, 174, 234,
            204, 8, 69, 23, 131, 82, 244, 121, 48, 2, 82, 192, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 190, 245,
            173, 79, 48, 166, 157, 102, 236, 91, 117, 125, 132, 79, 40, 246, 10, 245, 36, 22, 113,
            232, 153, 150, 174, 168, 156, 36, 83, 46, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([42, 62]);
        let exp_proof = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 163, 184, 207, 108, 154, 156, 115, 68, 165, 230, 8,
            11, 226, 107, 73, 58, 181, 117, 60, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138,
            180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155,
            184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 208, 130, 114, 230, 1, 119, 214, 6, 191, 235, 111, 177, 255, 136, 249, 147, 171,
            66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6,
            191, 235, 111, 177, 255, 136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 139, 185, 55, 221, 49, 200, 126, 26, 169, 165, 78, 200, 123, 181, 43, 7,
            127, 71, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 233, 90, 129, 43, 243, 205, 62, 98,
            225, 128, 14, 71, 11, 180, 174, 33, 214, 121, 18, 154, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 168, 215, 6, 114, 243, 70, 92, 90, 253, 160, 33, 251, 98, 209, 26, 84, 72, 79, 160,
            65,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                42,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                62,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Keccak256Masked160Lsb,
            SupportedHashes::Blake2s256Masked160Lsb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 64;
        let n_segments = 4;
        let n_verifier_friendly_commitment_layers = 2;
        let data = vec![
            3, 99, 203, 140, 171, 33, 105, 160, 139, 151, 173, 147, 250, 53, 221, 32, 204, 234,
            165, 101, 61, 47, 82, 4, 137, 35, 5, 241, 64, 184, 137, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 227,
            99, 53, 88, 84, 228, 30, 137, 236, 136, 139, 80, 224, 146, 2, 218, 47, 71, 111, 220,
            38, 183, 204, 140, 207, 202, 214, 207, 33, 100, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([0, 7, 22, 28, 42, 61]);
        let exp_proof = vec![
            6, 193, 108, 112, 161, 111, 253, 173, 27, 253, 242, 186, 87, 196, 148, 220, 106, 210,
            227, 252, 135, 73, 22, 226, 59, 221, 124, 183, 98, 77, 111, 34, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246,
            136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154,
            111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246,
            136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154,
            111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246,
            136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154,
            111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114,
            230, 1, 119, 214, 6, 191, 235, 111, 177, 255, 136, 249, 147, 171, 66, 211, 178, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6, 191, 235, 111, 177,
            255, 136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130,
            114, 230, 1, 119, 214, 6, 191, 235, 111, 177, 255, 136, 249, 147, 171, 66, 211, 178, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6, 191, 235, 111,
            177, 255, 136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 233,
            90, 129, 43, 243, 205, 62, 98, 225, 128, 14, 71, 11, 180, 174, 33, 214, 121, 18, 154,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 117, 208, 30, 244, 247, 162, 133, 216, 196,
            233, 205, 13, 140, 160, 58, 148, 19, 207, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 233,
            90, 129, 43, 243, 205, 62, 98, 225, 128, 14, 71, 11, 180, 174, 33, 214, 121, 18, 154,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                0,
                vec![
                    3, 99, 203, 140, 171, 33, 105, 160, 139, 151, 173, 147, 250, 53, 221, 32, 204,
                    234, 165, 101, 61, 47, 82, 4, 137, 35, 5, 241, 64, 184, 137, 182,
                ],
            ),
            (
                7,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                22,
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
                42,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                61,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Poseidon3,
            SupportedHashes::Blake2s256Masked160Lsb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 32;
        let n_elements = 64;
        let n_segments = 4;
        let n_verifier_friendly_commitment_layers = 3;
        let data = vec![
            6, 72, 142, 255, 93, 198, 227, 20, 16, 188, 20, 43, 161, 65, 107, 118, 43, 52, 123,
            179, 244, 180, 100, 83, 204, 121, 101, 255, 103, 208, 216, 84, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            161, 68, 213, 2, 209, 208, 223, 130, 69, 252, 64, 67, 46, 153, 231, 181, 61, 83, 30,
            243, 64, 68, 157, 229, 17, 160, 163, 117, 104, 4, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let queries = BTreeSet::from([3, 11, 18, 23, 43, 48, 58]);
        let exp_proof = vec![
            1, 56, 182, 201, 169, 211, 93, 20, 168, 73, 109, 246, 232, 70, 231, 168, 99, 239, 98,
            232, 150, 80, 183, 49, 85, 232, 96, 245, 243, 140, 243, 167, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 142, 137,
            113, 42, 55, 87, 222, 96, 37, 99, 141, 79, 251, 121, 200, 217, 173, 144, 176, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154,
            111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246,
            136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154,
            111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246,
            136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246, 136, 228, 149, 155, 184, 197, 63, 53, 154,
            111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 84, 26, 246,
            136, 228, 149, 155, 184, 197, 63, 53, 154, 111, 86, 227, 138, 180, 84, 163, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6, 191, 235, 111, 177, 255,
            136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114,
            230, 1, 119, 214, 6, 191, 235, 111, 177, 255, 136, 249, 147, 171, 66, 211, 178, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6, 191, 235, 111, 177,
            255, 136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130,
            114, 230, 1, 119, 214, 6, 191, 235, 111, 177, 255, 136, 249, 147, 171, 66, 211, 178, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 130, 114, 230, 1, 119, 214, 6, 191, 235, 111,
            177, 255, 136, 249, 147, 171, 66, 211, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 233,
            90, 129, 43, 243, 205, 62, 98, 225, 128, 14, 71, 11, 180, 174, 33, 214, 121, 18, 154,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 113, 1, 244, 249, 197, 78, 31, 23, 251, 71,
            216, 59, 93, 4, 98, 116, 109, 41, 31,
        ];
        let elements_to_verify = BTreeMap::from([
            (
                3,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                11,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                18,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                23,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                43,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                48,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
            (
                58,
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
            ),
        ]);
        let commitment_hashes = CommitmentHashes::new(
            SupportedHashes::Poseidon3,
            SupportedHashes::Blake2s256Masked160Lsb,
        );
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            data,
            queries,
            elements_to_verify,
            commitment_hashes,
        );

        let size_of_element = 158;
        let n_elements = 1;
        let n_segments = 1;
        let data = vec![
            68, 215, 79, 252, 234, 215, 70, 33, 216, 200, 46, 192, 55, 79, 114, 239, 107, 105, 248,
            81, 235, 78, 50, 46, 225, 177, 103, 220, 57, 160, 26, 132, 191, 245, 10, 139, 12, 104,
            202, 67, 118, 130, 15, 121, 157, 20, 45, 101, 94, 142, 111, 115, 3, 41, 119, 118, 156,
            156, 110, 186, 122, 24, 240, 115, 157, 44, 251, 18, 28, 226, 154, 13, 88, 114, 157,
            153, 76, 113, 146, 118, 229, 228, 2, 223, 177, 125, 147, 183, 239, 74, 216, 80, 135,
            220, 174, 130, 166, 243, 122, 132, 100, 70, 72, 101, 144, 114, 192, 196, 118, 86, 192,
            159, 218, 61, 129, 76, 153, 245, 51, 130, 158, 217, 79, 35, 220, 123, 206, 183, 107,
            91, 213, 8, 86, 133, 242, 75, 213, 246, 150, 110, 211, 101, 242, 174, 112, 237, 19,
            235, 122, 40, 246, 18, 87, 27, 224, 2, 146, 109,
        ];
        let queries = BTreeSet::from([0]);
        let exp_proof = vec![
            212, 141, 127, 140, 236, 1, 122, 153, 95, 242, 159, 113, 11, 121, 162, 179, 207, 217,
            198, 211, 157, 149, 113, 156, 102, 20, 96, 214, 99, 135, 128, 58,
        ];
        let elements_to_verify = BTreeMap::from([(
            0,
            vec![
                68, 215, 79, 252, 234, 215, 70, 33, 216, 200, 46, 192, 55, 79, 114, 239, 107, 105,
                248, 81, 235, 78, 50, 46, 225, 177, 103, 220, 57, 160, 26, 132, 191, 245, 10, 139,
                12, 104, 202, 67, 118, 130, 15, 121, 157, 20, 45, 101, 94, 142, 111, 115, 3, 41,
                119, 118, 156, 156, 110, 186, 122, 24, 240, 115, 157, 44, 251, 18, 28, 226, 154,
                13, 88, 114, 157, 153, 76, 113, 146, 118, 229, 228, 2, 223, 177, 125, 147, 183,
                239, 74, 216, 80, 135, 220, 174, 130, 166, 243, 122, 132, 100, 70, 72, 101, 144,
                114, 192, 196, 118, 86, 192, 159, 218, 61, 129, 76, 153, 245, 51, 130, 158, 217,
                79, 35, 220, 123, 206, 183, 107, 91, 213, 8, 86, 133, 242, 75, 213, 246, 150, 110,
                211, 101, 242, 174, 112, 237, 19, 235, 122, 40, 246, 18, 87, 27, 224, 2, 146, 109,
            ],
        )]);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Keccak256);
        test_packaging_completeness_with(
            size_of_element,
            n_segments,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof.clone(),
            data,
            queries,
            elements_to_verify.clone(),
            commitment_hashes.clone(),
        );

        // test corrupted_proof fails
        let mut corrupted_proof = exp_proof.clone();
        corrupted_proof[10] ^= 1;
        test_verify_corrupted(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            corrupted_proof,
            elements_to_verify.clone(),
            commitment_hashes.clone(),
        );

        // test corrupted_data fails
        let mut corrupted_data: BTreeMap<usize, Vec<u8>> = elements_to_verify.clone();
        corrupted_data.get_mut(&0).map(|v| v[0] = 99);
        test_verify_corrupted(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            exp_proof,
            corrupted_data,
            commitment_hashes,
        );
    }

    fn draw_n_segments(size_of_element: usize, n_elements: usize) -> usize {
        let mut rng = rand::thread_rng();

        let total_bytes = size_of_element * n_elements;
        let max_n_segments = n_elements.min(usize::max(1, total_bytes / 64));
        let max_log_n_segments = max_n_segments.ilog2() as usize;
        if max_log_n_segments > 0 {
            1 << rng.gen_range(0..=max_log_n_segments)
        } else {
            1
        }
    }

    fn test_single_hash_with(commitment_hashes: CommitmentHashes) {
        let mut rng = rand::thread_rng();

        // Input
        let size_of_element: usize = rng.gen_range(1..=160);
        let n_elements = 1 << rng.gen_range(0..=10);
        let n_segments: usize = draw_n_segments(size_of_element, n_elements);
        let queries: BTreeSet<usize> = draw_queries(n_elements);
        let data: Vec<u8> = draw_data(size_of_element * n_elements);
        let elements_to_verify: BTreeMap<usize, Vec<u8>> =
            get_sparse_data(&data, &queries, size_of_element);

        let channel_prng = PrngKeccak256::new();

        // Prover
        let mut prover_channel: FSProverChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(channel_prng.clone());
        let n_elements_in_segment = n_elements / n_segments;
        let mut prover = make_commitment_scheme_prover(
            size_of_element,
            n_elements_in_segment,
            n_segments,
            0,
            commitment_hashes.clone(),
            1,
        );
        for i in 0..n_segments {
            let segment = {
                let n_segment_bytes = size_of_element * (n_elements / n_segments);
                &data[i * n_segment_bytes..(i + 1) * n_segment_bytes]
            };
            prover.add_segment_for_commitment(segment, i);
        }
        prover.commit(&mut prover_channel).unwrap();
        let element_idxs = prover.start_decommitment_phase(queries);
        let elements_data: Vec<u8> = element_idxs
            .iter()
            .flat_map(|&idx| &data[idx * size_of_element..(idx + 1) * size_of_element])
            .cloned()
            .collect();
        prover
            .decommit(&elements_data, &mut prover_channel)
            .unwrap();
        let proof = prover_channel.get_proof();

        // Verifier
        let mut verifier_channel: FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(channel_prng, proof);

        let mut verifier =
            make_commitment_scheme_verifier(size_of_element, n_elements, 0, commitment_hashes, 1);
        verifier.read_commitment(&mut verifier_channel).unwrap();
        assert!(verifier
            .verify_integrity(&mut verifier_channel, elements_to_verify)
            .unwrap());
    }

    #[test]
    fn test_single_hash_randomised() {
        for _ in 0..20 {
            let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Keccak256);
            test_single_hash_with(commitment_hashes);

            let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Blake2s256);
            test_single_hash_with(commitment_hashes);
        }
    }

    fn test_two_hash_with(commitment_hashes: CommitmentHashes) {
        let mut rng = rand::thread_rng();

        // Input
        let size_of_element: usize = 32;
        let n_elements = 64;
        let n_segments: usize = 4;
        let queries: BTreeSet<usize> = draw_queries(n_elements);
        let data: Vec<u8> = draw_data(size_of_element * n_elements);
        let elements_to_verify: BTreeMap<usize, Vec<u8>> =
            get_sparse_data(&data, &queries, size_of_element);
        let n_verifier_friendly_commitment_layers = rng.gen_range(2..=5);

        let channel_prng = PrngKeccak256::new();

        // Prover
        let mut prover_channel: FSProverChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(channel_prng.clone());
        let n_elements_in_segment = n_elements / n_segments;
        let mut prover = make_commitment_scheme_prover(
            size_of_element,
            n_elements_in_segment,
            n_segments,
            n_verifier_friendly_commitment_layers,
            commitment_hashes.clone(),
            1,
        );
        for i in 0..n_segments {
            let segment = {
                let n_segment_bytes = size_of_element * (n_elements / n_segments);
                &data[i * n_segment_bytes..(i + 1) * n_segment_bytes]
            };
            prover.add_segment_for_commitment(segment, i);
        }
        prover.commit(&mut prover_channel).unwrap();
        let element_idxs = prover.start_decommitment_phase(queries);
        let elements_data: Vec<u8> = element_idxs
            .iter()
            .flat_map(|&idx| &data[idx * size_of_element..(idx + 1) * size_of_element])
            .cloned()
            .collect();
        prover
            .decommit(&elements_data, &mut prover_channel)
            .unwrap();
        let proof = prover_channel.get_proof();

        // Verifier
        let mut verifier_channel: FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(channel_prng, proof);

        let mut verifier = make_commitment_scheme_verifier(
            size_of_element,
            n_elements,
            n_verifier_friendly_commitment_layers,
            commitment_hashes,
            1,
        );
        verifier.read_commitment(&mut verifier_channel).unwrap();
        assert!(verifier
            .verify_integrity(&mut verifier_channel, elements_to_verify)
            .unwrap());
    }

    #[test]
    fn test_two_hash_randomised() {
        for _ in 0..20 {
            let commitment_hashes = CommitmentHashes::new(
                SupportedHashes::Blake2s256Masked160Msb,
                SupportedHashes::Keccak256Masked160Msb,
            );
            test_two_hash_with(commitment_hashes);

            let commitment_hashes = CommitmentHashes::new(
                SupportedHashes::Keccak256Masked160Lsb,
                SupportedHashes::Blake2s256Masked160Lsb,
            );
            test_two_hash_with(commitment_hashes);

            let commitment_hashes = CommitmentHashes::new(
                SupportedHashes::Poseidon3,
                SupportedHashes::Blake2s256Masked160Lsb,
            );
            test_two_hash_with(commitment_hashes);
        }
    }
}
