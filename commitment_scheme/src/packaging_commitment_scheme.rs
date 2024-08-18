use crate::merkle::hash::{vec_to_generic_array, Hasher};
use crate::packer_hasher::PackerHasher;
use crate::{CommitmentSchemeProver, CommitmentSchemeVerifier};
use ark_ff::PrimeField;
use channel::fs_prover_channel::FSProverChannel;
use channel::fs_verifier_channel::FSVerifierChannel;
use channel::ProverChannel;
use channel::VerifierChannel;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use randomness::Prng;
use sha3::Digest;
use std::collections::HashMap;

// These closures are given as an input parameter to packaging commitment scheme prover and verifier
// (correspondingly) to enable creation of inner_commitment_scheme after creating the packer.
type PackagingCommitmentSchemeProverFactory =
    Box<dyn FnOnce(usize) -> Box<dyn CommitmentSchemeProver>>;
type PackagingCommitmentSchemeVerifierFactory =
    Box<dyn FnOnce(usize) -> Box<dyn CommitmentSchemeVerifier>>;

/// Prover of Packaging Commitment Scheme.
pub struct PackagingCommitmentSchemeProver<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    size_of_element: usize,
    n_elements_in_segment: usize,
    n_segments: usize,
    channel: FSProverChannel<F, P, W>,
    packer: PackerHasher<F, H>,
    inner_commitment_scheme: Box<dyn CommitmentSchemeProver>,
    is_merkle_layer: bool,
    queries: Vec<usize>,
    missing_element_queries: Vec<usize>,
    n_missing_elements_for_inner_layer: usize,
}

#[allow(dead_code)]
impl<F: PrimeField, H: Hasher<F, Output = GenericArray<u8, U32>>, P: Prng, W: Digest>
    PackagingCommitmentSchemeProver<F, H, P, W>
{
    pub fn new(
        size_of_element: usize,
        n_elements_in_segment: usize,
        n_segments: usize,
        channel: FSProverChannel<F, P, W>,
        inner_commitment_scheme_factory: PackagingCommitmentSchemeProverFactory,
        is_merkle_layer: bool,
    ) -> Self {
        let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
        let inner_commitment_scheme = inner_commitment_scheme_factory(packer.n_packages);

        if is_merkle_layer {
            assert!(packer.n_elements_in_package == 2);
        }

        Self {
            size_of_element,
            n_elements_in_segment,
            n_segments,
            channel,
            packer,
            inner_commitment_scheme,
            is_merkle_layer,
            queries: vec![],
            missing_element_queries: vec![],
            n_missing_elements_for_inner_layer: 0,
        }
    }

    pub fn new_with_existing(
        size_of_element: usize,
        n_elements_in_segment: usize,
        n_segments: usize,
        channel: FSProverChannel<F, P, W>,
        inner_commitment_scheme: Box<dyn CommitmentSchemeProver>,
    ) -> Self {
        let commitment_scheme = Self::new(
            size_of_element,
            n_elements_in_segment,
            n_segments,
            channel,
            Box::new(move |_: usize| inner_commitment_scheme),
            true,
        );

        assert_eq!(
            2 * commitment_scheme
                .inner_commitment_scheme
                .segment_length_in_elements(),
            n_elements_in_segment
        );

        commitment_scheme
    }

    fn get_num_of_packages(&self) -> usize {
        self.packer.n_packages
    }

    fn get_is_merkle_layer(&self) -> bool {
        self.is_merkle_layer
    }
}

impl<F: PrimeField, H: Hasher<F, Output = GenericArray<u8, U32>>, P: Prng, W: Digest>
    CommitmentSchemeProver for PackagingCommitmentSchemeProver<F, H, P, W>
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

    fn commit(&mut self) {
        self.inner_commitment_scheme.commit()
    }

    fn start_decommitment_phase(&mut self, queries: Vec<usize>) -> Vec<usize> {
        self.queries = queries;
        self.missing_element_queries = self
            .packer
            .elements_required_to_compute_hashes(&self.queries);

        let package_queries_to_inner_layer: Vec<usize> = self
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

    fn decommit(&mut self, elements_data: &[u8]) {
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
                let digest = vec_to_generic_array(bytes_to_send.to_vec());
                let _ = self.channel.send_decommit_node(digest);
            } else {
                let _ = self.channel.send_data(bytes_to_send);
            }
        }

        let start = self.missing_element_queries.len() * self.size_of_element;
        let end = start + self.n_missing_elements_for_inner_layer * self.size_of_element;
        let data_for_inner_layer = self
            .packer
            .pack_and_hash_internal(&elements_data[start..end], self.is_merkle_layer);

        self.inner_commitment_scheme.decommit(&data_for_inner_layer);
    }
}

/// Verifier of Packaging Commitment Scheme.
pub struct PackagingCommitmentSchemeVerifier<F: PrimeField, H: Hasher<F>, P: Prng, W: Digest> {
    size_of_element: usize,
    n_elements: usize,
    channel: FSVerifierChannel<F, P, W>,
    packer: PackerHasher<F, H>,
    inner_commitment_scheme: Box<dyn CommitmentSchemeVerifier>,
    is_merkle_layer: bool,
}

#[allow(dead_code)]
impl<F: PrimeField, H: Hasher<F, Output = GenericArray<u8, U32>>, P: Prng, W: Digest>
    PackagingCommitmentSchemeVerifier<F, H, P, W>
{
    /// Constructs a new PackagingCommitmentSchemeVerifier using the commitment scheme factory input.
    ///
    /// # Arguments
    ///
    /// - `size_of_element`: length of element in bytes.
    /// - `n_elements`: number of elements.
    /// - `channel`: Fiat-Shamir verifier channel
    /// - `inner_commitment_scheme_factory`: commitment scheme verifier factory
    /// - `is_merkle_layer`: flag to indicate Merkle layer.
    ///
    /// # Returns
    ///
    /// - `Self`: PackagingCommitmentSchemeVerifier
    pub fn new(
        size_of_element: usize,
        n_elements: usize,
        channel: FSVerifierChannel<F, P, W>,
        inner_commitment_scheme_factory: PackagingCommitmentSchemeVerifierFactory,
        is_merkle_layer: bool,
    ) -> Self {
        let packer = PackerHasher::new(size_of_element, n_elements);
        let inner_commitment_scheme = inner_commitment_scheme_factory(packer.n_packages);

        if is_merkle_layer {
            assert_eq!(packer.n_elements_in_package, 2);
        }

        Self {
            size_of_element,
            n_elements,
            channel,
            packer,
            inner_commitment_scheme,
            is_merkle_layer,
        }
    }

    /// Constructs a new PackagingCommitmentSchemeVerifier with the input commitment scheme verifier.
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
    pub fn new_with_existing(
        size_of_element: usize,
        n_elements: usize,
        channel: FSVerifierChannel<F, P, W>,
        inner_commitment_scheme: Box<dyn CommitmentSchemeVerifier>,
    ) -> Self {
        let commitment_scheme = Self::new(
            size_of_element,
            n_elements,
            channel,
            Box::new(move |_: usize| inner_commitment_scheme),
            true,
        );

        assert_eq!(2 * commitment_scheme.num_of_elements(), n_elements);

        commitment_scheme
    }

    fn get_num_of_packages(&self) -> usize {
        self.packer.n_packages
    }

    fn get_is_merkle_layer(&self) -> bool {
        self.is_merkle_layer
    }
}

/// Implement CommitmentSchemeVerifier trait for PackagingCommitmentSchemeVerifier
impl<F: PrimeField, H: Hasher<F, Output = GenericArray<u8, U32>>, P: Prng, W: Digest>
    CommitmentSchemeVerifier for PackagingCommitmentSchemeVerifier<F, H, P, W>
{
    fn num_of_elements(&self) -> usize {
        self.n_elements
    }

    fn read_commitment(&mut self) -> Result<(), anyhow::Error> {
        self.inner_commitment_scheme.read_commitment()
    }

    fn verify_integrity(&mut self, elements_to_verify: &[(usize, Vec<u8>)]) -> Option<bool> {
        // Get missing elements required to compute hashes
        let elements_to_verify: HashMap<usize, Vec<u8>> =
            elements_to_verify.iter().cloned().collect();
        let keys: Vec<usize> = elements_to_verify.keys().copied().collect();
        let missing_elements_idxs = self.packer.elements_required_to_compute_hashes(&keys);

        let mut full_data_to_verify = elements_to_verify.clone();

        for &missing_element_idx in &missing_elements_idxs {
            if self.is_merkle_layer {
                let result_array = self.channel.recv_decommit_node().ok()?;
                full_data_to_verify.insert(missing_element_idx, result_array.to_vec());
            } else {
                let data = self.channel.recv_data(self.size_of_element).ok()?;
                full_data_to_verify.insert(missing_element_idx, data);
            }
        }

        // Convert data to hahses
        let bytes_to_verify = self
            .packer
            .pack_and_hash(&full_data_to_verify, self.is_merkle_layer);

        self.inner_commitment_scheme
            .verify_integrity(&bytes_to_verify)
    }
}
