pub mod merkle;
pub mod packaging_commitment_scheme;
pub mod packer_hasher;
use std::vec::Vec;

use ark_ff::PrimeField;
use channel::fs_verifier_channel::FSVerifierChannel;
use merkle::{
    hash::{Blake2s256Hasher, Keccak256Hasher},
    merkle_commitment_scheme::MerkleCommitmentSchemeVerifier,
};
use packaging_commitment_scheme::PackagingCommitmentSchemeVerifier;
use randomness::Prng;
use sha3::Digest;

// Define the CommitmentSchemeProver trait
pub trait CommitmentSchemeProver {
    // Return the number of segments
    fn num_segments(&self) -> usize;

    // Return the segment length, measured in elements
    fn segment_length_in_elements(&self) -> usize;

    // Return the size of an element, measured in bytes
    fn element_length_in_bytes(&self) -> usize;

    // Add a segment for commitment
    fn add_segment_for_commitment(&mut self, segment_data: &[u8], segment_index: usize);

    // Commit to the data
    fn commit(&mut self);

    // Start the decommitment phase
    fn start_decommitment_phase(&mut self, queries: Vec<usize>) -> Vec<usize>;

    // Decommit to data stored in queried locations
    fn decommit(&mut self, elements_data: &[u8]);
}

// Define the CommitmentSchemeVerifier trait
pub trait CommitmentSchemeVerifier {
    // Read the commitment
    fn read_commitment(&mut self) -> Result<(), anyhow::Error>;

    // Verify the integrity of the data
    fn verify_integrity(&mut self, elements_to_verify: &[(usize, Vec<u8>)]) -> Option<bool>;

    // Return the total number of elements in the current layer
    fn num_of_elements(&self) -> usize;
}

// Commitment hashes containing top and bottom hash strings
#[derive(Debug, Clone)]
pub struct CommitmentHashes {
    top_hash: String,
    bottom_hash: String,
}

impl CommitmentHashes {
    // Constructor taking two hashes
    pub fn new(top_hash: String, bottom_hash: String) -> Self {
        Self {
            top_hash,
            bottom_hash,
        }
    }

    // Constructor taking a single hash and using it for both top and bottom
    pub fn from_single_hash(hash: String) -> Self {
        Self::new(hash.clone(), hash)
    }

    // Method to get the hash name based on `is_top_hash_layer`
    fn get_hash_name(&self, is_top_hash_layer: bool) -> &String {
        if is_top_hash_layer {
            &self.top_hash
        } else {
            &self.bottom_hash
        }
    }
}

/// Creates log(n_elements) + 1 commitment scheme layers for verification.
/// Each layer is the inner layer of the next one. Returns the outermost layer.
///
/// # Arguments
///
/// - `n_elements`: number of elements
/// - `channel`: Fiat-Shamir verifier channel
/// - `n_verifier_friendly_commitment_layers`: number of verifier friendly commitmnet layers
/// - `commitment_hashes`: top and bottom hash string
///
/// # Returns
///
/// Returns the outermost commitmnet layer.
pub fn create_commitment_scheme_verifier_layers<F, P, W>(
    n_elements: usize,
    channel: FSVerifierChannel<F, P, W>,
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
) -> Box<dyn CommitmentSchemeVerifier>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
{
    let n_layers = n_elements.ilog2() as usize;
    let n_verifier_friendly_layers = std::cmp::min(n_layers, n_verifier_friendly_commitment_layers);

    let mut cur_n_elements_in_layer = 1;
    let is_top_hash = n_verifier_friendly_layers > 0;
    let hash_name = commitment_hashes.get_hash_name(is_top_hash);

    let mut next_inner_layer: Box<dyn CommitmentSchemeVerifier>;
    match hash_name.as_str() {
        "keccak256" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeVerifier::<F, Keccak256Hasher<F>, P, W>::new(
                    cur_n_elements_in_layer,
                    channel.clone(),
                ),
            )
        }
        "blake2s256" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                Blake2s256Hasher<F>,
                P,
                W,
            >::new(cur_n_elements_in_layer, channel.clone()))
        }
        &_ => todo!(),
    };

    for i in 0..n_layers {
        cur_n_elements_in_layer *= 2;
        assert!(cur_n_elements_in_layer <= n_elements);

        let is_top_hash = i < n_verifier_friendly_layers;
        let hash_name = commitment_hashes.get_hash_name(is_top_hash);

        match hash_name.as_str() {
            "keccak256" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    Keccak256Hasher<F>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_layer,
                    channel.clone(),
                    next_inner_layer,
                ))
            }
            "blake2s256" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    Blake2s256Hasher<F>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_layer,
                    channel.clone(),
                    next_inner_layer,
                ))
            }
            &_ => todo!(),
        };
    }

    next_inner_layer
}

pub fn make_commitment_scheme_verifier<F, P, W>(
    size_of_element: usize,
    n_elements: usize,
    channel: FSVerifierChannel<F, P, W>,
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
    n_columns: usize,
) -> Box<dyn CommitmentSchemeVerifier>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
{
    let n_layers = n_elements.ilog2() as usize - if n_columns == 1 { 1 } else { 0 };
    let is_verifier_friendly_layer = n_layers < n_verifier_friendly_commitment_layers;

    let hashes = commitment_hashes.clone();
    let hash_name = hashes.get_hash_name(is_verifier_friendly_layer);

    let channel_clone = channel.clone();

    let inner_commitment_scheme_factory = Box::new(move |n_elements_inner_layer: usize| {
        create_commitment_scheme_verifier_layers(
            n_elements_inner_layer,
            channel_clone,
            n_verifier_friendly_commitment_layers,
            commitment_hashes.clone(),
        )
    });

    let commitment_scheme: Box<dyn CommitmentSchemeVerifier> = match hash_name.as_str() {
        "keccak256" => Box::new(PackagingCommitmentSchemeVerifier::<
            F,
            Keccak256Hasher<F>,
            P,
            W,
        >::new(
            size_of_element,
            n_elements,
            channel.clone(),
            inner_commitment_scheme_factory,
            false,
        )),
        "blake2s256" => Box::new(PackagingCommitmentSchemeVerifier::<
            F,
            Blake2s256Hasher<F>,
            P,
            W,
        >::new(
            size_of_element,
            n_elements,
            channel.clone(),
            inner_commitment_scheme_factory,
            false,
        )),
        &_ => todo!(),
    };

    commitment_scheme
}
