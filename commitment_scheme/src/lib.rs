pub mod merkle;
pub mod packaging_commitment_scheme;
pub mod packer_hasher;
pub mod table_utils;
pub mod table_verifier;
use std::rc::Rc;
use std::vec::Vec;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use crate::merkle::hash::MaskedHash;
use crate::packer_hasher::PackerHasher;
use ark_ff::PrimeField;
use channel::{fs_prover_channel::FSProverChannel, fs_verifier_channel::FSVerifierChannel};
use merkle::hash::Poseidon3Hasher;
use merkle::{
    hash::{Blake2s256Hasher, Keccak256Hasher},
    merkle_commitment_scheme::{MerkleCommitmentSchemeProver, MerkleCommitmentSchemeVerifier},
};
use packaging_commitment_scheme::{
    PackagingCommitmentSchemeProver, PackagingCommitmentSchemeVerifier,
};
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
    fn start_decommitment_phase(&mut self, queries: BTreeSet<usize>) -> Vec<usize>;

    // Decommit to data stored in queried locations
    fn decommit(&mut self, elements_data: &[u8]);

    // Returns proof from Prover Channel
    fn get_proof(&self) -> Vec<u8>;
}

// Define the CommitmentSchemeVerifier trait
pub trait CommitmentSchemeVerifier {
    // Read the commitment
    fn read_commitment(&mut self) -> Result<(), anyhow::Error>;

    // Verify the integrity of the data
    fn verify_integrity(&mut self, elements_to_verify: BTreeMap<usize, Vec<u8>>) -> Option<bool>;

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

fn calculate_n_verifier_friendly_layers_in_segment(
    n_segments: usize,
    n_layers_in_segment: usize,
    n_verifier_friendly_commitment_layers: usize,
) -> usize {
    // No verifier-friendly commitment layers at all.
    if n_verifier_friendly_commitment_layers == 0 {
        return 0;
    }

    // The height of the top subtree with `n_segments` leaves.
    let segment_tree_height = n_segments.ilog2() as usize;
    let total_n_layers = n_layers_in_segment + segment_tree_height;

    if n_verifier_friendly_commitment_layers >= total_n_layers {
        // All layers are verifier-friendly commitment layers.
        return n_layers_in_segment;
    }

    assert!(
        n_verifier_friendly_commitment_layers >= segment_tree_height,
        "The top {} layers should use the same hash. n_verifier_friendly_commitment_layers: {}",
        segment_tree_height,
        n_verifier_friendly_commitment_layers
    );
    n_verifier_friendly_commitment_layers - segment_tree_height
}

fn create_all_commitment_scheme_layers<F, P, W>(
    _n_out_of_memory_merkle_layers: usize,
    n_elements_in_segment: usize,
    n_segments: usize,
    channel: FSProverChannel<F, P, W>,
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
) -> Box<dyn CommitmentSchemeProver>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
{
    // Create the innermost layer which holds the Merkle Tree.
    let is_verifier_friendly_layer = n_verifier_friendly_commitment_layers > 0;
    let hash_name = commitment_hashes.get_hash_name(is_verifier_friendly_layer);
    let mut next_inner_layer: Box<dyn CommitmentSchemeProver>;
    match hash_name.as_str() {
        "keccak256" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeProver::<F, Keccak256Hasher<F>, P, W>::new(
                    n_segments,
                    channel.clone(),
                ),
            )
        }
        "blake2s256" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeProver::<F, Blake2s256Hasher<F>, P, W>::new(
                    n_segments,
                    channel.clone(),
                ),
            )
        }
        &_ => unreachable!(),
    };

    let n_layers_in_segment = n_elements_in_segment.ilog2() as usize;
    // let n_in_memory_layers = n_layers_in_segment - std::cmp::min(n_out_of_memory_merkle_layers, n_layers_in_segment);

    let n_verifier_friendly_layers_in_segment = calculate_n_verifier_friendly_layers_in_segment(
        n_segments,
        n_layers_in_segment,
        n_verifier_friendly_commitment_layers,
    );
    assert!(
        n_verifier_friendly_layers_in_segment <= n_layers_in_segment,
        "n_verifier_friendly_layers_in_segment is too big"
    );

    let mut cur_n_elements_in_segment = 1;
    for layer in 0..n_layers_in_segment {
        cur_n_elements_in_segment *= 2;
        assert!(
            cur_n_elements_in_segment <= n_elements_in_segment,
            "Too many elements in a segment: {}. Should be at most: {}",
            cur_n_elements_in_segment,
            n_elements_in_segment
        );

        // Packaging commitment scheme layer.
        let is_verifier_friendly_layer = layer < n_verifier_friendly_layers_in_segment;

        let hash_name = commitment_hashes.get_hash_name(is_verifier_friendly_layer);
        match hash_name.as_str() {
            "keccak256" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeProver::<
                    F,
                    Keccak256Hasher<F>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_segment,
                    n_segments,
                    channel.clone(),
                    next_inner_layer,
                ))
            }
            "blake2s256" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeProver::<
                    F,
                    Blake2s256Hasher<F>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_segment,
                    n_segments,
                    channel.clone(),
                    next_inner_layer,
                ))
            }
            &_ => unreachable!(),
        };
    }
    next_inner_layer
}

#[allow(clippy::too_many_arguments)]
pub fn make_commitment_scheme_prover<F, P, W>(
    size_of_element: usize,
    n_elements_in_segment: usize,
    n_segments: usize,
    channel: &mut FSProverChannel<F, P, W>,
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
    n_columns: usize,
    n_out_of_memory_merkle_layers: usize,
) -> Box<dyn CommitmentSchemeProver>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
{
    // Calculate the number of layers in the segment and the total height
    let n_layers_in_segment =
        n_elements_in_segment.ilog2() as usize - if n_columns == 1 { 1 } else { 0 };
    let segment_tree_height = n_segments.ilog2() as usize;
    let total_height = n_layers_in_segment + segment_tree_height;
    let is_verifier_friendly_layer = total_height < n_verifier_friendly_commitment_layers;

    // Invoke the commitment_hashes to determine the hash function and create the commitment scheme
    let commitment_hashes_cloned = commitment_hashes.clone();
    let hash_name = commitment_hashes_cloned.get_hash_name(is_verifier_friendly_layer);
    let commitment_scheme: Box<dyn CommitmentSchemeProver>;

    let channel_clone = channel.clone();

    let inner_commitment_scheme_factory = Box::new(move |n_elements_inner_layer: usize| {
        create_all_commitment_scheme_layers(
            n_out_of_memory_merkle_layers,
            n_elements_inner_layer / n_segments,
            n_segments,
            channel_clone,
            n_verifier_friendly_commitment_layers,
            commitment_hashes,
        )
    });

    match hash_name.as_str() {
        "keccak256" => {
            commitment_scheme =
                Box::new(
                    PackagingCommitmentSchemeProver::<F, Keccak256Hasher<F>, P, W>::new(
                        size_of_element,
                        n_elements_in_segment,
                        n_segments,
                        channel.clone(),
                        inner_commitment_scheme_factory,
                        false,
                    ),
                )
        }
        "blake2s256" => {
            commitment_scheme = Box::new(PackagingCommitmentSchemeProver::<
                F,
                Blake2s256Hasher<F>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements_in_segment,
                n_segments,
                channel.clone(),
                inner_commitment_scheme_factory,
                false,
            ))
        }
        &_ => unreachable!(),
    };

    commitment_scheme
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
    channel: Rc<RefCell<FSVerifierChannel<F, P, W>>>,
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
) -> Box<dyn CommitmentSchemeVerifier>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
    // Poseidon3<F>: Hasher<F, Output = Vec<u8>>,
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

        "keccak256_masked160_msb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                P,
                W,
            >::new(cur_n_elements_in_layer, channel.clone()))
        }

        "keccak256_masked160_lsb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                P,
                W,
            >::new(cur_n_elements_in_layer, channel.clone()))
        }

        "blake2s256_masked160_msb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                P,
                W,
            >::new(cur_n_elements_in_layer, channel.clone()))
        }

        "blake2s256_masked160_lsb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                P,
                W,
            >::new(cur_n_elements_in_layer, channel.clone()))
        }

        "blake2s256" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                Blake2s256Hasher<F>,
                P,
                W,
            >::new(cur_n_elements_in_layer, channel.clone()))
        }

        "poseidon3" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeVerifier::<F, Poseidon3Hasher<F>, P, W>::new(
                    cur_n_elements_in_layer,
                    channel.clone(),
                ),
            )
        }

        &_ => unreachable!(),
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

            "keccak256_masked160_msb" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_layer,
                    channel.clone(),
                    next_inner_layer,
                ))
            }

            "keccak256_masked160_lsb" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_layer,
                    channel.clone(),
                    next_inner_layer,
                ))
            }

            "blake2s256_masked160_msb" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_layer,
                    channel.clone(),
                    next_inner_layer,
                ))
            }

            "blake2s256_masked160_lsb" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
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

            "poseidon3" => {
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    Poseidon3Hasher<F>,
                    P,
                    W,
                >::new_with_existing(
                    32,
                    cur_n_elements_in_layer,
                    channel.clone(),
                    next_inner_layer,
                ))
            }

            &_ => unreachable!(),
        };
    }

    next_inner_layer
}

pub fn make_commitment_scheme_verifier<F, P, W>(
    size_of_element: usize,
    n_elements: usize,
    channel: Rc<RefCell<FSVerifierChannel<F, P, W>>>,
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
    n_columns: usize,
) -> Box<dyn CommitmentSchemeVerifier>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
{
    let n_layers = if n_elements == 1 {
        0
    } else {
        n_elements.ilog2() as usize - if n_columns == 1 { 1 } else { 0 }
    };
    let is_verifier_friendly_layer = n_layers < n_verifier_friendly_commitment_layers;

    let hashes = commitment_hashes.clone();
    let hash_name = hashes.get_hash_name(is_verifier_friendly_layer);

    let commitment_scheme: Box<dyn CommitmentSchemeVerifier> = match hash_name.as_str() {
        "keccak256" => {
            let packer: PackerHasher<F, Keccak256Hasher<F>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                channel.clone(),
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                Keccak256Hasher<F>,
                P,
                W,
            >::new_test(
                size_of_element,
                n_elements,
                channel.clone(),
                false,
                packer,
                inner_commitment_scheme,
            ))
        }

        "keccak256_masked160_msb" => {
            let packer: PackerHasher<F, MaskedHash<F, Keccak256Hasher<F>, 20, true>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                channel.clone(),
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                P,
                W,
            >::new_test(
                size_of_element,
                n_elements,
                channel.clone(),
                false,
                packer,
                inner_commitment_scheme,
            ))
        }

        "keccak256_masked160_lsb" => {
            let packer: PackerHasher<F, MaskedHash<F, Keccak256Hasher<F>, 20, false>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                channel.clone(),
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                P,
                W,
            >::new_test(
                size_of_element,
                n_elements,
                channel.clone(),
                false,
                packer,
                inner_commitment_scheme,
            ))
        }

        "blake2s256_masked160_msb" => {
            let packer: PackerHasher<F, MaskedHash<F, Blake2s256Hasher<F>, 20, true>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                channel.clone(),
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                P,
                W,
            >::new_test(
                size_of_element,
                n_elements,
                channel.clone(),
                false,
                packer,
                inner_commitment_scheme,
            ))
        }

        "blake2s256_masked160_lsb" => {
            let packer: PackerHasher<F, MaskedHash<F, Blake2s256Hasher<F>, 20, false>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                channel.clone(),
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                P,
                W,
            >::new_test(
                size_of_element,
                n_elements,
                channel.clone(),
                false,
                packer,
                inner_commitment_scheme,
            ))
        }

        "blake2s256" => {
            let packer: PackerHasher<F, Blake2s256Hasher<F>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                channel.clone(),
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                Blake2s256Hasher<F>,
                P,
                W,
            >::new_test(
                size_of_element,
                n_elements,
                channel.clone(),
                false,
                packer,
                inner_commitment_scheme,
            ))
        }

        "poseidon3" => {
            let packer: PackerHasher<F, Poseidon3Hasher<F>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                channel.clone(),
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                Poseidon3Hasher<F>,
                P,
                W,
            >::new_test(
                size_of_element,
                n_elements,
                channel.clone(),
                false,
                packer,
                inner_commitment_scheme,
            ))
        }

        &_ => unreachable!(),
    };

    commitment_scheme
}

mod tests {

    use channel::ProverChannel;
    use merkle::hash::Hasher;
    use randomness::keccak256::PrngKeccak256;
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use super::*;

    #[allow(dead_code)]
    pub trait CommitmentSchemePair<F: PrimeField, P: Prng, W: Digest> {
        type Prover: CommitmentSchemeProver;
        type Verifier: CommitmentSchemeVerifier;
        type Hash: Hasher<F>;

        fn create_prover(
            prover_channel: FSProverChannel<F, P, W>,
            size_of_element: usize,
            n_elements_in_segment: usize,
            n_segments: usize,
            n_layers: usize,
            n_verifier_friendly_commitment_layers: usize,
        ) -> Self::Prover;

        fn create_verifier(
            verifier_channel: Rc<RefCell<FSVerifierChannel<F, P, W>>>,
            size_of_element: usize,
            n_elements: usize,
            n_verifier_friendly_commitment_layers: usize,
        ) -> Self::Verifier;

        fn draw_size_of_element(prng: &mut PrngKeccak256) -> usize;

        const IS_MERKLE: bool;
        const MIN_ELEMENT_SIZE: usize;
    }

    pub struct MerkleCommitmentSchemePair<F: PrimeField, H: Hasher<F>> {
        _ph: PhantomData<(F, H)>,
    }

    impl<F: PrimeField, H: Hasher<F, Output = Vec<u8>>, P: Prng, W: Digest>
        CommitmentSchemePair<F, P, W> for MerkleCommitmentSchemePair<F, H>
    {
        // Define Prover and Verifier types
        type Hash = H;
        type Prover = MerkleCommitmentSchemeProver<F, H, P, W>;
        type Verifier = MerkleCommitmentSchemeVerifier<F, H, P, W>;

        // CreateProver function
        fn create_prover(
            prover_channel: FSProverChannel<F, P, W>,
            _size_of_element: usize,
            n_elements_in_segment: usize,
            n_segments: usize,
            _n_layers: usize,
            _n_verifier_friendly_commitment_layers: usize,
        ) -> Self::Prover {
            assert!(n_elements_in_segment == 1);

            Self::Prover::new(n_segments, prover_channel)
        }

        // CreateVerifier function
        fn create_verifier(
            verifier_channel: Rc<RefCell<FSVerifierChannel<F, P, W>>>,
            _size_of_element: usize,
            n_elements: usize,
            _n_verifier_friendly_commitment_layers: usize,
        ) -> Self::Verifier {
            Self::Verifier::new(n_elements, verifier_channel)
        }

        // DrawSizeOfElement function
        fn draw_size_of_element(_prng: &mut PrngKeccak256) -> usize {
            H::DIGEST_NUM_BYTES
        }

        // Static constants
        const IS_MERKLE: bool = true;
        const MIN_ELEMENT_SIZE: usize = H::DIGEST_NUM_BYTES;
    }

    #[allow(dead_code)]
    pub struct CommitmentScheme<F: PrimeField, P: Prng, W: Digest, T: CommitmentSchemePair<F, P, W>> {
        channel_prng: P,
        size_of_element: usize,
        n_elements: usize,
        n_segments: usize,
        data: Vec<u8>,
        queries: BTreeSet<usize>,
        n_verifier_friendly_commitment_layers: usize,
        _marker: std::marker::PhantomData<(F, P, W, T)>,
    }

    #[allow(dead_code)]
    impl<F: PrimeField, P: Prng + Clone, W: Digest + Clone, T: CommitmentSchemePair<F, P, W>>
        CommitmentScheme<F, P, W, T>
    {
        pub fn new(
            channel_prng: P,
            n_elements: usize,
            n_segments: usize,
            data: Vec<u8>,
            queries: BTreeSet<usize>,
            n_verifier_friendly_commitment_layers: usize,
        ) -> Self {
            let size_of_element = T::Hash::DIGEST_NUM_BYTES;
            CommitmentScheme {
                channel_prng,
                size_of_element,
                n_elements,
                n_segments,
                data,
                queries,
                n_verifier_friendly_commitment_layers,
                _marker: std::marker::PhantomData,
            }
        }

        pub fn get_prover_channel(&self) -> FSProverChannel<F, P, W> {
            FSProverChannel::new(self.channel_prng.clone())
        }

        pub fn get_verifier_channel(
            &self,
            proof: &[u8],
        ) -> Rc<RefCell<FSVerifierChannel<F, P, W>>> {
            Rc::new(RefCell::new(FSVerifierChannel::new(
                self.channel_prng.clone(),
                proof.to_vec(),
            )))
        }

        fn get_num_segments(&self) -> usize {
            self.n_segments
        }

        fn get_num_elements_in_segment(&self) -> usize {
            self.n_elements / self.n_segments
        }

        fn get_segment(&self, index: usize) -> &[u8] {
            let n_segment_bytes = self.size_of_element * self.get_num_elements_in_segment();
            &self.data[index * n_segment_bytes..(index + 1) * n_segment_bytes]
        }

        fn get_element(&self, index: usize) -> &[u8] {
            &self.data[index * self.size_of_element..(index + 1) * self.size_of_element]
        }

        pub fn get_sparse_data(&self) -> HashMap<usize, Vec<u8>> {
            self.queries
                .iter()
                .map(|&q| (q, self.get_element(q).to_vec()))
                .collect()
        }

        pub fn generate_proof(
            &self,
            n_out_of_memory_layers: usize,
            include_decommitment: bool,
        ) -> Vec<u8> {
            let prover_channel = self.get_prover_channel();
            let mut committer = T::create_prover(
                prover_channel.clone(),
                self.size_of_element,
                self.get_num_elements_in_segment(),
                self.n_segments,
                n_out_of_memory_layers,
                self.n_verifier_friendly_commitment_layers,
            );

            for i in 0..self.n_segments {
                let segment = self.get_segment(i);
                committer.add_segment_for_commitment(segment, i);
            }
            committer.commit();

            if include_decommitment {
                let element_idxs = committer.start_decommitment_phase(self.queries.clone());
                let elements_data: Vec<u8> = element_idxs
                    .iter()
                    .flat_map(|&idx| self.get_element(idx))
                    .cloned()
                    .collect();
                committer.decommit(&elements_data);
            }

            prover_channel.get_proof()
        }

        pub fn verify_proof(
            &self,
            proof: &[u8],
            elements_to_verify: BTreeMap<usize, Vec<u8>>,
        ) -> bool {
            let verifier_channel = self.get_verifier_channel(proof);
            let mut verifier = T::create_verifier(
                verifier_channel,
                self.size_of_element,
                self.n_elements,
                self.n_verifier_friendly_commitment_layers,
            );

            let _ = verifier.read_commitment();
            verifier.verify_integrity(elements_to_verify).unwrap()
        }
    }
}
