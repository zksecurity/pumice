pub mod merkle;
pub mod packaging_commitment_scheme;
pub mod packer_hasher;
pub mod table_prover;
pub mod table_utils;
pub mod table_verifier;
use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;

use crate::merkle::hash::MaskedHash;
use crate::packer_hasher::PackerHasher;
use anyhow::Error;
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
pub trait CommitmentSchemeProver<F: PrimeField, P: Prng, W: Digest> {
    // Return the number of segments
    fn num_segments(&self) -> usize;

    // Return the segment length, measured in elements
    fn segment_length_in_elements(&self) -> usize;

    // Return the size of an element, measured in bytes
    fn element_length_in_bytes(&self) -> usize;

    // Add a segment for commitment
    fn add_segment_for_commitment(&mut self, segment_data: &[u8], segment_index: usize);

    // Commit to the data
    fn commit(&mut self, channel: &mut FSProverChannel<F, P, W>) -> Result<(), Error>;

    // Start the decommitment phase
    fn start_decommitment_phase(&mut self, queries: BTreeSet<usize>) -> Vec<usize>;

    // Decommit to data stored in queried locations
    fn decommit(
        &mut self,
        elements_data: &[u8],
        channel: &mut FSProverChannel<F, P, W>,
    ) -> Result<(), Error>;

    // Returns proof from Prover Channel
    fn get_proof(&self, channel: &mut FSProverChannel<F, P, W>) -> Vec<u8>;
}

// Define the CommitmentSchemeVerifier trait
pub trait CommitmentSchemeVerifier<F: PrimeField, P: Prng, W: Digest> {
    // Read the commitment
    fn read_commitment(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
    ) -> Result<(), anyhow::Error>;

    // Verify the integrity of the data
    fn verify_integrity(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
        elements_to_verify: BTreeMap<usize, Vec<u8>>,
    ) -> Result<bool, Error>;

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
    n_elements_in_segment: usize,
    n_segments: usize,
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
) -> Box<dyn CommitmentSchemeProver<F, P, W>>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
{
    // Create the innermost layer which holds the Merkle Tree.
    let is_verifier_friendly_layer = n_verifier_friendly_commitment_layers > 0;
    let hash_name = commitment_hashes.get_hash_name(is_verifier_friendly_layer);
    let mut next_inner_layer: Box<dyn CommitmentSchemeProver<F, P, W>>;
    match hash_name.as_str() {
        "keccak256" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeProver::<F, Keccak256Hasher<F>, P, W>::new(n_segments),
            )
        }
        "keccak256_masked160_msb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeProver::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                P,
                W,
            >::new(n_segments))
        }
        "keccak256_masked160_lsb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeProver::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                P,
                W,
            >::new(n_segments))
        }
        "blake2s256" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeProver::<F, Blake2s256Hasher<F>, P, W>::new(n_segments),
            )
        }
        "blake2s256_masked160_msb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeProver::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                P,
                W,
            >::new(n_segments))
        }
        "blake2s256_masked160_lsb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeProver::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                P,
                W,
            >::new(n_segments))
        }
        "poseidon3" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeProver::<F, Poseidon3Hasher<F>, P, W>::new(n_segments),
            )
        }
        &_ => unreachable!(),
    };

    let n_layers_in_segment = n_elements_in_segment.ilog2() as usize;

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
                let packer = PackerHasher::new(32, n_segments * cur_n_elements_in_segment);
                next_inner_layer =
                    Box::new(
                        PackagingCommitmentSchemeProver::<F, Keccak256Hasher<F>, P, W>::new(
                            32,
                            cur_n_elements_in_segment,
                            n_segments,
                            packer,
                            next_inner_layer,
                            true,
                        ),
                    )
            }
            "keccak256_masked160_msb" => {
                let packer = PackerHasher::new(32, n_segments * cur_n_elements_in_segment);
                next_inner_layer = Box::new(PackagingCommitmentSchemeProver::<
                    F,
                    MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_segment,
                    n_segments,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }
            "keccak256_masked160_lsb" => {
                let packer = PackerHasher::new(32, n_segments * cur_n_elements_in_segment);
                next_inner_layer = Box::new(PackagingCommitmentSchemeProver::<
                    F,
                    MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_segment,
                    n_segments,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }
            "blake2s256" => {
                let packer = PackerHasher::new(32, n_segments * cur_n_elements_in_segment);
                next_inner_layer = Box::new(PackagingCommitmentSchemeProver::<
                    F,
                    Blake2s256Hasher<F>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_segment,
                    n_segments,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }
            "blake2s256_masked160_msb" => {
                let packer = PackerHasher::new(32, n_segments * cur_n_elements_in_segment);
                next_inner_layer = Box::new(PackagingCommitmentSchemeProver::<
                    F,
                    MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_segment,
                    n_segments,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }
            "blake2s256_masked160_lsb" => {
                let packer = PackerHasher::new(32, n_segments * cur_n_elements_in_segment);
                next_inner_layer = Box::new(PackagingCommitmentSchemeProver::<
                    F,
                    MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_segment,
                    n_segments,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }
            "poseidon3" => {
                let packer = PackerHasher::new(32, n_segments * cur_n_elements_in_segment);
                next_inner_layer =
                    Box::new(
                        PackagingCommitmentSchemeProver::<F, Poseidon3Hasher<F>, P, W>::new(
                            32,
                            cur_n_elements_in_segment,
                            n_segments,
                            packer,
                            next_inner_layer,
                            true,
                        ),
                    )
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
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
    n_columns: usize,
) -> Box<dyn CommitmentSchemeProver<F, P, W>>
where
    F: PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
{
    // Calculate the number of layers in the segment and the total height
    let n_layers_in_segment = if n_elements_in_segment == 1 {
        0
    } else {
        n_elements_in_segment.ilog2() as usize - if n_columns == 1 { 1 } else { 0 }
    };

    let segment_tree_height = n_segments.ilog2() as usize;
    let total_height = n_layers_in_segment + segment_tree_height;
    let is_verifier_friendly_layer = total_height < n_verifier_friendly_commitment_layers;

    // Invoke the commitment_hashes to determine the hash function and create the commitment scheme
    let commitment_hashes_cloned = commitment_hashes.clone();
    let hash_name = commitment_hashes_cloned.get_hash_name(is_verifier_friendly_layer);

    let commitment_scheme: Box<dyn CommitmentSchemeProver<F, P, W>> = match hash_name.as_str() {
        "keccak256" => {
            let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
            let inner_commitment_scheme = create_all_commitment_scheme_layers(
                packer.n_packages / n_segments,
                n_segments,
                n_verifier_friendly_commitment_layers,
                commitment_hashes,
            );
            Box::new(
                PackagingCommitmentSchemeProver::<F, Keccak256Hasher<F>, P, W>::new(
                    size_of_element,
                    n_elements_in_segment,
                    n_segments,
                    packer,
                    inner_commitment_scheme,
                    false,
                ),
            )
        }
        "keccak256_masked160_msb" => {
            let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
            let inner_commitment_scheme = create_all_commitment_scheme_layers(
                packer.n_packages / n_segments,
                n_segments,
                n_verifier_friendly_commitment_layers,
                commitment_hashes,
            );
            Box::new(PackagingCommitmentSchemeProver::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements_in_segment,
                n_segments,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }
        "keccak256_masked160_lsb" => {
            let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
            let inner_commitment_scheme = create_all_commitment_scheme_layers(
                packer.n_packages / n_segments,
                n_segments,
                n_verifier_friendly_commitment_layers,
                commitment_hashes,
            );
            Box::new(PackagingCommitmentSchemeProver::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements_in_segment,
                n_segments,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }
        "blake2s256" => {
            let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
            let inner_commitment_scheme = create_all_commitment_scheme_layers(
                packer.n_packages / n_segments,
                n_segments,
                n_verifier_friendly_commitment_layers,
                commitment_hashes,
            );
            Box::new(PackagingCommitmentSchemeProver::<
                F,
                Blake2s256Hasher<F>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements_in_segment,
                n_segments,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }
        "blake2s256_masked160_msb" => {
            let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
            let inner_commitment_scheme = create_all_commitment_scheme_layers(
                packer.n_packages / n_segments,
                n_segments,
                n_verifier_friendly_commitment_layers,
                commitment_hashes,
            );
            Box::new(PackagingCommitmentSchemeProver::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements_in_segment,
                n_segments,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }
        "blake2s256_masked160_lsb" => {
            let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
            let inner_commitment_scheme = create_all_commitment_scheme_layers(
                packer.n_packages / n_segments,
                n_segments,
                n_verifier_friendly_commitment_layers,
                commitment_hashes,
            );
            Box::new(PackagingCommitmentSchemeProver::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements_in_segment,
                n_segments,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }
        "poseidon3" => {
            let packer = PackerHasher::new(size_of_element, n_segments * n_elements_in_segment);
            let inner_commitment_scheme = create_all_commitment_scheme_layers(
                packer.n_packages / n_segments,
                n_segments,
                n_verifier_friendly_commitment_layers,
                commitment_hashes,
            );

            Box::new(
                PackagingCommitmentSchemeProver::<F, Poseidon3Hasher<F>, P, W>::new(
                    size_of_element,
                    n_elements_in_segment,
                    n_segments,
                    packer,
                    inner_commitment_scheme,
                    false,
                ),
            )
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
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
) -> Box<dyn CommitmentSchemeVerifier<F, P, W>>
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

    let mut next_inner_layer: Box<dyn CommitmentSchemeVerifier<F, P, W>>;
    match hash_name.as_str() {
        "keccak256" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeVerifier::<F, Keccak256Hasher<F>, P, W>::new(
                    cur_n_elements_in_layer,
                ),
            )
        }

        "keccak256_masked160_msb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                P,
                W,
            >::new(cur_n_elements_in_layer))
        }

        "keccak256_masked160_lsb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                P,
                W,
            >::new(cur_n_elements_in_layer))
        }

        "blake2s256_masked160_msb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                P,
                W,
            >::new(cur_n_elements_in_layer))
        }

        "blake2s256_masked160_lsb" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                P,
                W,
            >::new(cur_n_elements_in_layer))
        }

        "blake2s256" => {
            next_inner_layer = Box::new(MerkleCommitmentSchemeVerifier::<
                F,
                Blake2s256Hasher<F>,
                P,
                W,
            >::new(cur_n_elements_in_layer))
        }

        "poseidon3" => {
            next_inner_layer = Box::new(
                MerkleCommitmentSchemeVerifier::<F, Poseidon3Hasher<F>, P, W>::new(
                    cur_n_elements_in_layer,
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
                let packer = PackerHasher::new(32, cur_n_elements_in_layer);
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    Keccak256Hasher<F>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_layer,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }

            "keccak256_masked160_msb" => {
                let packer = PackerHasher::new(32, cur_n_elements_in_layer);
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_layer,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }

            "keccak256_masked160_lsb" => {
                let packer = PackerHasher::new(32, cur_n_elements_in_layer);
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_layer,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }

            "blake2s256_masked160_msb" => {
                let packer = PackerHasher::new(32, cur_n_elements_in_layer);
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_layer,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }

            "blake2s256_masked160_lsb" => {
                let packer = PackerHasher::new(32, cur_n_elements_in_layer);
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_layer,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }

            "blake2s256" => {
                let packer = PackerHasher::new(32, cur_n_elements_in_layer);
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    Blake2s256Hasher<F>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_layer,
                    packer,
                    next_inner_layer,
                    true,
                ))
            }

            "poseidon3" => {
                let packer = PackerHasher::new(32, cur_n_elements_in_layer);
                next_inner_layer = Box::new(PackagingCommitmentSchemeVerifier::<
                    F,
                    Poseidon3Hasher<F>,
                    P,
                    W,
                >::new(
                    32,
                    cur_n_elements_in_layer,
                    packer,
                    next_inner_layer,
                    true,
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
    n_verifier_friendly_commitment_layers: usize,
    commitment_hashes: CommitmentHashes,
    n_columns: usize,
) -> Box<dyn CommitmentSchemeVerifier<F, P, W>>
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

    let commitment_scheme: Box<dyn CommitmentSchemeVerifier<F, P, W>> = match hash_name.as_str() {
        "keccak256" => {
            let packer: PackerHasher<F, Keccak256Hasher<F>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                Keccak256Hasher<F>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }

        "keccak256_masked160_msb" => {
            let packer: PackerHasher<F, MaskedHash<F, Keccak256Hasher<F>, 20, true>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, true>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }

        "keccak256_masked160_lsb" => {
            let packer: PackerHasher<F, MaskedHash<F, Keccak256Hasher<F>, 20, false>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Keccak256Hasher<F>, 20, false>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }

        "blake2s256_masked160_msb" => {
            let packer: PackerHasher<F, MaskedHash<F, Blake2s256Hasher<F>, 20, true>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, true>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }

        "blake2s256_masked160_lsb" => {
            let packer: PackerHasher<F, MaskedHash<F, Blake2s256Hasher<F>, 20, false>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                MaskedHash<F, Blake2s256Hasher<F>, 20, false>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }

        "blake2s256" => {
            let packer: PackerHasher<F, Blake2s256Hasher<F>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                Blake2s256Hasher<F>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }

        "poseidon3" => {
            let packer: PackerHasher<F, Poseidon3Hasher<F>> =
                PackerHasher::new(size_of_element, n_elements);

            let inner_commitment_scheme = create_commitment_scheme_verifier_layers(
                packer.n_packages,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
            );

            Box::new(PackagingCommitmentSchemeVerifier::<
                F,
                Poseidon3Hasher<F>,
                P,
                W,
            >::new(
                size_of_element,
                n_elements,
                packer,
                inner_commitment_scheme,
                false,
            ))
        }

        &_ => unreachable!(),
    };

    commitment_scheme
}
