use ark_ff::PrimeField;

use crate::merkle::bytes_as_hash;
use crate::merkle::hash::Hasher;
use std::collections::HashMap;
use std::collections::HashSet;
use std::marker::PhantomData;

/// PackerHasher group elements together into packages, approximately the size of the hash (or larger),
/// and use these as the basic element for the tree.
pub struct PackerHasher<F: PrimeField, H: Hasher<F>> {
    pub size_of_element: usize,
    pub n_elements_in_package: usize,
    pub n_packages: usize,
    _ph: PhantomData<(F, H)>,
}

impl<F: PrimeField, H: Hasher<F, Output = Vec<u8>>> PackerHasher<F, H> {
    /// Constructs a new PackerHasher.
    ///
    /// # Arguments
    ///
    /// - `size_of_element`: length of element in bytes.
    /// - `n_elements`: number of elements.
    ///
    /// # Returns
    ///
    /// - `Self`: PackerHasher
    pub fn new(size_of_element: usize, n_elements: usize) -> Self {
        let n_elements_in_package =
            compute_num_elements_in_package(size_of_element, 2 * H::DIGEST_NUM_BYTES, n_elements);
        let n_packages = n_elements / n_elements_in_package;

        assert!(
            n_elements != 0 && (n_elements & (n_elements - 1)) == 0,
            "n_elements is not a power of two."
        );
        assert!(
            n_elements_in_package != 0
                && (n_elements_in_package & (n_elements_in_package - 1)) == 0,
            "n_elements_in_package is not a power of two."
        );
        assert!(n_elements >= n_elements_in_package);

        Self {
            size_of_element,
            n_elements_in_package,
            n_packages,
            _ph: PhantomData,
        }
    }

    /// Groups together elements into packages and returns the sequence of hashes (one has per package).
    ///
    /// # Arguments
    ///
    /// - `data`: bytes to be hashed.
    /// - `is_merkle_layer`: flag to indicate Merkle layer.
    ///
    /// # Returns
    ///
    /// Returns sequence of hashes (one has per package)
    pub fn pack_and_hash_internal(&self, data: &[u8], is_merkle_layer: bool) -> Vec<u8> {
        if data.is_empty() {
            return vec![];
        }

        let n_elements_in_data = data.len() / self.size_of_element;
        let n_packages = n_elements_in_data / self.n_elements_in_package;

        if is_merkle_layer
            || (self.n_elements_in_package == 2 && self.size_of_element == H::DIGEST_NUM_BYTES)
        {
            assert!(
                data.len() / n_packages == 2 * H::DIGEST_NUM_BYTES,
                "Data size is wrong."
            );
            return hash_elements_two_to_one::<F, H>(data);
        }

        hash_elements::<F, H>(data, n_packages)
    }

    /// Given a vector of packages, returns a vector of the indices of all elements in that package.
    /// For example, if there are 4 elements in each package and packages equals to {2,4}
    /// then the return value is {8,9,10,11,16,17,18,19}.
    ///
    /// # Arguments
    ///
    /// - `packages`: packages indices.
    ///
    /// # Returns
    ///
    /// Returns a vector of the indices of all elements in that package
    pub fn get_elements_in_packages(&self, packages: &[usize]) -> Vec<usize> {
        let mut elements_needed = Vec::with_capacity(packages.len() * self.n_elements_in_package);
        for &package in packages {
            let range =
                package * self.n_elements_in_package..(package + 1) * self.n_elements_in_package;
            elements_needed.extend(range);
        }
        elements_needed
    }

    /// Given a list of elements, returns a vector of the additional elements that the caller
    /// has to provide so that the packer can compute the set of hashes for the packages.
    ///
    /// # Arguments
    ///
    /// - `elements_known`: indices of known elements.
    ///
    /// # Returns
    ///
    /// Returns indices of elements that belong to packages but are not known.
    pub fn elements_required_to_compute_hashes(&self, elements_known: &Vec<usize>) -> Vec<usize> {
        let mut packages = Vec::new();

        // Get package indices of known_elements.
        for &el in elements_known {
            let package_id = el / self.n_elements_in_package;
            assert!(
                package_id < self.n_packages,
                "Query out of range. range: [0, {}), query: {}",
                self.n_packages,
                package_id
            );
            packages.push(package_id);
        }

        // Return only elements that belong to packages but are not known.
        let all_packages_elements = self.get_elements_in_packages(&packages);

        // Perform set difference to filter out known elements
        let set1: HashSet<usize> = all_packages_elements.into_iter().collect();
        let set2: HashSet<usize> = elements_known.iter().cloned().collect();
        let difference: HashSet<usize> = set1.difference(&set2).cloned().collect();
        let required_elements: Vec<usize> = difference.into_iter().collect();

        required_elements
    }

    /// Given numbered elements, groups them into packages, and returns a vec of [(idx, bytes)]
    /// where the first element is the package's index, and the second element is the packages's hash bytes.
    ///
    /// # Arguments
    ///
    /// - `elements`: numbered elements represented as HashMap [(idx, bytes)]
    /// - `is_merkle_layer`: flag to indicate Merkle layer.
    ///
    /// # Returns
    ///
    /// Returns a map with key as package index and value as package hash bytes.
    pub fn pack_and_hash(
        &self,
        elements: &HashMap<usize, Vec<u8>>,
        is_merkle_layer: bool,
    ) -> Vec<(usize, Vec<u8>)> {
        let mut packages = Vec::new();

        // Deduce required packages.
        for key in elements.keys() {
            packages.push(key / self.n_elements_in_package);
        }

        // Hash packages and return the results as a map of element indices with their hash values.
        let mut hashed_packages = Vec::new();
        for &package in &packages {
            let first = package * self.n_elements_in_package;
            let last = (package + 1) * self.n_elements_in_package;
            let mut packed_elements = vec![0u8; self.size_of_element * self.n_elements_in_package];

            // Hash package.
            for (i, pos) in (first..last).zip((0..).step_by(self.size_of_element)) {
                if let Some(element_data) = elements.get(&i) {
                    assert_eq!(
                        element_data.len(),
                        self.size_of_element,
                        "Element size mismatches the one declared."
                    );
                    packed_elements[pos..pos + self.size_of_element].copy_from_slice(element_data);
                }
            }

            // Store the results in the returned map.
            let hash_array = self.pack_and_hash_internal(&packed_elements, is_merkle_layer);
            hashed_packages.push((package, hash_array));
        }

        hashed_packages
    }
}

/// Computes the number elements in a package.
///
/// # Arguments
///
/// - `size_of_element`: length of element in bytes.
/// - `size_of_package`: length of package in bytes.
/// - `max_n_elements`: number of elements to be grouped in a package.
///
/// # Returns
///
/// Returns the number elements in a package.
fn compute_num_elements_in_package(
    size_of_element: usize,
    size_of_package: usize,
    max_n_elements: usize,
) -> usize {
    assert!(
        size_of_element > 0,
        "An element must be at least of length 1 byte."
    );

    if size_of_element >= size_of_package {
        return 1;
    }

    let elements_fit_in_package = (size_of_package - 1) / size_of_element + 1;
    let log2_elements_fit_in_package = (elements_fit_in_package as f64).log2().ceil() as u32;
    usize::min(1 << log2_elements_fit_in_package, max_n_elements)
}

/// Given a sequence of bytes, partitions the sequence to n_elements equal sub-sequences,
/// hashing each separately, and returning the resulting sequence of hashes as vector of bytes.
///
/// # Arguments
///
/// - `data`: bytes to be hashed.
/// - `n_elements`: number of elements.
///
/// # Returns
///
/// Returns the resulting sequence of hashes as vector of bytes.
pub fn hash_elements<F: PrimeField, H: Hasher<F, Output = Vec<u8>>>(
    data: &[u8],
    n_elements: usize,
) -> Vec<u8> {
    // If n_elements == 0 and data is empty, return an empty vector.
    if n_elements == 0 && data.is_empty() {
        return Vec::new();
    }

    let element_size = data.len() / n_elements;
    let mut res = Vec::with_capacity(n_elements * H::DIGEST_NUM_BYTES);
    let mut pos = 0;

    for _ in 0..n_elements {
        let end_pos = pos + element_size;
        let chunk = &data[pos..end_pos];
        let mut hash_as_bytes_array = H::hash_bytes(chunk).to_vec();
        res.append(&mut hash_as_bytes_array);
        pos = end_pos;
    }

    res
}

/// Given a sequence of bytes, partitions the sequence to elements and hashes each pair separately.
///
/// # Arguments
///
/// - `data`: bytes to be hashed.
///
/// # Returns
///
/// Returns the resulting sequence of hashes as vector of bytes.
pub fn hash_elements_two_to_one<F: PrimeField, H: Hasher<F, Output = Vec<u8>>>(
    data: &[u8],
) -> Vec<u8> {
    // If data is empty, return an empty vector.
    if data.is_empty() {
        return Vec::new();
    }

    // Each element in the next layer is a hash of 2 elements in the current layer.
    let elements_to_hash_size = 2 * H::DIGEST_NUM_BYTES;
    let n_elements_next_layer = data.len() / elements_to_hash_size;

    // Compute the first layer of hashes from the data.
    let bytes_as_hash = bytes_as_hash::<F, H>(data, H::DIGEST_NUM_BYTES);

    // Compute the next hash layer.
    let mut res = Vec::with_capacity(n_elements_next_layer * H::DIGEST_NUM_BYTES);
    for i in 0..n_elements_next_layer {
        let mut next_hash = H::node(&[bytes_as_hash[i * 2].clone(), bytes_as_hash[i * 2 + 1].clone()]).to_vec();
        res.append(&mut next_hash);
    }

    res
}
