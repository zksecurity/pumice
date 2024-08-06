pub mod hash;
use crate::merkle::hash::Hasher;
use thiserror::Error;

use std::{collections::VecDeque, marker::PhantomData};

use ark_ff::PrimeField;

#[allow(dead_code)]
pub struct MerkleTree<F: PrimeField, H: Hasher<F>> {
    levels: usize,
    leaves: usize,
    root: H::Output,
    nodes: Vec<H::Output>,
    _ph: PhantomData<F>,
}

impl<F: PrimeField, H: Hasher<F>> MerkleTree<F, H> {
    /// Constructs a new MerkleTree with data.
    ///
    /// # Arguments
    ///
    /// - `data`: array of hash outputs
    ///
    /// # Returns
    ///
    /// - `Self`: MerkleTree which commits on the input data
    pub fn new(data: &[H::Output]) -> Self {
        let num_leaves = data.len();

        // assert num_leaves is a power of 2
        assert!(
            num_leaves != 0 && (num_leaves & (num_leaves - 1)) == 0,
            "Number of leaves is not a power of two"
        );

        let height: usize = num_leaves.ilog2() as usize;

        // for better indexing, use an array that has one extra cell at the beginning
        let mut nodes: Vec<H::Output> = vec![H::Output::default(); 2 * num_leaves];

        // copy given data to the leaves of the tree
        nodes.splice(num_leaves.., data.to_vec());

        // Hash to compute all parent nodes
        let mut cur = num_leaves / 2;
        for i in (0..height).rev() {
            let num_nodes = 1 << i;
            for j in cur..(cur + num_nodes) {
                nodes[j] = H::node(&[nodes[2 * j].clone(), nodes[2 * j + 1].clone()]);
            }
            cur /= 2
        }

        Self {
            levels: height,
            leaves: num_leaves,
            root: nodes[1].clone(),
            nodes,
            _ph: PhantomData,
        }
    }
}

impl<F: PrimeField, H: Hasher<F>> MerkleTree<F, H> {
    /// Verifies a batched Merkle-tree decommitment.
    ///
    /// # Arguments
    ///
    /// - `comm`: the commitment to the Merkle-tree
    /// - `to_verify`: a set of (position, hash) pairs to verify
    /// - `siblings`: an advice stream of sibling nodes
    ///
    /// # Returns
    ///
    /// Returns an error type for easier "monadic style" chaining.
    pub fn verify_decommitment(
        &self,
        comm: H::Output,
        to_verify: &[(usize, H::Output)],
    ) -> Result<bool, MerkleError> {
        assert!(!to_verify.is_empty(), "Empty verify queries");

        let queries_idx: Vec<usize> = to_verify.iter().map(|&(x, _)| x).collect();
        let siblings = self
            .generate_decommitment(&queries_idx)
            .ok_or(MerkleError::InvalidQuery)?;
        if self
            .root_decommitment(to_verify, siblings.into_iter())
            .ok_or(MerkleError::VerificationFail)?
            == comm
        {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Generates siblings from input query indices.
    ///
    /// # Arguments
    ///
    /// - `queries_idx`: an array of [position] to query
    ///
    /// # Returns
    ///
    /// - `Some(sib)`: vector of sibling hashes
    fn generate_decommitment(&self, queries_idx: &[usize]) -> Option<Vec<H::Output>> {
        // initialize the queue with the query leaves and fix offset
        let mut queue: VecDeque<usize> = queries_idx
            .iter()
            .cloned()
            .map(|idx| {
                assert!(idx < self.leaves, "query out of range");
                idx + self.leaves
            })
            .collect();

        let mut sib: Vec<H::Output> = vec![];
        let mut node_idx = queue.pop_front()?;
        while node_idx != 1 {
            queue.push_back(node_idx / 2);
            let sib_node_idx = node_idx ^ 1;

            if queue.front() == Some(&sib_node_idx) {
                // next node is the sibling, skip it
                queue.pop_front();
            } else {
                // next node is not the sibling, push sibling from tree nodes
                sib.push(self.nodes[sib_node_idx].clone());
            }

            node_idx = queue.pop_front()?;
        }

        Some(sib)
    }

    /// Computes the root of a batched Merkle-tree decommitment.
    ///
    /// # Arguments
    ///
    /// - `to_verify`: a set of (position, hash) pairs to verify
    /// - `siblings`: an advice stream of sibling nodes
    ///
    /// # Returns
    ///
    /// - `Some(root)`: the recomputed root of the decommitment
    /// - `None`: if the decommitment is invalid
    fn root_decommitment(
        &self,
        to_verify: &[(usize, H::Output)], // the positions to verify
        mut siblings: impl Iterator<Item = H::Output>, // an advice stream of siblings
    ) -> Option<H::Output> {
        const ROOT_IDX: usize = 1;

        // add the nodes to verify to the set of known nodes
        let mut queue: VecDeque<(usize, H::Output)> = to_verify
            .iter()
            .cloned()
            .map(|(idx, hash)| (idx + self.leaves, hash))
            .collect();

        // keep merging nodes until we reach the root
        loop {
            let node = queue.pop_front()?;
            let succ = queue.front().cloned();
            match (node, succ) {
                // if the sole node is the root, return it
                ((ROOT_IDX, hash), None) => break Some(hash),

                ((idx, hash), None) => {
                    // retrieve the sibling of the node
                    let sibl = siblings.next()?;

                    // merge the node with its sibling
                    let nodes: [H::Output; 2] = match idx % 2 {
                        0 => [hash, sibl],
                        1 => [sibl, hash],
                        _ => unreachable!(),
                    };

                    // push the parent node to the queue
                    queue.push_back((idx / 2, H::node(&nodes)));
                }

                // merge the node with its sibling
                ((idx, hash), Some((nxt_idx, nxt_hash))) => {
                    // retrieve the sibling of the node
                    let sibl = match nxt_idx == idx ^ 1 {
                        true => {
                            queue.pop_front();
                            nxt_hash
                        }
                        false => siblings.next()?,
                    };

                    // merge the node with its sibling
                    let nodes: [H::Output; 2] = match idx % 2 {
                        0 => [hash, sibl],
                        1 => [sibl, hash],
                        _ => unreachable!(),
                    };

                    // push the parent node to the queue
                    queue.push_back((idx / 2, H::node(&nodes)));
                }
            }
        }
    }
}

/// Errors returned by Merkle Tree Verification
#[derive(Clone, Debug, Eq, PartialEq, Error)]
#[non_exhaustive]
pub enum MerkleError {
    /// returned if error in merkle proof verification
    #[error("VerificationFail")]
    VerificationFail,
    /// returned if query to generate the sibilings is invalid
    #[error("InvalidQuery")]
    InvalidQuery,
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    // use hex_literal::hex;
    use poseidon::Poseidon3;

    use crate::{
        merkle::hash::{Blake2s256Hasher, Hasher, Keccak256Hasher},
        merkle::MerkleTree,
    };

    use felt::Felt252;
    use generic_array::typenum::U32;
    use generic_array::GenericArray;
    use hex::decode;

    fn hex_to_generic_array(hex_str: &str) -> GenericArray<u8, U32> {
        let mut hex_str = String::from(hex_str);
        let padding_length = 64_i32.saturating_sub(hex_str.len() as i32);
        if padding_length > 0 {
            let padding = "0".repeat(padding_length as usize);
            hex_str.insert_str(0, &padding);
        }
        let mut bytes = decode(hex_str).unwrap();

        let padding_length = 32_i32.saturating_sub(bytes.len() as i32);
        if padding_length > 0 {
            let mut padding = vec![0u8; padding_length as usize];
            padding.append(&mut bytes);
            bytes = padding;
        }
        assert_eq!(bytes.len(), 32);

        let mut array = GenericArray::<u8, U32>::default();
        array.clone_from_slice(&bytes);
        array
    }

    fn test_verify_true<F, H>(
        input: &[H::Output],
        comm: H::Output,
        to_verify: &[(usize, H::Output)],
    ) where
        F: PrimeField,
        H: Hasher<F>,
    {
        let tree = MerkleTree::<F, H>::new(input);
        assert_eq!(tree.root, comm);
        assert!(tree.verify_decommitment(comm, to_verify).unwrap());
    }

    #[test]
    fn test_verify_true_with() {
        // test vectors generated from https://github.com/starkware-libs/stone-prover/blob/main/src/starkware/commitment_scheme/merkle/merkle_test.cc

        // tests using Blake2s256
        let input = [hex_to_generic_array(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125",
        )];
        let root_exp = hex_to_generic_array(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125",
        );
        let to_verify = [(
            0,
            hex_to_generic_array(
                "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125",
            ),
        )];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
            ),
            hex_to_generic_array(
                "6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9",
        );
        let to_verify = [(
            0,
            hex_to_generic_array(
                "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
            ),
        )];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
            ),
            hex_to_generic_array(
                "6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
                ),
            ),
            (
                1,
                hex_to_generic_array(
                    "6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd",
                ),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
            ),
            hex_to_generic_array(
                "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
            ),
            hex_to_generic_array(
                "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
            ),
            hex_to_generic_array(
                "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
                ),
            ),
            (
                1,
                hex_to_generic_array(
                    "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
                ),
            ),
            (
                2,
                hex_to_generic_array(
                    "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
                ),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
            ),
            hex_to_generic_array(
                "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
            ),
            hex_to_generic_array(
                "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
            ),
            hex_to_generic_array(
                "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea",
        );
        let to_verify = [
            (
                1,
                hex_to_generic_array(
                    "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
                ),
            ),
            (
                2,
                hex_to_generic_array(
                    "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
                ),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
            ),
            hex_to_generic_array(
                "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
            ),
            hex_to_generic_array(
                "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
            ),
            hex_to_generic_array(
                "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
                ),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f",
            ),
            hex_to_generic_array(
                "82ce423aac9f3cf8b8c28553a5ae607f2586c2f0ca695d4ec97136a8b7fc9f91",
            ),
            hex_to_generic_array(
                "7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89",
            ),
            hex_to_generic_array(
                "9e74347b0b870523de79a2117c2f6954ccdbef01baa6850e22680dd9a7bbf0f2",
            ),
            hex_to_generic_array(
                "c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1",
            ),
            hex_to_generic_array(
                "1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d",
            ),
            hex_to_generic_array(
                "0a614f0d06d701ddc9674406097452de7cf9df5fff1382d167a5f6801620cbfa",
            ),
            hex_to_generic_array(
                "0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "594e2c4c084f406df0130a252fe030a64a1539225e2b4156f04cf4cefcd75b01",
        );
        let to_verify = [
            (
                2,
                hex_to_generic_array(
                    "7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "9e74347b0b870523de79a2117c2f6954ccdbef01baa6850e22680dd9a7bbf0f2",
                ),
            ),
            (
                4,
                hex_to_generic_array(
                    "c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d",
                ),
            ),
            (
                7,
                hex_to_generic_array(
                    "0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a",
                ),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c",
            ),
            hex_to_generic_array(
                "d05c29c29f7db3906f02dc7fbcbb16da58c9d67de7d8c3405cf81592e7a7087b",
            ),
            hex_to_generic_array(
                "e9cdcd85e00bf03e3b7741830cfc3e94d5dd16419b1fcec02eadbf1387cbbf74",
            ),
            hex_to_generic_array(
                "8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979",
            ),
            hex_to_generic_array(
                "09114eaab98d5d3fbfd5ab29c707b5c361ec79d514a6c3bd31c5ec3ec54d55bf",
            ),
            hex_to_generic_array(
                "64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d",
            ),
            hex_to_generic_array(
                "b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e",
            ),
            hex_to_generic_array(
                "0a47848bf63587decc1675ec0ad26bd3b6734a00ebcfcf84e9191ebcacb9c94e",
            ),
            hex_to_generic_array(
                "9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297",
            ),
            hex_to_generic_array(
                "98e8177af0b18366127b14940c2eafcc1f5da635d73891d6bce7e5a5e2d3c721",
            ),
            hex_to_generic_array(
                "b9179e6abddace935de2846267c0b8ef90b575c0f1bfe2a2bc804a05e452e8f9",
            ),
            hex_to_generic_array(
                "a741d2a18d6a1d3d76b06b66febfa128ffbf9ce7ff880d811244ec75887b25e0",
            ),
            hex_to_generic_array(
                "a5bad18826679e52eb722f6fbd3d45cd08add9cec39a15a1046b7f2b17507565",
            ),
            hex_to_generic_array(
                "33ae65efe662938f03694fab95a0ad87653de68e811b9b41292433dc1433c559",
            ),
            hex_to_generic_array(
                "53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440",
            ),
            hex_to_generic_array(
                "6dc75f281250f2d2194b86e272be6662aa28f4ee2e5202556a0796d50a7469dc",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "b7a3cd28384b4baea480d070801106bf07f56f848acf271f6b6415ddc355f8e9",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d",
                ),
            ),
            (
                6,
                hex_to_generic_array(
                    "b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e",
                ),
            ),
            (
                8,
                hex_to_generic_array(
                    "9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297",
                ),
            ),
            (
                14,
                hex_to_generic_array(
                    "53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440",
                ),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        // tests using Keccak256
        let input = [hex_to_generic_array(
            "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127",
        )];
        let root_exp = hex_to_generic_array(
            "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127",
        );
        let to_verify = [(
            0,
            hex_to_generic_array(
                "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127",
            ),
        )];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2",
            ),
            hex_to_generic_array(
                "a1482873bccd9dd66ec6ef8c8a092c7f70839af97b22936ffa5606f1cd28dcea",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "f272f3ba749e68b9ccd51f322c6ae6cac8734967ecc31c1058b8f9a8c99fb083",
        );
        let to_verify = [(
            1,
            hex_to_generic_array(
                "a1482873bccd9dd66ec6ef8c8a092c7f70839af97b22936ffa5606f1cd28dcea",
            ),
        )];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "b77b78e96b3f1de1a11ad49cae9804d8fd754123c916f25c638dd84d7ef8687d",
            ),
            hex_to_generic_array(
                "15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e",
            ),
            hex_to_generic_array(
                "2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793",
            ),
            hex_to_generic_array(
                "c0e9d48d53c45ebfa3cd5ba2492638322463df296bab03b6492f4f11536e7e0e",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "24562159dd8260d379ae390b80cb8266da3f4469bc6643db3b5c3f760c126b83",
        );
        let to_verify = [
            (
                1,
                hex_to_generic_array(
                    "15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "c0e9d48d53c45ebfa3cd5ba2492638322463df296bab03b6492f4f11536e7e0e",
                ),
            ),
        ];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "66661b6925e2abacbb63f975277eb908fa7d3f2c4de8d2cfe9788fd0e2af3234",
            ),
            hex_to_generic_array(
                "fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1",
            ),
            hex_to_generic_array(
                "abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9",
            ),
            hex_to_generic_array(
                "6c63d57004dd9fb1f6a65d111e2230cca32f9aff392d0b84e6ba8c47fe093ae0",
            ),
            hex_to_generic_array(
                "1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6",
            ),
            hex_to_generic_array(
                "3213a156ac8029f8355208b9e6afd496775a494bee3bf4a2bbdaade80da9cc93",
            ),
            hex_to_generic_array(
                "8e62dab2bb313c8e2ed86d601e47e3307e919fac5042be9faa53ba83902dd0a8",
            ),
            hex_to_generic_array(
                "2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "50a1b9b02edd048756030d39f12e795ab7885565964dde0de6e5de1655f0d793",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "66661b6925e2abacbb63f975277eb908fa7d3f2c4de8d2cfe9788fd0e2af3234",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "6c63d57004dd9fb1f6a65d111e2230cca32f9aff392d0b84e6ba8c47fe093ae0",
                ),
            ),
            (
                4,
                hex_to_generic_array(
                    "1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6",
                ),
            ),
            (
                7,
                hex_to_generic_array(
                    "2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95",
                ),
            ),
        ];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1edc3c8392034de0f516534ed7f5441f971d6fa78e1458107939398aaf35162c",
            ),
            hex_to_generic_array(
                "e6d004f42a562534a47d304aaf52425773b70d11c0be3bd59112a0ccf1f0ab2b",
            ),
            hex_to_generic_array(
                "614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5",
            ),
            hex_to_generic_array(
                "564b9ffa2508e2d59c2d5f43c4ca96b7646f3b2363814dac042a89b48af183a3",
            ),
            hex_to_generic_array(
                "e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83",
            ),
            hex_to_generic_array(
                "5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715",
            ),
            hex_to_generic_array(
                "3136305dd4779e01c586fb66b0400d44606dfd3a38c51eda04dc3c059b3c3215",
            ),
            hex_to_generic_array(
                "0085f15f8357aecc4ed40fa7de7a8c44e4800ef5f556d73d6d9e8e77e99eefce",
            ),
            hex_to_generic_array(
                "c11b6869d1674f3342a366f2fc728bed396ab858a36d0d125dea64fb2495e7ac",
            ),
            hex_to_generic_array(
                "ba350a7e4e86f425f9624be90cb4a82c59263304aa02acd8fcb6e246cdc9b12c",
            ),
            hex_to_generic_array(
                "19350ec1a9d255a21556d63d9e35bfb0839ceab89d4d221e92d6cf68ba02bbd5",
            ),
            hex_to_generic_array(
                "9c3982feabacd25de79b03852235fb8c757c2f41912aeda46a5f84b534e2ad40",
            ),
            hex_to_generic_array(
                "87204b53f02a216e574b13e78a7ab11c15181ccbab05694039cfae3333e308a0",
            ),
            hex_to_generic_array(
                "81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36",
            ),
            hex_to_generic_array(
                "0678011aba74ebbdc6d79093b39aa4b6d4c88eb96043a95537633f361e1dc4ed",
            ),
            hex_to_generic_array(
                "8a45012a030697b1c0db1504c68ee0fca1ab0ac8e3ad80c032b26f7b38ea97b4",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "fba6d37293ad9845ff546e9615853594c47237ee666cf5267788e14e0032f3de",
        );
        let to_verify = [
            (
                4,
                hex_to_generic_array(
                    "e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715",
                ),
            ),
            (
                13,
                hex_to_generic_array(
                    "81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36",
                ),
            ),
        ];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        // tests using Poseidon3
        let input = [hex_to_generic_array(
            "075667f6fe5693fbad372d22f98a6327fde210e05c38cb60a0b18680dbcb36a8",
        )];
        let root_exp = hex_to_generic_array(
            "075667f6fe5693fbad372d22f98a6327fde210e05c38cb60a0b18680dbcb36a8",
        );
        let to_verify = [(
            0,
            hex_to_generic_array(
                "075667f6fe5693fbad372d22f98a6327fde210e05c38cb60a0b18680dbcb36a8",
            ),
        )];
        test_verify_true::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array("26a7232a361ae171948e7fb8e00f012ed8071ba0b8d34afc3108d821d3943a3"),
            hex_to_generic_array("169512152548024fded52fd02253b9ee2be4a4fdaab4d8495d22be9e113884c"),
        ];
        let root_exp =
            hex_to_generic_array("3ea667f15f07b1127afe2473679069e19861bacc05df9ac42635e91bf887fa3");
        let to_verify = [(
            1,
            hex_to_generic_array("169512152548024fded52fd02253b9ee2be4a4fdaab4d8495d22be9e113884c"),
        )];
        test_verify_true::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array("5d5e6513cb2c66f61bfa1d6a6eb8215c0637ed6cb8be3310a991a271bba195d"),
            hex_to_generic_array("71b3e69ba1d55ce0d64b87ae1a76f498bc3c444bbcdd02a81893a5b71020a8"),
            hex_to_generic_array("75857673562a5611b0005047728fa1e050dcbf19d3a2d08c45909b142903309"),
            hex_to_generic_array("dcb000821d941b4aee583805390296f859fa4b3f1d5acfa9bf7de8a561c19"),
        ];
        let root_exp =
            hex_to_generic_array("8eacf88fcb82bed025b069d23d41a3b3d7902e6e8279b3e1de42ce43061008");
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "5d5e6513cb2c66f61bfa1d6a6eb8215c0637ed6cb8be3310a991a271bba195d",
                ),
            ),
            (
                2,
                hex_to_generic_array(
                    "75857673562a5611b0005047728fa1e050dcbf19d3a2d08c45909b142903309",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "dcb000821d941b4aee583805390296f859fa4b3f1d5acfa9bf7de8a561c19",
                ),
            ),
        ];
        test_verify_true::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array("36313083bda3d5d1f1ade3dfb59311bd38f583c92f570719cb41be7e46e6ee5"),
            hex_to_generic_array("353699d84e4b67ce55874046b58e501a73582c2b16ceed4ff651e6439089483"),
            hex_to_generic_array("452135053077d0c52f8057d5a418a67bdecec4afb240d59613e885e0e71a0bf"),
            hex_to_generic_array("4705a84ca4ee4bc971f9bdf51fd2f74e1273ca72261c0a5845e89dc5c3a1a00"),
            hex_to_generic_array("27c1e003f81b13f5282b863dceddb162dd6180150eabc16d2267b5aa25c1786"),
            hex_to_generic_array("27b3118926ffe13b70a3a3ed551869cc31d344551e5a7013a9146d0fa84f06a"),
            hex_to_generic_array("5f7701e493613cfb4e3b0600eccf74d4916cc66aa2631ab374e73d3a43bcee4"),
            hex_to_generic_array("5e598f5a773a9ab554121b8d4937bf1b383393f10ae49f98532a2beea1f7852"),
        ];
        let root_exp =
            hex_to_generic_array("3a80041b3647dd472cb7979dc422e9b7d86d4bcd08b957a6ae05caf6c6e189b");
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "36313083bda3d5d1f1ade3dfb59311bd38f583c92f570719cb41be7e46e6ee5",
                ),
            ),
            (
                1,
                hex_to_generic_array(
                    "353699d84e4b67ce55874046b58e501a73582c2b16ceed4ff651e6439089483",
                ),
            ),
            (
                2,
                hex_to_generic_array(
                    "452135053077d0c52f8057d5a418a67bdecec4afb240d59613e885e0e71a0bf",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "4705a84ca4ee4bc971f9bdf51fd2f74e1273ca72261c0a5845e89dc5c3a1a00",
                ),
            ),
            (
                4,
                hex_to_generic_array(
                    "27c1e003f81b13f5282b863dceddb162dd6180150eabc16d2267b5aa25c1786",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "27b3118926ffe13b70a3a3ed551869cc31d344551e5a7013a9146d0fa84f06a",
                ),
            ),
            (
                6,
                hex_to_generic_array(
                    "5f7701e493613cfb4e3b0600eccf74d4916cc66aa2631ab374e73d3a43bcee4",
                ),
            ),
            (
                7,
                hex_to_generic_array(
                    "5e598f5a773a9ab554121b8d4937bf1b383393f10ae49f98532a2beea1f7852",
                ),
            ),
        ];
        test_verify_true::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);
    }

    fn test_verify_false<F, H>(
        input: &[H::Output],
        comm: H::Output,
        to_verify: &[(usize, H::Output)],
    ) where
        F: PrimeField,
        H: Hasher<F>,
    {
        let tree = MerkleTree::<F, H>::new(input);
        assert_eq!(tree.root, comm);
        assert!(!tree.verify_decommitment(comm, to_verify).unwrap());
    }

    #[test]
    fn test_verify_false_with() {
        // tests using Blake2s256
        let input = [hex_to_generic_array(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125",
        )];
        let root_exp = hex_to_generic_array(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125",
        );
        let to_verify = [(
            0,
            hex_to_generic_array(
                "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
            ),
        )];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
            ),
            hex_to_generic_array(
                "6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9",
        );
        let to_verify = [(
            0,
            hex_to_generic_array(
                "6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd",
            ),
        )];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
            ),
            hex_to_generic_array(
                "6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
                ),
            ),
            (
                1,
                hex_to_generic_array(
                    "d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482",
                ),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
            ),
            hex_to_generic_array(
                "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
            ),
            hex_to_generic_array(
                "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
            ),
            hex_to_generic_array(
                "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
                ),
            ),
            (
                1,
                hex_to_generic_array(
                    "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
                ),
            ),
            (
                2,
                hex_to_generic_array(
                    "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
                ),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
            ),
            hex_to_generic_array(
                "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
            ),
            hex_to_generic_array(
                "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
            ),
            hex_to_generic_array(
                "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea",
        );
        let to_verify = [
            (
                1,
                hex_to_generic_array(
                    "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
                ),
            ),
            (
                2,
                hex_to_generic_array(
                    "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
                ),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
            ),
            hex_to_generic_array(
                "12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed",
            ),
            hex_to_generic_array(
                "aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933",
            ),
            hex_to_generic_array(
                "1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c",
                ),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f",
            ),
            hex_to_generic_array(
                "82ce423aac9f3cf8b8c28553a5ae607f2586c2f0ca695d4ec97136a8b7fc9f91",
            ),
            hex_to_generic_array(
                "7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89",
            ),
            hex_to_generic_array(
                "9e74347b0b870523de79a2117c2f6954ccdbef01baa6850e22680dd9a7bbf0f2",
            ),
            hex_to_generic_array(
                "c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1",
            ),
            hex_to_generic_array(
                "1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d",
            ),
            hex_to_generic_array(
                "0a614f0d06d701ddc9674406097452de7cf9df5fff1382d167a5f6801620cbfa",
            ),
            hex_to_generic_array(
                "0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "594e2c4c084f406df0130a252fe030a64a1539225e2b4156f04cf4cefcd75b01",
        );
        let to_verify = [
            (
                2,
                hex_to_generic_array(
                    "7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f",
                ),
            ),
            (
                4,
                hex_to_generic_array(
                    "c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d",
                ),
            ),
            (
                7,
                hex_to_generic_array(
                    "0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a",
                ),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c",
            ),
            hex_to_generic_array(
                "d05c29c29f7db3906f02dc7fbcbb16da58c9d67de7d8c3405cf81592e7a7087b",
            ),
            hex_to_generic_array(
                "e9cdcd85e00bf03e3b7741830cfc3e94d5dd16419b1fcec02eadbf1387cbbf74",
            ),
            hex_to_generic_array(
                "8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979",
            ),
            hex_to_generic_array(
                "09114eaab98d5d3fbfd5ab29c707b5c361ec79d514a6c3bd31c5ec3ec54d55bf",
            ),
            hex_to_generic_array(
                "64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d",
            ),
            hex_to_generic_array(
                "b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e",
            ),
            hex_to_generic_array(
                "0a47848bf63587decc1675ec0ad26bd3b6734a00ebcfcf84e9191ebcacb9c94e",
            ),
            hex_to_generic_array(
                "9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297",
            ),
            hex_to_generic_array(
                "98e8177af0b18366127b14940c2eafcc1f5da635d73891d6bce7e5a5e2d3c721",
            ),
            hex_to_generic_array(
                "b9179e6abddace935de2846267c0b8ef90b575c0f1bfe2a2bc804a05e452e8f9",
            ),
            hex_to_generic_array(
                "a741d2a18d6a1d3d76b06b66febfa128ffbf9ce7ff880d811244ec75887b25e0",
            ),
            hex_to_generic_array(
                "a5bad18826679e52eb722f6fbd3d45cd08add9cec39a15a1046b7f2b17507565",
            ),
            hex_to_generic_array(
                "33ae65efe662938f03694fab95a0ad87653de68e811b9b41292433dc1433c559",
            ),
            hex_to_generic_array(
                "53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440",
            ),
            hex_to_generic_array(
                "6dc75f281250f2d2194b86e272be6662aa28f4ee2e5202556a0796d50a7469dc",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "b7a3cd28384b4baea480d070801106bf07f56f848acf271f6b6415ddc355f8e9",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d",
                ),
            ),
            (
                6,
                hex_to_generic_array(
                    "b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e",
                ),
            ),
            (
                8,
                hex_to_generic_array(
                    "9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297",
                ),
            ),
            (
                14,
                hex_to_generic_array(
                    "53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440",
                ),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        // tests using Keccak256
        let input = [hex_to_generic_array(
            "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127",
        )];
        let root_exp = hex_to_generic_array(
            "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127",
        );
        let to_verify = [(
            0,
            hex_to_generic_array(
                "8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2",
            ),
        )];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2",
            ),
            hex_to_generic_array(
                "a1482873bccd9dd66ec6ef8c8a092c7f70839af97b22936ffa5606f1cd28dcea",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "f272f3ba749e68b9ccd51f322c6ae6cac8734967ecc31c1058b8f9a8c99fb083",
        );
        let to_verify = [(
            1,
            hex_to_generic_array(
                "8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2",
            ),
        )];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "b77b78e96b3f1de1a11ad49cae9804d8fd754123c916f25c638dd84d7ef8687d",
            ),
            hex_to_generic_array(
                "15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e",
            ),
            hex_to_generic_array(
                "2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793",
            ),
            hex_to_generic_array(
                "c0e9d48d53c45ebfa3cd5ba2492638322463df296bab03b6492f4f11536e7e0e",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "24562159dd8260d379ae390b80cb8266da3f4469bc6643db3b5c3f760c126b83",
        );
        let to_verify = [
            (
                1,
                hex_to_generic_array(
                    "15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793",
                ),
            ),
        ];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "66661b6925e2abacbb63f975277eb908fa7d3f2c4de8d2cfe9788fd0e2af3234",
            ),
            hex_to_generic_array(
                "fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1",
            ),
            hex_to_generic_array(
                "abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9",
            ),
            hex_to_generic_array(
                "6c63d57004dd9fb1f6a65d111e2230cca32f9aff392d0b84e6ba8c47fe093ae0",
            ),
            hex_to_generic_array(
                "1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6",
            ),
            hex_to_generic_array(
                "3213a156ac8029f8355208b9e6afd496775a494bee3bf4a2bbdaade80da9cc93",
            ),
            hex_to_generic_array(
                "8e62dab2bb313c8e2ed86d601e47e3307e919fac5042be9faa53ba83902dd0a8",
            ),
            hex_to_generic_array(
                "2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "50a1b9b02edd048756030d39f12e795ab7885565964dde0de6e5de1655f0d793",
        );
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9",
                ),
            ),
            (
                4,
                hex_to_generic_array(
                    "1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6",
                ),
            ),
            (
                7,
                hex_to_generic_array(
                    "2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95",
                ),
            ),
        ];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "1edc3c8392034de0f516534ed7f5441f971d6fa78e1458107939398aaf35162c",
            ),
            hex_to_generic_array(
                "e6d004f42a562534a47d304aaf52425773b70d11c0be3bd59112a0ccf1f0ab2b",
            ),
            hex_to_generic_array(
                "614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5",
            ),
            hex_to_generic_array(
                "564b9ffa2508e2d59c2d5f43c4ca96b7646f3b2363814dac042a89b48af183a3",
            ),
            hex_to_generic_array(
                "e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83",
            ),
            hex_to_generic_array(
                "5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715",
            ),
            hex_to_generic_array(
                "3136305dd4779e01c586fb66b0400d44606dfd3a38c51eda04dc3c059b3c3215",
            ),
            hex_to_generic_array(
                "0085f15f8357aecc4ed40fa7de7a8c44e4800ef5f556d73d6d9e8e77e99eefce",
            ),
            hex_to_generic_array(
                "c11b6869d1674f3342a366f2fc728bed396ab858a36d0d125dea64fb2495e7ac",
            ),
            hex_to_generic_array(
                "ba350a7e4e86f425f9624be90cb4a82c59263304aa02acd8fcb6e246cdc9b12c",
            ),
            hex_to_generic_array(
                "19350ec1a9d255a21556d63d9e35bfb0839ceab89d4d221e92d6cf68ba02bbd5",
            ),
            hex_to_generic_array(
                "9c3982feabacd25de79b03852235fb8c757c2f41912aeda46a5f84b534e2ad40",
            ),
            hex_to_generic_array(
                "87204b53f02a216e574b13e78a7ab11c15181ccbab05694039cfae3333e308a0",
            ),
            hex_to_generic_array(
                "81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36",
            ),
            hex_to_generic_array(
                "0678011aba74ebbdc6d79093b39aa4b6d4c88eb96043a95537633f361e1dc4ed",
            ),
            hex_to_generic_array(
                "8a45012a030697b1c0db1504c68ee0fca1ab0ac8e3ad80c032b26f7b38ea97b4",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "fba6d37293ad9845ff546e9615853594c47237ee666cf5267788e14e0032f3de",
        );
        let to_verify = [
            (
                4,
                hex_to_generic_array(
                    "e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715",
                ),
            ),
            (
                13,
                hex_to_generic_array(
                    "614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5",
                ),
            ),
        ];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        // tests using Poseidon3
        let input = [hex_to_generic_array(
            "c89ae25f3fa9f809dc7e255509bbe13d8ee41e7050a1757d10b14380479762",
        )];
        let root_exp =
            hex_to_generic_array("c89ae25f3fa9f809dc7e255509bbe13d8ee41e7050a1757d10b14380479762");
        let to_verify = [(
            0,
            hex_to_generic_array(
                "061e4f02a5fb16a37cef579d5a3bc31ab6bc3dfb112d0bbe440afcf4ef6b2dbd",
            ),
        )];
        test_verify_false::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array(
                "02f926674daed935c5ec20daf9e116f45e74ebad57909889e6c4e60ac9a7239a",
            ),
            hex_to_generic_array(
                "059089a262fd310d47e824b3add73c7bbedd67b2f111b3d67a48177765891a1f",
            ),
        ];
        let root_exp = hex_to_generic_array(
            "07572153d1bc66733cf79b40c1427cdf8c5754e71254491da93c3a789c5f1af3",
        );
        let to_verify = [(
            1,
            hex_to_generic_array(
                "0070336f8988bd453e936b157afcfcf07fa2924e5d670f36fcc9cf01ff09fc6f",
            ),
        )];
        test_verify_false::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array("167c6d08b3aec83b4b27bce5df9c9ba4dce709ea7d40497f7bf2cc2b787cc41"),
            hex_to_generic_array("5934aa1631d1759018513505f5407abb4e232bdab2aa74e48cbbe1cec301387"),
            hex_to_generic_array("56daeb7ceeeda161e5ee669bf88202e034216fa8424c89e1408ad77ea6b8829"),
            hex_to_generic_array("1808bca5f11183aaf603971b0ac93f5b4558c47f0777e5db2cc14e3b512c66"),
        ];
        let root_exp =
            hex_to_generic_array("32cbc8162b4c5f91efd2a5f2c2701fbabafdd08ea8ce7f06d6f0ee2a28cdef5");
        let to_verify = [(
            2,
            hex_to_generic_array("1f8c6141be9707ec0a767257d522ef2bf321a2e9efc6b93136e3dc9d9665d26"),
        )];
        test_verify_false::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_generic_array("726cb96d8303497a472d118b54046e2966076ad68b3c39a24cd96a8c5ae466b"),
            hex_to_generic_array("6380a19495b51c52bd73a7111d5a4b0c022efedfb90d46660301ce365b0069c"),
            hex_to_generic_array("4c3abd3626c95cd55e330856ebc8cc85c8871349c28079149e1ee19f4ba7809"),
            hex_to_generic_array("438059b58dd33650037db7274014d00ce07a1a62ddbf68b43b10a91de504606"),
            hex_to_generic_array("573f3d932cbfc0070b76aa652a82bd93bc0e92517068092b252788bd54bbe84"),
            hex_to_generic_array("26a109ece8e786838ad839a0513db66ff403cb97e6c35396b8e82ef014729ff"),
            hex_to_generic_array("355834fe0fb7afcbd719967841a691822148ff959c16e5ba67114a9774c57e5"),
            hex_to_generic_array("203b523ca101a81bbb94013b9408968c324e35340081375f77f628114441622"),
        ];
        let root_exp =
            hex_to_generic_array("577c0d4d52b1b4b583e4f6be73ed16b33067318b0d9eda930c47f60679fe5c0");
        let to_verify = [
            (
                0,
                hex_to_generic_array(
                    "726cb96d8303497a472d118b54046e2966076ad68b3c39a24cd96a8c5ae466b",
                ),
            ),
            (
                1,
                hex_to_generic_array(
                    "6380a19495b51c52bd73a7111d5a4b0c022efedfb90d46660301ce365b0069c",
                ),
            ),
            (
                2,
                hex_to_generic_array(
                    "4c3abd3626c95cd55e330856ebc8cc85c8871349c28079149e1ee19f4ba7809",
                ),
            ),
            (
                3,
                hex_to_generic_array(
                    "28dc328d44f2a150c15de51b322b020adbf685b520cac210a314fa98efedab3",
                ),
            ),
            (
                4,
                hex_to_generic_array(
                    "573f3d932cbfc0070b76aa652a82bd93bc0e92517068092b252788bd54bbe84",
                ),
            ),
            (
                5,
                hex_to_generic_array(
                    "26a109ece8e786838ad839a0513db66ff403cb97e6c35396b8e82ef014729ff",
                ),
            ),
            (
                6,
                hex_to_generic_array(
                    "355834fe0fb7afcbd719967841a691822148ff959c16e5ba67114a9774c57e5",
                ),
            ),
        ];
        test_verify_false::<Felt252, Poseidon3<Felt252>>(&input, root_exp, &to_verify);
    }
}
