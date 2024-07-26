pub mod hash;
use crate::hash::Hasher;
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
    use hex_literal::hex;

    use crate::{
        hash::{Blake2s256Hasher, Hasher},
        MerkleTree,
    };

    use felt::Felt252;

    fn test_compute_root<F, H>(input: &[H::Output], root_exp: H::Output)
    where
        F: PrimeField,
        H: Hasher<F>,
    {
        let tree = MerkleTree::<F, H>::new(input);
        assert_eq!(tree.root, root_exp);
    }

    #[test]
    fn test_compute_root_with() {
        // test vectors generated from https://github.com/starkware-libs/stone-prover/blob/main/src/starkware/commitment_scheme/merkle/merkle_test.cc

        let input = [hex!(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125"
        )];
        let root_exp = hex!("216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125");
        test_compute_root::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp);

        let input = [
            hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            hex!("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
        ];
        let root_exp = hex!("b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9");
        test_compute_root::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp);

        let input = [
            hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp = hex!("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        test_compute_root::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp);

        let input = [
            hex!("72413d150744cf57eb6588853f44855b03b360b232a2109b83bed983369d1412"),
            hex!("914d9ac0dbc6d97e427340798b5ac8b5c1f4c5cd7be177d55463665965e334c4"),
            hex!("969477390c57491d9237cf4fb1cecc17584c0a7b9b0a3db6255899779ab8f52d"),
            hex!("59e28ede24abe8ee0a8319ddd90beb9725edaa107531f1497574fe745d153d59"),
            hex!("c28ed6b97ca7ba227402b12d3c4fe73d6ab45aad72e81c20c7fd32816db1398c"),
            hex!("7b78d48039e32a055df717b065e478207c5693f37d9ce6229c55e13f8d71b397"),
            hex!("dd4b9612ef3cb88534a8602320145118bd22781d29c396b8686f4871f3727764"),
            hex!("f5f865937bd28b5c996d94627226888dbad14a5b024f5962fd45c5f62315fb63"),
        ];
        let root_exp = hex!("3f8893c325c0ddbd7b8d6c7340b30861bbb79ad64562124e25aa47499c582de3");
        test_compute_root::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp);

        let input = [
            hex!("b834a8385e53f736e02e308351cde4a3e9a70c83446487cb3397ca7cfc868fd2"),
            hex!("5761708eb0ac5f10ad04d71415453f53bfeca9f8454e0a85037ced8e09ad536e"),
            hex!("04203a2181b8948292ffbaf7dfbd0e70d9b71ecab2a6075a39828fde26a54415"),
            hex!("bd03e9abeb519b817c2d96f6a227755e6807656f24075e5933895f38b81ca840"),
            hex!("9c0a39bd966e29420d9e4e9718d0238fc8935649202ff7056e40aaa5bcea62ef"),
            hex!("3c74f69c462b05212087673174f4f24a9d5f65e55868a1d593467abb3905d5bb"),
            hex!("e2cea6e8e32426b23b38f766720dc7ebf72865bac608c8c1030ef806b84ebb97"),
            hex!("e081a1e8983546099bce2967607f0c25d43bd01ae564c4212bb4931e38b6ffad"),
            hex!("d3dfec774ab0b0433a3a32766d50c11fdcfdd3f97785cce28d3b23ed963694f9"),
            hex!("0d835a0558af1b4c8664228ebf7ea6a6440cd6fd2387573e0c5bee2b03d8c506"),
            hex!("d5559fbd925ce10cf9e7b734d5c0b25f898d56d3dac7c3253130781460d35fb4"),
            hex!("bc9a983f00efa883f39a1e168a18d3f8d47841acc34640d80fafda40968cf2ad"),
            hex!("d035d3b16da2e6a1f355d6d650f9c891e3b030f0612521e5431f42a162e92e41"),
            hex!("02ec5ddb356c692553d911625def6369aa8c4ad46cea51c7b6b5f7d2d17d3244"),
            hex!("04f20878faaac6e3eb11b2d7f7490661138b355b4fcd7a1436705f42a68de61c"),
            hex!("3a579a12f0250c86182920fad2048ab0d9195b6e3461160db36b4a4eb63399f6"),
        ];
        let root_exp = hex!("eeae978671e1365726c7247cf945725bbaebe267260530a871153b39064ab342");
        test_compute_root::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp);
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

        let input = [hex!(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125"
        )];
        let root_exp = hex!("216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125");
        let to_verify = [(
            0,
            hex!("216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125"),
        )];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            hex!("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
        ];
        let root_exp = hex!("b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9");
        let to_verify = [(
            0,
            hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
        )];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            hex!("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
        ];
        let root_exp = hex!("b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9");
        let to_verify = [
            (
                0,
                hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            ),
            (
                1,
                hex!("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp = hex!("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        let to_verify = [
            (
                0,
                hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
            (
                1,
                hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            ),
            (
                2,
                hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            ),
            (
                3,
                hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp = hex!("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        let to_verify = [
            (
                1,
                hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            ),
            (
                2,
                hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            ),
            (
                3,
                hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp = hex!("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        let to_verify = [
            (
                0,
                hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
            (
                3,
                hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f"),
            hex!("82ce423aac9f3cf8b8c28553a5ae607f2586c2f0ca695d4ec97136a8b7fc9f91"),
            hex!("7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89"),
            hex!("9e74347b0b870523de79a2117c2f6954ccdbef01baa6850e22680dd9a7bbf0f2"),
            hex!("c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1"),
            hex!("1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d"),
            hex!("0a614f0d06d701ddc9674406097452de7cf9df5fff1382d167a5f6801620cbfa"),
            hex!("0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a"),
        ];
        let root_exp = hex!("594e2c4c084f406df0130a252fe030a64a1539225e2b4156f04cf4cefcd75b01");
        let to_verify = [
            (
                2,
                hex!("7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89"),
            ),
            (
                3,
                hex!("9e74347b0b870523de79a2117c2f6954ccdbef01baa6850e22680dd9a7bbf0f2"),
            ),
            (
                4,
                hex!("c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1"),
            ),
            (
                5,
                hex!("1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d"),
            ),
            (
                7,
                hex!("0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a"),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            hex!("d05c29c29f7db3906f02dc7fbcbb16da58c9d67de7d8c3405cf81592e7a7087b"),
            hex!("e9cdcd85e00bf03e3b7741830cfc3e94d5dd16419b1fcec02eadbf1387cbbf74"),
            hex!("8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979"),
            hex!("09114eaab98d5d3fbfd5ab29c707b5c361ec79d514a6c3bd31c5ec3ec54d55bf"),
            hex!("64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d"),
            hex!("b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e"),
            hex!("0a47848bf63587decc1675ec0ad26bd3b6734a00ebcfcf84e9191ebcacb9c94e"),
            hex!("9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297"),
            hex!("98e8177af0b18366127b14940c2eafcc1f5da635d73891d6bce7e5a5e2d3c721"),
            hex!("b9179e6abddace935de2846267c0b8ef90b575c0f1bfe2a2bc804a05e452e8f9"),
            hex!("a741d2a18d6a1d3d76b06b66febfa128ffbf9ce7ff880d811244ec75887b25e0"),
            hex!("a5bad18826679e52eb722f6fbd3d45cd08add9cec39a15a1046b7f2b17507565"),
            hex!("33ae65efe662938f03694fab95a0ad87653de68e811b9b41292433dc1433c559"),
            hex!("53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440"),
            hex!("6dc75f281250f2d2194b86e272be6662aa28f4ee2e5202556a0796d50a7469dc"),
        ];
        let root_exp = hex!("b7a3cd28384b4baea480d070801106bf07f56f848acf271f6b6415ddc355f8e9");
        let to_verify = [
            (
                0,
                hex!("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            ),
            (
                3,
                hex!("8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979"),
            ),
            (
                5,
                hex!("64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d"),
            ),
            (
                6,
                hex!("b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e"),
            ),
            (
                8,
                hex!("9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297"),
            ),
            (
                14,
                hex!("53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440"),
            ),
        ];
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);
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
        let input = [hex!(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125"
        )];
        let root_exp = hex!("216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125");
        let to_verify = [(
            0,
            hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
        )];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            hex!("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
        ];
        let root_exp = hex!("b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9");
        let to_verify = [(
            0,
            hex!("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
        )];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            hex!("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
        ];
        let root_exp = hex!("b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9");
        let to_verify = [
            (
                0,
                hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            ),
            (
                1,
                hex!("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp = hex!("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        let to_verify = [
            (
                0,
                hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
            (
                1,
                hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
            (
                2,
                hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            ),
            (
                3,
                hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp = hex!("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        let to_verify = [
            (
                1,
                hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            ),
            (
                2,
                hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            ),
            (
                3,
                hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex!("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex!("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex!("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp = hex!("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        let to_verify = [
            (
                0,
                hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
            (
                3,
                hex!("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f"),
            hex!("82ce423aac9f3cf8b8c28553a5ae607f2586c2f0ca695d4ec97136a8b7fc9f91"),
            hex!("7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89"),
            hex!("9e74347b0b870523de79a2117c2f6954ccdbef01baa6850e22680dd9a7bbf0f2"),
            hex!("c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1"),
            hex!("1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d"),
            hex!("0a614f0d06d701ddc9674406097452de7cf9df5fff1382d167a5f6801620cbfa"),
            hex!("0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a"),
        ];
        let root_exp = hex!("594e2c4c084f406df0130a252fe030a64a1539225e2b4156f04cf4cefcd75b01");
        let to_verify = [
            (
                2,
                hex!("7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89"),
            ),
            (
                3,
                hex!("a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f"),
            ),
            (
                4,
                hex!("c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1"),
            ),
            (
                5,
                hex!("1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d"),
            ),
            (
                7,
                hex!("0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a"),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            hex!("d05c29c29f7db3906f02dc7fbcbb16da58c9d67de7d8c3405cf81592e7a7087b"),
            hex!("e9cdcd85e00bf03e3b7741830cfc3e94d5dd16419b1fcec02eadbf1387cbbf74"),
            hex!("8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979"),
            hex!("09114eaab98d5d3fbfd5ab29c707b5c361ec79d514a6c3bd31c5ec3ec54d55bf"),
            hex!("64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d"),
            hex!("b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e"),
            hex!("0a47848bf63587decc1675ec0ad26bd3b6734a00ebcfcf84e9191ebcacb9c94e"),
            hex!("9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297"),
            hex!("98e8177af0b18366127b14940c2eafcc1f5da635d73891d6bce7e5a5e2d3c721"),
            hex!("b9179e6abddace935de2846267c0b8ef90b575c0f1bfe2a2bc804a05e452e8f9"),
            hex!("a741d2a18d6a1d3d76b06b66febfa128ffbf9ce7ff880d811244ec75887b25e0"),
            hex!("a5bad18826679e52eb722f6fbd3d45cd08add9cec39a15a1046b7f2b17507565"),
            hex!("33ae65efe662938f03694fab95a0ad87653de68e811b9b41292433dc1433c559"),
            hex!("53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440"),
            hex!("6dc75f281250f2d2194b86e272be6662aa28f4ee2e5202556a0796d50a7469dc"),
        ];
        let root_exp = hex!("b7a3cd28384b4baea480d070801106bf07f56f848acf271f6b6415ddc355f8e9");
        let to_verify = [
            (
                0,
                hex!("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            ),
            (
                3,
                hex!("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            ),
            (
                5,
                hex!("64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d"),
            ),
            (
                6,
                hex!("b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e"),
            ),
            (
                8,
                hex!("9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297"),
            ),
            (
                14,
                hex!("53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440"),
            ),
        ];
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);
    }
}
