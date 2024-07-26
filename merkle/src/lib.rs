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
        hash::{Blake2s256Hasher, Hasher, Keccak256Hasher},
        MerkleTree,
    };

    use felt::Felt252;

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

        // tests using Keccak256
        let input = [hex!(
            "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127"
        )];
        let root_exp = hex!("ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127");
        let to_verify = [(
            0,
            hex!("ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127"),
        )];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2"),
            hex!("a1482873bccd9dd66ec6ef8c8a092c7f70839af97b22936ffa5606f1cd28dcea"),
        ];
        let root_exp = hex!("f272f3ba749e68b9ccd51f322c6ae6cac8734967ecc31c1058b8f9a8c99fb083");
        let to_verify = [(
            1,
            hex!("a1482873bccd9dd66ec6ef8c8a092c7f70839af97b22936ffa5606f1cd28dcea"),
        )];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("b77b78e96b3f1de1a11ad49cae9804d8fd754123c916f25c638dd84d7ef8687d"),
            hex!("15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e"),
            hex!("2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793"),
            hex!("c0e9d48d53c45ebfa3cd5ba2492638322463df296bab03b6492f4f11536e7e0e"),
        ];
        let root_exp = hex!("24562159dd8260d379ae390b80cb8266da3f4469bc6643db3b5c3f760c126b83");
        let to_verify = [
            (
                1,
                hex!("15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e"),
            ),
            (
                3,
                hex!("c0e9d48d53c45ebfa3cd5ba2492638322463df296bab03b6492f4f11536e7e0e"),
            ),
        ];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("66661b6925e2abacbb63f975277eb908fa7d3f2c4de8d2cfe9788fd0e2af3234"),
            hex!("fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1"),
            hex!("abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9"),
            hex!("6c63d57004dd9fb1f6a65d111e2230cca32f9aff392d0b84e6ba8c47fe093ae0"),
            hex!("1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6"),
            hex!("3213a156ac8029f8355208b9e6afd496775a494bee3bf4a2bbdaade80da9cc93"),
            hex!("8e62dab2bb313c8e2ed86d601e47e3307e919fac5042be9faa53ba83902dd0a8"),
            hex!("2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95"),
        ];
        let root_exp = hex!("50a1b9b02edd048756030d39f12e795ab7885565964dde0de6e5de1655f0d793");
        let to_verify = [
            (
                0,
                hex!("66661b6925e2abacbb63f975277eb908fa7d3f2c4de8d2cfe9788fd0e2af3234"),
            ),
            (
                3,
                hex!("6c63d57004dd9fb1f6a65d111e2230cca32f9aff392d0b84e6ba8c47fe093ae0"),
            ),
            (
                4,
                hex!("1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6"),
            ),
            (
                7,
                hex!("2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95"),
            ),
        ];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1edc3c8392034de0f516534ed7f5441f971d6fa78e1458107939398aaf35162c"),
            hex!("e6d004f42a562534a47d304aaf52425773b70d11c0be3bd59112a0ccf1f0ab2b"),
            hex!("614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5"),
            hex!("564b9ffa2508e2d59c2d5f43c4ca96b7646f3b2363814dac042a89b48af183a3"),
            hex!("e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83"),
            hex!("5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715"),
            hex!("3136305dd4779e01c586fb66b0400d44606dfd3a38c51eda04dc3c059b3c3215"),
            hex!("0085f15f8357aecc4ed40fa7de7a8c44e4800ef5f556d73d6d9e8e77e99eefce"),
            hex!("c11b6869d1674f3342a366f2fc728bed396ab858a36d0d125dea64fb2495e7ac"),
            hex!("ba350a7e4e86f425f9624be90cb4a82c59263304aa02acd8fcb6e246cdc9b12c"),
            hex!("19350ec1a9d255a21556d63d9e35bfb0839ceab89d4d221e92d6cf68ba02bbd5"),
            hex!("9c3982feabacd25de79b03852235fb8c757c2f41912aeda46a5f84b534e2ad40"),
            hex!("87204b53f02a216e574b13e78a7ab11c15181ccbab05694039cfae3333e308a0"),
            hex!("81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36"),
            hex!("0678011aba74ebbdc6d79093b39aa4b6d4c88eb96043a95537633f361e1dc4ed"),
            hex!("8a45012a030697b1c0db1504c68ee0fca1ab0ac8e3ad80c032b26f7b38ea97b4"),
        ];
        let root_exp = hex!("fba6d37293ad9845ff546e9615853594c47237ee666cf5267788e14e0032f3de");
        let to_verify = [
            (
                4,
                hex!("e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83"),
            ),
            (
                5,
                hex!("5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715"),
            ),
            (
                13,
                hex!("81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36"),
            ),
        ];
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);
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

        // tests using Keccak256
        let input = [hex!(
            "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127"
        )];
        let root_exp = hex!("ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127");
        let to_verify = [(
            0,
            hex!("8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2"),
        )];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2"),
            hex!("a1482873bccd9dd66ec6ef8c8a092c7f70839af97b22936ffa5606f1cd28dcea"),
        ];
        let root_exp = hex!("f272f3ba749e68b9ccd51f322c6ae6cac8734967ecc31c1058b8f9a8c99fb083");
        let to_verify = [(
            1,
            hex!("8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2"),
        )];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("b77b78e96b3f1de1a11ad49cae9804d8fd754123c916f25c638dd84d7ef8687d"),
            hex!("15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e"),
            hex!("2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793"),
            hex!("c0e9d48d53c45ebfa3cd5ba2492638322463df296bab03b6492f4f11536e7e0e"),
        ];
        let root_exp = hex!("24562159dd8260d379ae390b80cb8266da3f4469bc6643db3b5c3f760c126b83");
        let to_verify = [
            (
                1,
                hex!("15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e"),
            ),
            (
                3,
                hex!("2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793"),
            ),
        ];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("66661b6925e2abacbb63f975277eb908fa7d3f2c4de8d2cfe9788fd0e2af3234"),
            hex!("fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1"),
            hex!("abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9"),
            hex!("6c63d57004dd9fb1f6a65d111e2230cca32f9aff392d0b84e6ba8c47fe093ae0"),
            hex!("1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6"),
            hex!("3213a156ac8029f8355208b9e6afd496775a494bee3bf4a2bbdaade80da9cc93"),
            hex!("8e62dab2bb313c8e2ed86d601e47e3307e919fac5042be9faa53ba83902dd0a8"),
            hex!("2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95"),
        ];
        let root_exp = hex!("50a1b9b02edd048756030d39f12e795ab7885565964dde0de6e5de1655f0d793");
        let to_verify = [
            (
                0,
                hex!("fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1"),
            ),
            (
                3,
                hex!("abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9"),
            ),
            (
                4,
                hex!("1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6"),
            ),
            (
                7,
                hex!("2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95"),
            ),
        ];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex!("1edc3c8392034de0f516534ed7f5441f971d6fa78e1458107939398aaf35162c"),
            hex!("e6d004f42a562534a47d304aaf52425773b70d11c0be3bd59112a0ccf1f0ab2b"),
            hex!("614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5"),
            hex!("564b9ffa2508e2d59c2d5f43c4ca96b7646f3b2363814dac042a89b48af183a3"),
            hex!("e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83"),
            hex!("5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715"),
            hex!("3136305dd4779e01c586fb66b0400d44606dfd3a38c51eda04dc3c059b3c3215"),
            hex!("0085f15f8357aecc4ed40fa7de7a8c44e4800ef5f556d73d6d9e8e77e99eefce"),
            hex!("c11b6869d1674f3342a366f2fc728bed396ab858a36d0d125dea64fb2495e7ac"),
            hex!("ba350a7e4e86f425f9624be90cb4a82c59263304aa02acd8fcb6e246cdc9b12c"),
            hex!("19350ec1a9d255a21556d63d9e35bfb0839ceab89d4d221e92d6cf68ba02bbd5"),
            hex!("9c3982feabacd25de79b03852235fb8c757c2f41912aeda46a5f84b534e2ad40"),
            hex!("87204b53f02a216e574b13e78a7ab11c15181ccbab05694039cfae3333e308a0"),
            hex!("81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36"),
            hex!("0678011aba74ebbdc6d79093b39aa4b6d4c88eb96043a95537633f361e1dc4ed"),
            hex!("8a45012a030697b1c0db1504c68ee0fca1ab0ac8e3ad80c032b26f7b38ea97b4"),
        ];
        let root_exp = hex!("fba6d37293ad9845ff546e9615853594c47237ee666cf5267788e14e0032f3de");
        let to_verify = [
            (
                4,
                hex!("e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83"),
            ),
            (
                5,
                hex!("5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715"),
            ),
            (
                13,
                hex!("614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5"),
            ),
        ];
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);
    }
}
