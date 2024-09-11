pub mod hash;
pub mod merkle_commitment_scheme;
use crate::merkle::hash::Hasher;
use anyhow::Error;

use std::collections::{BTreeMap, BTreeSet};
use std::{collections::VecDeque, marker::PhantomData};

use ark_ff::PrimeField;

use channel::ProverChannel;
use channel::VerifierChannel;
use channel::{fs_prover_channel::FSProverChannel, fs_verifier_channel::FSVerifierChannel};
use randomness::Prng;
use sha3::Digest;

pub struct MerkleTree<F: PrimeField, H: Hasher<F>> {
    num_leafs: usize,
    nodes: Vec<H::Output>,
    _ph: PhantomData<F>,
}

impl<F: PrimeField, H: Hasher<F>> MerkleTree<F, H> {
    /// Constructs a new MerkleTree with empty nodes.
    ///
    /// # Arguments
    ///
    /// - `num_leafs`: length of data which the tree will commit to.
    ///
    /// # Returns
    ///
    /// - `Self`: MerkleTree with empty nodes
    pub fn new(num_leafs: usize) -> Self {
        // assert num_leafs is a power of 2
        assert!(
            num_leafs.is_power_of_two(),
            "Data length is not a power of two."
        );

        // for better indexing, use an array that has one extra cell at the beginning
        let nodes: Vec<H::Output> = vec![H::Output::default(); 2 * num_leafs];

        Self {
            num_leafs,
            nodes,
            _ph: PhantomData,
        }
    }
}

impl<F: PrimeField, H: Hasher<F, Output = [u8; 32]>> MerkleTree<F, H> {
    /// Feeds the tree with data to commit on.
    ///
    /// # Arguments
    ///
    /// - `data`: input data to commit on.
    /// - `start_index`: index of the tree leaves where the data will be added.
    pub fn add_data(&mut self, data: &[H::Output], start_index: usize) {
        assert!(start_index + data.len() <= self.num_leafs);

        // copy given data to the leaves of the tree
        self.nodes.splice(
            (self.num_leafs + start_index)..(self.num_leafs + start_index + data.len()),
            data.to_vec(),
        );

        // Hash to compute all parent nodes
        let mut cur = (self.num_leafs + start_index) / 2;
        let mut sub_layer_length = data.len() / 2;

        while sub_layer_length > 0 {
            for j in cur..(cur + sub_layer_length) {
                self.nodes[j] = H::node(&[self.nodes[2 * j], self.nodes[2 * j + 1]]);
            }
            cur /= 2;
            sub_layer_length /= 2;
        }
    }

    /// Retrieves the root of the tree.
    ///
    ///
    /// # Returns
    ///
    /// Returns the root of the tree.
    pub fn get_root(&mut self) -> H::Output {
        let height_correct = self.num_leafs;

        for j in (1..height_correct).rev() {
            self.nodes[j] = H::node(&[self.nodes[2 * j], self.nodes[2 * j + 1]]);
        }

        self.nodes[1]
    }

    /// Verifies a batched Merkle-tree decommitment.
    ///
    /// # Arguments
    ///
    /// - `merkle_root`: the commitment to the Merkle-tree
    /// - `total_data_length`: length of data to be verified
    /// - `data_to_verify`: a map of (position, hash) pairs to verify
    /// - `channel`: Verifier Channel used to receive the decommitment node
    ///
    /// # Returns
    ///
    /// Returns a bool which is true if data_to_verify is present in the tree.
    pub fn verify_decommitment<P: Prng, W: Digest>(
        merkle_root: H::Output,
        total_data_length: usize,
        data_to_verify: &BTreeMap<usize, H::Output>,
        channel: &mut FSVerifierChannel<F, P, W>,
    ) -> Result<bool, Error> {
        assert!(total_data_length > 0);

        // add the nodes to verify to the set of known nodes
        let mut queue: VecDeque<(usize, H::Output)> = VecDeque::new();
        for (&key, value) in data_to_verify {
            queue.push_back((key + total_data_length, *value));
        }

        let (mut node_idx, mut node_hash) = *queue
            .front()
            .ok_or_else(|| anyhow::anyhow!("front() called on empty queue !"))?;
        let mut sib = [H::Output::default(), H::Output::default()];
        let mut sib_node_idx;
        let mut sib_node_hash = H::Output::default();
        while node_idx != 1 {
            queue
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("pop_front() called on empty queue !"))?;
            sib_node_idx = node_idx ^ 1;
            sib[node_idx & 1] = node_hash;

            if !queue.is_empty() && queue.front().unwrap().0 == sib_node_idx {
                sib_node_hash.clone_from(&queue.front().unwrap().1);
                queue.pop_front();
            } else {
                let decommitment_node = channel.recv_decommit_node(H::DIGEST_NUM_BYTES);
                match decommitment_node {
                    Ok(value) => {
                        assert_eq!(value.len(), 32);
                        let mut bytes = [0u8; 32];
                        bytes.copy_from_slice(&value);
                        sib_node_hash = bytes;
                    }

                    Err(e) => {
                        return Err(anyhow::anyhow!("failed to receive decommit node: {} !", e))
                    }
                }
            }

            sib[sib_node_idx & 1].clone_from(&sib_node_hash);
            queue.push_back((node_idx / 2, H::node(&sib)));

            node_idx = queue
                .front()
                .ok_or_else(|| anyhow::anyhow!("front() called on empty queue !"))?
                .0;
            node_hash.clone_from(&queue.front().unwrap().1);
        }

        Ok(queue.front().unwrap().1 == merkle_root)
    }

    /// Generates decommitment nodes used to verify data.
    ///
    /// # Arguments
    ///
    /// - `queries_idx`: BTreeSet [position] to query.
    /// - `channel`: Prover Channel used to send decommitmnet node.
    fn generate_decommitment<P: Prng, W: Digest>(
        &self,
        queries_idx: &BTreeSet<usize>,
        channel: &mut FSProverChannel<F, P, W>,
    ) -> Option<()> {
        assert!(!queries_idx.is_empty());

        // initialize the queue with the query leaves and fix offset
        let mut queue: VecDeque<usize> = queries_idx
            .iter()
            .cloned()
            .map(|idx| {
                assert!(idx < self.num_leafs, "query out of range");
                idx + self.num_leafs
            })
            .collect();

        let mut node_idx = queue.pop_front()?;
        while node_idx != 1 {
            queue.push_back(node_idx / 2);
            let sib_node_idx = node_idx ^ 1;

            if queue.front() == Some(&sib_node_idx) {
                // next node is the sibling, skip it
                queue.pop_front();
            } else {
                // next node is not the sibling, send node to channel
                let _ = channel.send_decommit_node(self.nodes[sib_node_idx]);
            }

            node_idx = queue.pop_front()?;
        }

        Some(())
    }
}

/// Given span of bytes, bytes_data, converts and returns them in the format of vector of hash output.
///
/// # Arguments
///
/// - `bytes_data`: input data bytes.
/// - `size_of_element`: length of element in bytes.
///
/// # Returns
///
/// Returns vector of hash output.
pub fn bytes_as_hash<F: PrimeField, H: Hasher<F, Output = [u8; 32]>>(
    bytes_data: &[u8],
    size_of_element: usize,
) -> Vec<H::Output> {
    let chunks = bytes_data.chunks_exact(size_of_element);
    assert!(chunks.remainder().is_empty());

    let bytes_as_hash: Vec<H::Output> = chunks
        .map(|chunk| {
            let chunk: [u8; 32] = chunk.try_into().expect("chunk size is incorrect");
            chunk
        })
        .collect();

    bytes_as_hash
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ark_ff::PrimeField;

    use crate::{
        merkle::hash::{Blake2s256Hasher, Hasher, Keccak256Hasher},
        merkle::MerkleTree,
    };

    use felt::Felt252;
    use hex::decode;
    use rand::Rng;

    use channel::fs_verifier_channel::FSVerifierChannel;
    use channel::{fs_prover_channel::FSProverChannel, ProverChannel};
    use randomness::keccak256::PrngKeccak256;
    use randomness::Prng;
    use sha3::Sha3_256;

    use super::hash::Poseidon3Hasher;

    pub fn hex_to_b32(hex_str: &str) -> [u8; 32] {
        let mut hex_str = String::from(hex_str);
        let padding_length = 64_i32.saturating_sub(hex_str.len() as i32);
        if padding_length > 0 {
            let padding = "0".repeat(padding_length as usize);
            hex_str.insert_str(0, &padding);
        }
        let bytes = decode(hex_str).unwrap();
        assert_eq!(bytes.len(), 32);
        let mut out_bytes = [0u8; 32];
        out_bytes.copy_from_slice(&bytes);
        out_bytes
    }

    fn test_diff_tree_diff_root<F, H>(data0: &[H::Output], data1: &[H::Output])
    where
        F: PrimeField,
        H: Hasher<F, Output = [u8; 32]>,
    {
        assert_eq!(data0.len(), data1.len());
        let mut tree = MerkleTree::<F, H>::new(data0.len());

        MerkleTree::add_data(&mut tree, data0, 0);
        let root0 = tree.get_root();

        MerkleTree::add_data(&mut tree, data1, 0);
        let root1 = tree.get_root();

        assert!(root0 != root1);
    }

    fn test_root_compute<F, H>(data0: &[H::Output], data1: &[H::Output], exp_root: H::Output)
    where
        F: PrimeField,
        H: Hasher<F, Output = [u8; 32]>,
    {
        assert_eq!(data0.len(), data1.len());
        let mut tree = MerkleTree::<F, H>::new(data0.len() * 2);

        MerkleTree::add_data(&mut tree, data0, 0);
        MerkleTree::add_data(&mut tree, data1, data0.len());

        let root0 = tree.get_root();
        let root1 = tree.get_root();
        assert_eq!(root0, root1);
        assert_eq!(root0, exp_root);
    }

    #[test]
    fn test_tree_root() {
        // test with Blake2s256
        let data0 = [
            hex_to_b32("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            hex_to_b32("d05c29c29f7db3906f02dc7fbcbb16da58c9d67de7d8c3405cf81592e7a7087b"),
            hex_to_b32("e9cdcd85e00bf03e3b7741830cfc3e94d5dd16419b1fcec02eadbf1387cbbf74"),
            hex_to_b32("8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979"),
            hex_to_b32("09114eaab98d5d3fbfd5ab29c707b5c361ec79d514a6c3bd31c5ec3ec54d55bf"),
            hex_to_b32("64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d"),
            hex_to_b32("b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e"),
            hex_to_b32("0a47848bf63587decc1675ec0ad26bd3b6734a00ebcfcf84e9191ebcacb9c94e"),
        ];
        let data1 = [
            hex_to_b32("9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297"),
            hex_to_b32("98e8177af0b18366127b14940c2eafcc1f5da635d73891d6bce7e5a5e2d3c721"),
            hex_to_b32("b9179e6abddace935de2846267c0b8ef90b575c0f1bfe2a2bc804a05e452e8f9"),
            hex_to_b32("a741d2a18d6a1d3d76b06b66febfa128ffbf9ce7ff880d811244ec75887b25e0"),
            hex_to_b32("a5bad18826679e52eb722f6fbd3d45cd08add9cec39a15a1046b7f2b17507565"),
            hex_to_b32("33ae65efe662938f03694fab95a0ad87653de68e811b9b41292433dc1433c559"),
            hex_to_b32("53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440"),
            hex_to_b32("6dc75f281250f2d2194b86e272be6662aa28f4ee2e5202556a0796d50a7469dc"),
        ];
        let root_exp =
            hex_to_b32("b7a3cd28384b4baea480d070801106bf07f56f848acf271f6b6415ddc355f8e9");
        test_diff_tree_diff_root::<Felt252, Blake2s256Hasher<Felt252>>(&data0, &data1);
        test_root_compute::<Felt252, Blake2s256Hasher<Felt252>>(&data0, &data1, root_exp);

        // test with Keccak256
        let data0 = [
            hex_to_b32("1edc3c8392034de0f516534ed7f5441f971d6fa78e1458107939398aaf35162c"),
            hex_to_b32("e6d004f42a562534a47d304aaf52425773b70d11c0be3bd59112a0ccf1f0ab2b"),
            hex_to_b32("614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5"),
            hex_to_b32("564b9ffa2508e2d59c2d5f43c4ca96b7646f3b2363814dac042a89b48af183a3"),
            hex_to_b32("e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83"),
            hex_to_b32("5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715"),
            hex_to_b32("3136305dd4779e01c586fb66b0400d44606dfd3a38c51eda04dc3c059b3c3215"),
            hex_to_b32("0085f15f8357aecc4ed40fa7de7a8c44e4800ef5f556d73d6d9e8e77e99eefce"),
        ];
        let data1 = [
            hex_to_b32("c11b6869d1674f3342a366f2fc728bed396ab858a36d0d125dea64fb2495e7ac"),
            hex_to_b32("ba350a7e4e86f425f9624be90cb4a82c59263304aa02acd8fcb6e246cdc9b12c"),
            hex_to_b32("19350ec1a9d255a21556d63d9e35bfb0839ceab89d4d221e92d6cf68ba02bbd5"),
            hex_to_b32("9c3982feabacd25de79b03852235fb8c757c2f41912aeda46a5f84b534e2ad40"),
            hex_to_b32("87204b53f02a216e574b13e78a7ab11c15181ccbab05694039cfae3333e308a0"),
            hex_to_b32("81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36"),
            hex_to_b32("0678011aba74ebbdc6d79093b39aa4b6d4c88eb96043a95537633f361e1dc4ed"),
            hex_to_b32("8a45012a030697b1c0db1504c68ee0fca1ab0ac8e3ad80c032b26f7b38ea97b4"),
        ];
        let root_exp =
            hex_to_b32("fba6d37293ad9845ff546e9615853594c47237ee666cf5267788e14e0032f3de");
        test_diff_tree_diff_root::<Felt252, Keccak256Hasher<Felt252>>(&data0, &data1);
        test_root_compute::<Felt252, Keccak256Hasher<Felt252>>(&data0, &data1, root_exp);

        // test with Poseidon3
        let data0 = [
            hex_to_b32("36313083bda3d5d1f1ade3dfb59311bd38f583c92f570719cb41be7e46e6ee5"),
            hex_to_b32("353699d84e4b67ce55874046b58e501a73582c2b16ceed4ff651e6439089483"),
            hex_to_b32("452135053077d0c52f8057d5a418a67bdecec4afb240d59613e885e0e71a0bf"),
            hex_to_b32("4705a84ca4ee4bc971f9bdf51fd2f74e1273ca72261c0a5845e89dc5c3a1a00"),
        ];
        let data1 = [
            hex_to_b32("27c1e003f81b13f5282b863dceddb162dd6180150eabc16d2267b5aa25c1786"),
            hex_to_b32("27b3118926ffe13b70a3a3ed551869cc31d344551e5a7013a9146d0fa84f06a"),
            hex_to_b32("5f7701e493613cfb4e3b0600eccf74d4916cc66aa2631ab374e73d3a43bcee4"),
            hex_to_b32("5e598f5a773a9ab554121b8d4937bf1b383393f10ae49f98532a2beea1f7852"),
        ];
        let root_exp =
            hex_to_b32("3a80041b3647dd472cb7979dc422e9b7d86d4bcd08b957a6ae05caf6c6e189b");
        test_diff_tree_diff_root::<Felt252, Poseidon3Hasher<Felt252>>(&data0, &data1);
        test_root_compute::<Felt252, Poseidon3Hasher<Felt252>>(&data0, &data1, root_exp);
    }

    fn test_verify_true<F, H>(data: &[H::Output], root_exp: H::Output)
    where
        F: PrimeField,
        H: Hasher<F, Output = [u8; 32]>,
    {
        let mut rng = rand::thread_rng();

        let mut tree = MerkleTree::<F, H>::new(data.len());
        MerkleTree::add_data(&mut tree, data, 0);
        let root = tree.get_root();
        assert_eq!(root, root_exp);

        let num_queries = rng.gen_range(1..=data.len());
        let mut queries = BTreeSet::new();
        let mut query_data = BTreeMap::new();
        while queries.len() < num_queries {
            let query = rng.gen_range(0..=(data.len() - 1));
            queries.insert(query);
            query_data.insert(query, data[query].clone());
        }

        let prng = PrngKeccak256::new();
        let mut prover_channel: FSProverChannel<F, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(prng);
        tree.generate_decommitment::<PrngKeccak256, Sha3_256>(&queries, &mut prover_channel);

        let prng = PrngKeccak256::new();
        let mut verifier_channel: FSVerifierChannel<F, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(prng, prover_channel.get_proof());
        assert!(MerkleTree::<F, H>::verify_decommitment(
            root,
            data.len(),
            &query_data,
            &mut verifier_channel
        )
        .unwrap());
    }

    fn test_verify_false<F, H>(
        data: &[H::Output],
        root_exp: H::Output,
        query_data: &BTreeMap<usize, H::Output>,
    ) where
        F: PrimeField,
        H: Hasher<F, Output = [u8; 32]>,
    {
        let queries: BTreeSet<usize> = query_data.keys().cloned().collect();

        let mut tree = MerkleTree::<F, H>::new(data.len());
        MerkleTree::add_data(&mut tree, data, 0);
        let root = tree.get_root();
        assert_eq!(root, root_exp);

        let prng = PrngKeccak256::new();
        let mut prover_channel: FSProverChannel<F, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(prng);
        tree.generate_decommitment::<PrngKeccak256, Sha3_256>(&queries, &mut prover_channel);

        let prng = PrngKeccak256::new();
        let mut verifier_channel: FSVerifierChannel<F, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(prng, prover_channel.get_proof());
        assert!(!MerkleTree::<F, H>::verify_decommitment(
            root,
            data.len(),
            &query_data,
            &mut verifier_channel
        )
        .unwrap());
    }

    #[test]
    fn test_verify() {
        // tests using Blake2s256
        let input = [hex_to_b32(
            "216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125",
        )];
        let root_exp =
            hex_to_b32("216acdc6a1fe9e6b89605b2eb3452c613b4ebc09af6c8477bf79d69fa9ec1125");
        let to_verify = BTreeMap::from([(
            0,
            hex_to_b32("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
        )]);
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            hex_to_b32("6dc48ad654bc4a3e3c8f3270a987b2782af1707e78e1512018f16fdee124bdbd"),
        ];
        let root_exp =
            hex_to_b32("b823ac891cee85512521528e1d61cdcad829080392b63f393e46adc213862af9");
        let to_verify = BTreeMap::from([
            (
                0,
                hex_to_b32("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            ),
            (
                1,
                hex_to_b32("d7005ac2e5ece2a48746ae40264076edf63fc833532572d359a0c47cbc42c482"),
            ),
        ]);
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            hex_to_b32("12ee05a2b647db0371c79c13842574c13ccc3610faa888aa4ec4764407fe84ed"),
            hex_to_b32("aa7ea89c5a679c4aa2c7f85d58988bc42eb97828f5bf18a8fca88f52fe3cf933"),
            hex_to_b32("1c16cd6af66980b3f38f66a213a82b0c5d3480296d6315d12ea3862e72e29a8c"),
        ];
        let root_exp =
            hex_to_b32("57989eb39d929071d2f3a4400067d00e4d77671d9ed682a8cdd2d4e11d3f5aea");
        let to_verify = BTreeMap::from([
            (
                0,
                hex_to_b32("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
            (
                3,
                hex_to_b32("1363b8220c90c05d93c279ab287fadfe2e223543ca46dee65b32ecd7d7bc891c"),
            ),
        ]);
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f"),
            hex_to_b32("82ce423aac9f3cf8b8c28553a5ae607f2586c2f0ca695d4ec97136a8b7fc9f91"),
            hex_to_b32("7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89"),
            hex_to_b32("9e74347b0b870523de79a2117c2f6954ccdbef01baa6850e22680dd9a7bbf0f2"),
            hex_to_b32("c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1"),
            hex_to_b32("1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d"),
            hex_to_b32("0a614f0d06d701ddc9674406097452de7cf9df5fff1382d167a5f6801620cbfa"),
            hex_to_b32("0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a"),
        ];
        let root_exp =
            hex_to_b32("594e2c4c084f406df0130a252fe030a64a1539225e2b4156f04cf4cefcd75b01");
        let to_verify = BTreeMap::from([
            (
                2,
                hex_to_b32("7cf9a07e6169885c6c2a3e8e32ea3aec234d79095a775aeaf04250276c77ed89"),
            ),
            (
                3,
                hex_to_b32("a9a9cce2406aac65d8b8c2e64fa88c20af029373d784bb4357db4521cb05df2f"),
            ),
            (
                4,
                hex_to_b32("c34262d4a92511ae195259274a83191dd6dd41659621b152cd88b59181f0d8f1"),
            ),
            (
                5,
                hex_to_b32("1998e773220e155214ae129d65c0bfe98b0b729d69b5fa487ca2343783cc8a3d"),
            ),
            (
                7,
                hex_to_b32("0c5ba953f251b55655ac4cda2622f13e4d68016a3297ff29e0b8d21984ccc33a"),
            ),
        ]);
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            hex_to_b32("d05c29c29f7db3906f02dc7fbcbb16da58c9d67de7d8c3405cf81592e7a7087b"),
            hex_to_b32("e9cdcd85e00bf03e3b7741830cfc3e94d5dd16419b1fcec02eadbf1387cbbf74"),
            hex_to_b32("8951af3f7576fea7f4f29422cecf9a072487af9b5fbc0eb06d23889e81d98979"),
            hex_to_b32("09114eaab98d5d3fbfd5ab29c707b5c361ec79d514a6c3bd31c5ec3ec54d55bf"),
            hex_to_b32("64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d"),
            hex_to_b32("b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e"),
            hex_to_b32("0a47848bf63587decc1675ec0ad26bd3b6734a00ebcfcf84e9191ebcacb9c94e"),
            hex_to_b32("9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297"),
            hex_to_b32("98e8177af0b18366127b14940c2eafcc1f5da635d73891d6bce7e5a5e2d3c721"),
            hex_to_b32("b9179e6abddace935de2846267c0b8ef90b575c0f1bfe2a2bc804a05e452e8f9"),
            hex_to_b32("a741d2a18d6a1d3d76b06b66febfa128ffbf9ce7ff880d811244ec75887b25e0"),
            hex_to_b32("a5bad18826679e52eb722f6fbd3d45cd08add9cec39a15a1046b7f2b17507565"),
            hex_to_b32("33ae65efe662938f03694fab95a0ad87653de68e811b9b41292433dc1433c559"),
            hex_to_b32("53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440"),
            hex_to_b32("6dc75f281250f2d2194b86e272be6662aa28f4ee2e5202556a0796d50a7469dc"),
        ];
        let root_exp =
            hex_to_b32("b7a3cd28384b4baea480d070801106bf07f56f848acf271f6b6415ddc355f8e9");
        let to_verify = BTreeMap::from([
            (
                0,
                hex_to_b32("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            ),
            (
                3,
                hex_to_b32("837cd6db8f93d5ddfeaaba5509551c69c760c099e97969cfa04047ae65c33c8c"),
            ),
            (
                5,
                hex_to_b32("64a6d52004718db41784b1c1738ab18fb48b9ef323065151ea603dbf50a8c36d"),
            ),
            (
                6,
                hex_to_b32("b36e83f5fdf23aa5799c0f0358af60979e919c88cb08a2d29c122f644e2f167e"),
            ),
            (
                8,
                hex_to_b32("9be40d50e1559d36162d268b4af350c65fc8a7b3dc1cbe82a1b5b4e33726d297"),
            ),
            (
                14,
                hex_to_b32("53ebf1e5f6477b7f0d7a9b631d5ed97f0a14ca54c61173bb50ae98b8d7d81440"),
            ),
        ]);
        test_verify_true::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Blake2s256Hasher<Felt252>>(&input, root_exp, &to_verify);

        // tests using Keccak256
        let input = [hex_to_b32(
            "ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127",
        )];
        let root_exp =
            hex_to_b32("ed5f0c2a7fdf07022be01ec165a50601807910d9dcc0ce3def6d291e9675e127");
        let to_verify = BTreeMap::from([(
            0,
            hex_to_b32("8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2"),
        )]);
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2"),
            hex_to_b32("a1482873bccd9dd66ec6ef8c8a092c7f70839af97b22936ffa5606f1cd28dcea"),
        ];
        let root_exp =
            hex_to_b32("f272f3ba749e68b9ccd51f322c6ae6cac8734967ecc31c1058b8f9a8c99fb083");
        let to_verify = BTreeMap::from([(
            1,
            hex_to_b32("8b471e237284b2a8d0845469431ecc163264d4924c984987a4dac5c40e2c34f2"),
        )]);
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("b77b78e96b3f1de1a11ad49cae9804d8fd754123c916f25c638dd84d7ef8687d"),
            hex_to_b32("15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e"),
            hex_to_b32("2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793"),
            hex_to_b32("c0e9d48d53c45ebfa3cd5ba2492638322463df296bab03b6492f4f11536e7e0e"),
        ];
        let root_exp =
            hex_to_b32("24562159dd8260d379ae390b80cb8266da3f4469bc6643db3b5c3f760c126b83");
        let to_verify = BTreeMap::from([
            (
                1,
                hex_to_b32("15014fef710a715ea5a879a328912d8e1feefbc23137e8bf223139285fd9203e"),
            ),
            (
                3,
                hex_to_b32("2483654ae6756dc99e99173802f5737cf44d23ffa8b8fae732160c14db636793"),
            ),
        ]);
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("66661b6925e2abacbb63f975277eb908fa7d3f2c4de8d2cfe9788fd0e2af3234"),
            hex_to_b32("fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1"),
            hex_to_b32("abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9"),
            hex_to_b32("6c63d57004dd9fb1f6a65d111e2230cca32f9aff392d0b84e6ba8c47fe093ae0"),
            hex_to_b32("1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6"),
            hex_to_b32("3213a156ac8029f8355208b9e6afd496775a494bee3bf4a2bbdaade80da9cc93"),
            hex_to_b32("8e62dab2bb313c8e2ed86d601e47e3307e919fac5042be9faa53ba83902dd0a8"),
            hex_to_b32("2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95"),
        ];
        let root_exp =
            hex_to_b32("50a1b9b02edd048756030d39f12e795ab7885565964dde0de6e5de1655f0d793");
        let to_verify = BTreeMap::from([
            (
                0,
                hex_to_b32("fdc012059327bae5b7796e255b251a5eefcc4310f8438bb738c12964f0630da1"),
            ),
            (
                3,
                hex_to_b32("abe2a0f9213f7033dccb60a9742f9edcbbb7e952ca4eaf2736735155d66a9be9"),
            ),
            (
                4,
                hex_to_b32("1e0841b00ea5648b2996203d58818b39e7c951c7f12de730aecaa69670e324f6"),
            ),
            (
                7,
                hex_to_b32("2fe79a0be4d26e69164bdd96404780e8e504c5e96eb975975236579c8b569a95"),
            ),
        ]);
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("1edc3c8392034de0f516534ed7f5441f971d6fa78e1458107939398aaf35162c"),
            hex_to_b32("e6d004f42a562534a47d304aaf52425773b70d11c0be3bd59112a0ccf1f0ab2b"),
            hex_to_b32("614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5"),
            hex_to_b32("564b9ffa2508e2d59c2d5f43c4ca96b7646f3b2363814dac042a89b48af183a3"),
            hex_to_b32("e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83"),
            hex_to_b32("5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715"),
            hex_to_b32("3136305dd4779e01c586fb66b0400d44606dfd3a38c51eda04dc3c059b3c3215"),
            hex_to_b32("0085f15f8357aecc4ed40fa7de7a8c44e4800ef5f556d73d6d9e8e77e99eefce"),
            hex_to_b32("c11b6869d1674f3342a366f2fc728bed396ab858a36d0d125dea64fb2495e7ac"),
            hex_to_b32("ba350a7e4e86f425f9624be90cb4a82c59263304aa02acd8fcb6e246cdc9b12c"),
            hex_to_b32("19350ec1a9d255a21556d63d9e35bfb0839ceab89d4d221e92d6cf68ba02bbd5"),
            hex_to_b32("9c3982feabacd25de79b03852235fb8c757c2f41912aeda46a5f84b534e2ad40"),
            hex_to_b32("87204b53f02a216e574b13e78a7ab11c15181ccbab05694039cfae3333e308a0"),
            hex_to_b32("81ac8a8b30bf7170f11d23847729f335bfeaa4107a7acd68a87eb43a097bfc36"),
            hex_to_b32("0678011aba74ebbdc6d79093b39aa4b6d4c88eb96043a95537633f361e1dc4ed"),
            hex_to_b32("8a45012a030697b1c0db1504c68ee0fca1ab0ac8e3ad80c032b26f7b38ea97b4"),
        ];
        let root_exp =
            hex_to_b32("fba6d37293ad9845ff546e9615853594c47237ee666cf5267788e14e0032f3de");
        let to_verify = BTreeMap::from([
            (
                4,
                hex_to_b32("e4ef3f3ea1ae8c961aa6ef36cfdd91831aaa2c92d832aee4687a46144ebbef83"),
            ),
            (
                5,
                hex_to_b32("5462d01e69b3006ea33734a6eea7dbf05d983a46fed38522ac2fae8373b0c715"),
            ),
            (
                13,
                hex_to_b32("614a71ae7c9c127e71884f6bc64454842977b58be4dfcd3a2db8763bba5e8ae5"),
            ),
        ]);
        test_verify_true::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Keccak256Hasher<Felt252>>(&input, root_exp, &to_verify);

        // tests using Poseidon3
        let input = [hex_to_b32(
            "c89ae25f3fa9f809dc7e255509bbe13d8ee41e7050a1757d10b14380479762",
        )];
        let root_exp = hex_to_b32("c89ae25f3fa9f809dc7e255509bbe13d8ee41e7050a1757d10b14380479762");
        let to_verify = BTreeMap::from([(
            0,
            hex_to_b32("061e4f02a5fb16a37cef579d5a3bc31ab6bc3dfb112d0bbe440afcf4ef6b2dbd"),
        )]);
        test_verify_true::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("02f926674daed935c5ec20daf9e116f45e74ebad57909889e6c4e60ac9a7239a"),
            hex_to_b32("059089a262fd310d47e824b3add73c7bbedd67b2f111b3d67a48177765891a1f"),
        ];
        let root_exp =
            hex_to_b32("07572153d1bc66733cf79b40c1427cdf8c5754e71254491da93c3a789c5f1af3");
        let to_verify = BTreeMap::from([(
            1,
            hex_to_b32("0070336f8988bd453e936b157afcfcf07fa2924e5d670f36fcc9cf01ff09fc6f"),
        )]);
        test_verify_true::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("167c6d08b3aec83b4b27bce5df9c9ba4dce709ea7d40497f7bf2cc2b787cc41"),
            hex_to_b32("5934aa1631d1759018513505f5407abb4e232bdab2aa74e48cbbe1cec301387"),
            hex_to_b32("56daeb7ceeeda161e5ee669bf88202e034216fa8424c89e1408ad77ea6b8829"),
            hex_to_b32("1808bca5f11183aaf603971b0ac93f5b4558c47f0777e5db2cc14e3b512c66"),
        ];
        let root_exp =
            hex_to_b32("32cbc8162b4c5f91efd2a5f2c2701fbabafdd08ea8ce7f06d6f0ee2a28cdef5");
        let to_verify = BTreeMap::from([(
            2,
            hex_to_b32("1f8c6141be9707ec0a767257d522ef2bf321a2e9efc6b93136e3dc9d9665d26"),
        )]);
        test_verify_true::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp, &to_verify);

        let input = [
            hex_to_b32("726cb96d8303497a472d118b54046e2966076ad68b3c39a24cd96a8c5ae466b"),
            hex_to_b32("6380a19495b51c52bd73a7111d5a4b0c022efedfb90d46660301ce365b0069c"),
            hex_to_b32("4c3abd3626c95cd55e330856ebc8cc85c8871349c28079149e1ee19f4ba7809"),
            hex_to_b32("438059b58dd33650037db7274014d00ce07a1a62ddbf68b43b10a91de504606"),
            hex_to_b32("573f3d932cbfc0070b76aa652a82bd93bc0e92517068092b252788bd54bbe84"),
            hex_to_b32("26a109ece8e786838ad839a0513db66ff403cb97e6c35396b8e82ef014729ff"),
            hex_to_b32("355834fe0fb7afcbd719967841a691822148ff959c16e5ba67114a9774c57e5"),
            hex_to_b32("203b523ca101a81bbb94013b9408968c324e35340081375f77f628114441622"),
        ];
        let root_exp =
            hex_to_b32("577c0d4d52b1b4b583e4f6be73ed16b33067318b0d9eda930c47f60679fe5c0");
        let to_verify = BTreeMap::from([
            (
                0,
                hex_to_b32("726cb96d8303497a472d118b54046e2966076ad68b3c39a24cd96a8c5ae466b"),
            ),
            (
                1,
                hex_to_b32("6380a19495b51c52bd73a7111d5a4b0c022efedfb90d46660301ce365b0069c"),
            ),
            (
                2,
                hex_to_b32("4c3abd3626c95cd55e330856ebc8cc85c8871349c28079149e1ee19f4ba7809"),
            ),
            (
                3,
                hex_to_b32("28dc328d44f2a150c15de51b322b020adbf685b520cac210a314fa98efedab3"),
            ),
            (
                4,
                hex_to_b32("573f3d932cbfc0070b76aa652a82bd93bc0e92517068092b252788bd54bbe84"),
            ),
            (
                5,
                hex_to_b32("26a109ece8e786838ad839a0513db66ff403cb97e6c35396b8e82ef014729ff"),
            ),
            (
                6,
                hex_to_b32("355834fe0fb7afcbd719967841a691822148ff959c16e5ba67114a9774c57e5"),
            ),
        ]);
        test_verify_true::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp.clone());
        test_verify_false::<Felt252, Poseidon3Hasher<Felt252>>(&input, root_exp, &to_verify);
    }
}
