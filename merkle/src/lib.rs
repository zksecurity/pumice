use std::{collections::VecDeque, marker::PhantomData};

use ark_ff::Field;

#[allow(dead_code)]
pub struct MerkleTree<F: Field, H: Hasher<F>> {
    _ph: PhantomData<(F, H)>,
    #[allow(dead_code)]
    levels: usize,
    leaves: usize,
}

impl<F: Field, H: Hasher<F>> MerkleTree<F, H> {
    #[allow(dead_code)]
    pub fn new(levels: usize) -> Self {
        let leaves = 1 << levels;
        Self {
            _ph: PhantomData,
            levels,
            leaves,
        }
    }
}

pub trait Hasher<F: Field> {
    type Output: Clone + Eq;

    // compress a list of internal nodes into a single internal node
    #[allow(dead_code)]
    fn node(input: &[Self::Output]) -> Self::Output;

    // compress a list of leaves into a single leaf
    #[allow(dead_code)]
    fn leaf(input: &[F]) -> Self::Output;
}

impl<F: Field, H: Hasher<F>> MerkleTree<F, H> {
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
    #[allow(dead_code)]
    #[allow(clippy::result_unit_err)]
    pub fn verify_decommitment(
        &self,
        comm: H::Output,
        to_verify: &[(usize, H::Output)],
        siblings: impl Iterator<Item = H::Output>,
    ) -> Result<(), ()> {
        if self.root_decommitment(to_verify, siblings).ok_or(())? == comm {
            Ok(())
        } else {
            Err(())
        }
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
    #[allow(dead_code)]
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

                // merge the node with its sibling
                ((idx, hash), Some((nxt_idx, nxt_hash))) => {
                    // retrieve the sibling of the node
                    let sibl = match nxt_idx == idx ^ 1 {
                        true => nxt_hash,
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

                // any other case is invalid (bad proof)
                _ => break None,
            }
        }
    }
}
