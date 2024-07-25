use ark_ff::Field;

pub trait Hasher<F: Field> {
    type Output: Clone + Eq;

    // compress a list of internal nodes into a single internal node
    #[allow(dead_code)]
    fn node(input: &[Self::Output]) -> Self::Output;

    // compress a list of leaves into a single leaf
    #[allow(dead_code)]
    fn leaf(input: &[F]) -> Self::Output;
}