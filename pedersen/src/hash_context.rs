use crate::constants::{EC_SUBSET_SUM_HEIGHT, ELEMENT_BITS_HASH, N_HASH_INPUTS, POINTS};
use crate::stark_curve::Affine;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use felt::Felt252;

#[allow(dead_code)]
pub struct PedersenHashContext {
    n_element_bits: usize,
    ec_subset_sum_height: usize,
    n_inputs: usize,
    shift_point: Affine,
    points: Vec<Affine>,
}

impl Default for PedersenHashContext {
    fn default() -> Self {
        PedersenHashContext {
            n_element_bits: ELEMENT_BITS_HASH,
            ec_subset_sum_height: EC_SUBSET_SUM_HEIGHT,
            n_inputs: N_HASH_INPUTS,
            shift_point: POINTS[0],
            points: POINTS[2..(2 + N_HASH_INPUTS * ELEMENT_BITS_HASH)].to_vec(),
        }
    }
}

impl PedersenHashContext {
    pub fn hash(&self, hash_inputs: &[Felt252]) -> Felt252 {
        assert_eq!(
            self.points.len(),
            self.n_element_bits * hash_inputs.len(),
            "The number of points is not equal to the number of bits in total in the hash input."
        );

        let mut cur_sum = self.shift_point;
        for (i, input) in hash_inputs.iter().enumerate() {
            let offset = self.n_element_bits * i;

            cur_sum = Self::hash_internal(
                cur_sum,
                &self.points[offset..(offset + self.n_element_bits)],
                *input,
            );
        }
        cur_sum.x
    }

    fn hash_internal(shift_point: Affine, points: &[Affine], selector_value: Felt252) -> Affine {
        let mut sum = shift_point;
        let selector_value_as_big_int = selector_value.into_bigint();
        let selector_bits = selector_value_as_big_int.to_bits_le();

        assert!(points.len() <= selector_bits.len());

        for (j, p) in points.iter().enumerate() {
            assert!(
                sum.x().unwrap() != p.x().unwrap(),
                "Adding a point to itself or to its inverse point."
            );
            if selector_bits[j] {
                sum = (sum + p).into();
            }
        }
        sum
    }

    pub fn hash_elements(&self, x: Felt252, y: Felt252) -> Felt252 {
        self.hash(&[x, y])
    }
}
