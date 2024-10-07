use std::collections::BTreeSet;

use ark_ff::{FftField, PrimeField};
use ark_poly::EvaluationDomain;
use channel::FSChannel;
use commitment_scheme::table_utils::RowCol;
use sha3::Digest;

use crate::stone_domain::get_field_element_at_index;
use crate::{folder::MultiplicativeFriFolder, parameters::FriParameters};

// Given query indices that refer to FRI's second layer,
// compute the indices of the cosets in the first layer.
pub fn second_layer_queries_to_first_layer_queries(
    query_indices: &[u64],
    first_fri_step: usize,
) -> Vec<u64> {
    let first_layer_coset_size = (1 << first_fri_step) as u64;
    query_indices
        .iter()
        .copied()
        .flat_map(|idx| (idx * first_layer_coset_size)..((idx + 1) * first_layer_coset_size))
        .collect()
}

// Computes the element from the next FRI layer,
// given the corresponding coset from the current layer.
// For example, if fri_step_list[layer_num] = 1, this function behaves the same as
// next_layer_element_from_two_previous_layer_elements().
pub fn apply_fri_layers<F: FftField + PrimeField, E: EvaluationDomain<F>>(
    elements: &[F],
    eval_point: &F,
    params: &FriParameters<F, E>,
    layer_num: usize,
    mut first_element_index: usize,
) -> F {
    let mut curr_eval_point = *eval_point;
    let mut cumulative_fri_step = 0;
    for i in 0..layer_num {
        cumulative_fri_step += params.fri_step_list[i];
    }

    let layer_fri_step = params.fri_step_list[layer_num];
    assert_eq!(
        elements.len(),
        1 << layer_fri_step,
        "Number of elements is not consistent with the fri_step parameter."
    );

    let mut cur_layer = elements.to_vec();
    for basis_index in cumulative_fri_step..(cumulative_fri_step + layer_fri_step) {
        let fft_domain = params.fft_domains[basis_index];

        let mut next_layer = Vec::with_capacity(cur_layer.len() / 2);
        for j in (0..cur_layer.len()).step_by(2) {
            let res = MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
                cur_layer[j],
                cur_layer[j + 1],
                curr_eval_point,
                get_field_element_at_index(&fft_domain, first_element_index + j)
                    .inverse()
                    .unwrap(),
            );
            next_layer.push(res);
        }

        cur_layer = next_layer;
        // ApplyBasisTransform just calculates square of curr_eval_point
        curr_eval_point = curr_eval_point.square();
        first_element_index /= 2;
    }

    assert_eq!(cur_layer.len(), 1, "Expected number of elements to be one.");
    cur_layer[0]
}

pub fn choose_query_indices<F: FftField + PrimeField, E: EvaluationDomain<F>, W: Digest>(
    params: &FriParameters<F, E>,
    channel: &mut dyn FSChannel<Field = F, PowHash = W>,
) -> Vec<u64> {
    let domain_size = params.fft_domains[params.fri_step_list[0]].size();
    let n_queries = params.n_queries;
    let proof_of_work_bits = params.proof_of_work_bits;

    let _ = channel.apply_proof_of_work(proof_of_work_bits);

    let mut query_indices = Vec::with_capacity(n_queries);
    for _ in 0..n_queries {
        let random_index = channel.draw_number(domain_size as u64);
        query_indices.push(random_index);
    }

    query_indices.sort_unstable();
    query_indices
}

// Given the query indices (of FRI's second layer),
// we compute the data queries and integrity queries for the next layer of FRI.
// Data queries are queries whose data needs to go over the channel.
// Integrity queries are ones that each party can compute based on previously known information.
//
// For example, if fri_step of the corresponding layer is 3,
// then the size of the coset is 8. The verifier will be able to compute one element (integrity query)
// and the other 7 will be sent in the channel (data queries).
//
// Note: The two resulting sets are disjoint.
pub fn next_layer_data_and_integrity_queries<F: FftField + PrimeField, E: EvaluationDomain<F>>(
    params: &FriParameters<F, E>,
    query_indices: &[u64],
    layer: usize,
) -> (BTreeSet<RowCol>, BTreeSet<RowCol>) {
    let cumulative_fri_step = params.fri_step_list[1..layer].iter().sum::<usize>();
    let layer_fri_step = params.fri_step_list[layer];

    let mut integrity_queries: BTreeSet<RowCol> = BTreeSet::new();
    let mut data_queries: BTreeSet<RowCol> = BTreeSet::new();

    for &idx in query_indices {
        integrity_queries.insert(get_table_prover_row_col(
            idx >> cumulative_fri_step,
            layer_fri_step,
        ));
    }

    for &idx in query_indices {
        let coset_row = get_table_prover_row(idx >> cumulative_fri_step, layer_fri_step);
        for coset_col in 0..(1 << layer_fri_step) {
            let query = RowCol::new(coset_row, coset_col);
            if !integrity_queries.contains(&query) {
                data_queries.insert(query);
            }
        }
    }

    (data_queries, integrity_queries)
}

// Given the query index in the layer (1D), calculate the cell position in the 2D table
// according to coset size (always power of 2).
// fri_step is a log2 of coset size (row_size).
pub fn get_table_prover_row_col(query_index: u64, fri_step: usize) -> RowCol {
    RowCol::new(
        get_table_prover_row(query_index, fri_step),
        get_table_prover_col(query_index, fri_step),
    )
}

// Logic: query_index >> fri_step == query_index / Pow2(fri_step) == query_index / row_size.
pub fn get_table_prover_row(query_index: u64, fri_step: usize) -> usize {
    (query_index >> fri_step) as usize
}

// Logic: query_index & (Pow2(fri_step) - 1) == query_index % row_size
// (Pow2(fri_step) - 1) is a mask of 1s to the row_size.
pub fn get_table_prover_col(query_index: u64, fri_step: usize) -> usize {
    (query_index & ((1 << fri_step) - 1)) as usize
}

#[cfg(test)]
mod tests {
    use crate::parameters::FriParameters;
    use crate::{
        folder::MultiplicativeFriFolder,
        stone_domain::{get_field_element_at_index, make_fft_domains},
    };
    use ark_ff::Field;
    use ark_ff::UniformRand;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    use felt::Felt252;

    use super::apply_fri_layers;

    #[test]
    fn test_apply_fri_layer_correctness() {
        let mut rng = rand::thread_rng();

        let bases = make_fft_domains::<Felt252>(5, Felt252::rand(&mut rng));
        let params = FriParameters::new(vec![1, 2], 1, 1, bases.clone(), 15);
        let eval_point = Felt252::rand(&mut rng);

        // fri_step = 1.
        let elements: Vec<Felt252> = (0..2).map(|_| Felt252::rand(&mut rng)).collect();
        let coset_offset = 4;
        let fri_out = apply_fri_layers(&elements, &eval_point, &params, 0, coset_offset);
        let two_to_one_out =
            MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
                elements[0],
                elements[1],
                eval_point,
                get_field_element_at_index(&bases[0], coset_offset)
                    .inverse()
                    .unwrap(),
            );
        assert_eq!(fri_out, two_to_one_out);

        // fri_step = 2.
        let elements2: Vec<Felt252> = (0..4).map(|_| Felt252::rand(&mut rng)).collect();
        let coset_offset2 = 12;
        let fri_out2 = apply_fri_layers(&elements2, &eval_point, &params, 1, coset_offset2);

        let fold_0_1 = MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
            elements2[0],
            elements2[1],
            eval_point,
            get_field_element_at_index(&bases[1], coset_offset2)
                .inverse()
                .unwrap(),
        );
        let fold_2_3 = MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
            elements2[2],
            elements2[3],
            eval_point,
            get_field_element_at_index(&bases[1], coset_offset2 + 2)
                .inverse()
                .unwrap(),
        );
        let two_to_one_out2 =
            MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
                fold_0_1,
                fold_2_3,
                eval_point * eval_point,
                get_field_element_at_index(&bases[2], coset_offset2 / 2)
                    .inverse()
                    .unwrap(),
            );
        assert_eq!(fri_out2, two_to_one_out2);
    }

    #[test]
    fn test_apply_fri_layer_poly() {
        let mut rng = rand::thread_rng();
        let fri_step = 3;
        let offset = Felt252::rand(&mut rng);
        let bases = make_fft_domains::<Felt252>(fri_step, offset);
        let eval_point = Felt252::rand(&mut rng);
        let params = FriParameters::new(vec![fri_step], 1, 1, bases.clone(), 15);

        let coeffs: Vec<Felt252> = (0..(1 << fri_step))
            .map(|_| Felt252::rand(&mut rng))
            .collect();
        let poly = DensePolynomial::from_coefficients_vec(coeffs);

        let mut elements = Vec::with_capacity(bases[0].size as usize);
        for i in 0..bases[0].size {
            let x = &get_field_element_at_index(&bases[0], i as usize);
            elements.push(poly.evaluate(x));
        }
        let res = apply_fri_layers(&elements, &eval_point, &params, 0, 0);
        let correction_factor = Felt252::from(1 << fri_step);
        assert_eq!(poly.evaluate(&eval_point) * correction_factor, res);
    }
}
