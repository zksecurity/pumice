use ark_ff::FftField;
use ark_poly::EvaluationDomain;

use crate::stone_domain::get_field_element_at_index;
use crate::{folder::MultiplicativeFriFolder, parameters::FriParameters};

pub fn second_layer_queries_to_first_layer_queries(
    query_indices: &[u64],
    first_fri_step: usize,
) -> Vec<u64> {
    let first_layer_coset_size = 1 << first_fri_step;
    let mut first_layer_queries = Vec::with_capacity(query_indices.len() * first_layer_coset_size);

    for &idx in query_indices {
        for i in (idx * first_layer_coset_size as u64)..((idx + 1) * first_layer_coset_size as u64)
        {
            first_layer_queries.push(i);
        }
    }

    first_layer_queries
}

pub fn apply_fri_layers<F: FftField, E: EvaluationDomain<F>>(
    elements: &[F],
    eval_point: Option<F>,
    params: &FriParameters<F, E>,
    layer_num: usize,
    mut first_element_index: usize,
) -> F {
    let mut curr_eval_point = eval_point;
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
        assert!(
            curr_eval_point.is_some(),
            "evaluation point doesn't have a value"
        );
        let fft_domain = params.fft_domains[basis_index];

        let mut next_layer = Vec::with_capacity(cur_layer.len() / 2);
        for j in (0..cur_layer.len()).step_by(2) {
            next_layer.push(
                MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
                    &cur_layer[j],
                    &cur_layer[j + 1],
                    &curr_eval_point.unwrap(),
                    &get_field_element_at_index(&fft_domain, first_element_index + j as usize),
                ),
            );
        }

        cur_layer = next_layer;
        // ApplyBasisTransform just calculates square of curr_eval_point
        curr_eval_point = Some(curr_eval_point.unwrap() * curr_eval_point.unwrap());
        first_element_index /= 2;
    }

    assert_eq!(cur_layer.len(), 1, "Expected number of elements to be one.");
    cur_layer[0]
}
