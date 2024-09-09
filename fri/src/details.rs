use std::collections::BTreeSet;

use ark_ff::{FftField, PrimeField};
use ark_poly::EvaluationDomain;
use channel::FSChannel;
use commitment_scheme::table_utils::RowCol;
use sha3::Digest;

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

pub fn apply_fri_layers<F: FftField + PrimeField, E: EvaluationDomain<F>>(
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
            let res = MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
                &cur_layer[j],
                &cur_layer[j + 1],
                &curr_eval_point.unwrap(),
                &get_field_element_at_index(&fft_domain, first_element_index + j),
            );
            next_layer.push(res);
        }

        cur_layer = next_layer;
        // ApplyBasisTransform just calculates square of curr_eval_point
        curr_eval_point = Some(curr_eval_point.unwrap() * curr_eval_point.unwrap());
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

pub fn get_table_prover_row_col(query_index: u64, fri_step: usize) -> RowCol {
    RowCol::new(
        get_table_prover_row(query_index, fri_step),
        get_table_prover_col(query_index, fri_step),
    )
}

pub fn get_table_prover_row(query_index: u64, fri_step: usize) -> usize {
    (query_index >> fri_step) as usize
}

pub fn get_table_prover_col(query_index: u64, fri_step: usize) -> usize {
    (query_index & ((1 << fri_step) - 1)) as usize
}
