use std::{collections::BTreeSet, error::Error};

use ark_ff::{FftField, PrimeField};
use ark_poly::{domain::EvaluationDomain, univariate::DensePolynomial, DenseUVPolynomial};
use randomness::Prng;
use sha3::Digest;

use crate::{
    folder::MultiplicativeFriFolder,
    parameters::FriParameters,
};
use channel::{FSChannel, VerifierChannel};
use commitment_scheme::{table_utils::RowCol, table_verifier::{TableVerifier, TableVerifierFactory}};

#[allow(dead_code)]
pub type FirstLayerQueriesCallback<F> = fn(&[u64]) -> Vec<F>;

pub struct FriVerifier<F: FftField + PrimeField, P: Prng, W: Digest, V: FSChannel<Field = F, PowHash = W> + VerifierChannel<Field = F>> {
    channel: Box<V>,
    table_verifier_factory: TableVerifierFactory<F, P, W>,
    params: Box<FriParameters<F>>,
    // folder
    first_layer_callback: FirstLayerQueriesCallback<F>,
    n_layers: usize,
    // exepcted_last_layer
    first_eval_point: Option<F>,
    eval_points: Vec<F>,
    table_verifiers: Vec<TableVerifier<F, P, W>>,
    query_indices: Vec<u64>,
    query_results: Vec<F>,
    expected_last_layer: Option<Vec<F>>,
}

impl<F: FftField + PrimeField, P: Prng, W: Digest, V: VerifierChannel<Field = F> + FSChannel<Field = F, PowHash = W>> FriVerifier<F, P, W, V> {
    pub fn new(
        channel: Box<V>,
        table_verifier_factory: TableVerifierFactory<F, P, W>,
        params: Box<FriParameters<F>>,
        first_layer_callback: FirstLayerQueriesCallback<F>,
        n_layers: usize,
    ) -> Self {
        let n_queries = params.n_queries;
        Self {
            channel,
            table_verifier_factory,
            params,
            first_layer_callback,
            n_layers,
            first_eval_point: None,
            eval_points: vec![F::zero(); n_layers - 1],
            // reserve table verifiers to n_layers - 1
            table_verifiers: vec![],
            query_indices: vec![],
            query_results: vec![F::zero(); n_queries],
            expected_last_layer: None,
        }
    }

    pub fn verify_fri(&mut self) -> Result<(), Box<dyn Error>> {
        // commitment phase
        self.commitment_phase();
        self.read_last_layer_coefficients();

        // query phase
        self.query_indices = self.choose_query_indices();
        //self.channel.begin_query_phase();

        // decommitment phase
        // TODO : annotation

        // verify first layer
        self.verify_first_layer();
        // verify inner layers
        self.verify_inner_layers();
        // verify last layer
        self.verify_last_layer();
        Ok(())
    }

    fn choose_query_indices(&mut self) -> Vec<u64> {
        let domain_size = self
            .params
            .fft_bases
            .as_ref()
            .unwrap()
            .at(self.params.fri_step_list[0])
            .size();
        let n_queries = self.params.n_queries;
        let proof_of_work_bits = self.params.proof_of_work_bits;

        let _ = self.channel.apply_proof_of_work(proof_of_work_bits);

        let mut query_indices = Vec::with_capacity(n_queries);
        for _ in 0..n_queries {
            let random_index = self.channel.draw_number(domain_size as u64);
            query_indices.push(random_index);
        }

        query_indices.sort_unstable();

        query_indices
    }

    pub fn commitment_phase(&mut self) {
        let mut basis_index = 0;
        for i in 0..self.n_layers {
            let cur_fri_step = self.params.fri_step_list[i];
            // TODO: Implement annotation scope
            // AnnotationScope scope(channel_.get(), "Layer " + std::to_string(i + 1));
            basis_index += cur_fri_step;

            if i == 0 {
                if self.params.fri_step_list[0] != 0 {
                    self.first_eval_point = Some(self.channel.draw_felem());
                }
            } else {
                self.eval_points[i - 1] = self.channel.draw_felem();
            }

            if i < self.n_layers - 1 {
                let coset_size = 1 << self.params.fri_step_list[i + 1];
                let n_elements = self
                    .params
                    .fft_bases
                    .as_ref()
                    .unwrap()
                    .at(basis_index)
                    .size()
                    / coset_size;
                let n_columns = coset_size;

                let mut table_verifier = (self.table_verifier_factory)(n_elements, n_columns);
                let _ = table_verifier.read_commitment();
                self.table_verifiers.push(table_verifier);
            }
        }
    }

    pub fn read_last_layer_coefficients(&mut self) {
        // TODO: AnnotationScope
        // AnnotationScope scope(self.channel.as_mut(), "Last Layer");

        let fri_step_sum: usize = self.params.fri_step_list.iter().sum();
        let last_layer_size = self.params.fft_bases.as_ref().unwrap().at(fri_step_sum).size();

        let last_layer_coefficients_vector = self.channel.recv_felts(self.params.last_layer_degree_bound as usize).unwrap();

        assert!(
            self.params.last_layer_degree_bound as usize <= last_layer_size,
            "last_layer_degree_bound ({}) must be <= last_layer_size ({})",
            self.params.last_layer_degree_bound,
            last_layer_size
        );

        let last_layer_basis_index = fri_step_sum;
        let lde_bases = self.params.fft_bases.as_ref().unwrap().at(last_layer_basis_index);
        
        let poly = DensePolynomial::from_coefficients_slice(&last_layer_coefficients_vector);
        let poly_eval: ark_poly::Evaluations<F, ark_poly::Radix2EvaluationDomain<F>> = poly.evaluate_over_domain(lde_bases.clone());
        self.expected_last_layer = Some(poly_eval.evals.iter().map(|x| x.clone()).collect());
    }

    pub fn verify_first_layer(&mut self) {
        // TODO: AnnotationScope

        let first_fri_step = self.params.fri_step_list[0];
        let first_layer_queries =
            self.second_layer_queries_to_first_layer_queries(&self.query_indices, first_fri_step);
        let first_layer_result = (self.first_layer_callback)(&first_layer_queries);

        assert_eq!(
            first_layer_result.len(),
            first_layer_queries.len(),
            "Returned number of queries does not match the number sent"
        );
        let first_layer_coset_size = 1 << first_fri_step;
        for i in (0..first_layer_queries.len()).step_by(first_layer_coset_size) {
            // TODO: Implement FRI layers application
            let result = self.apply_fri_layers(
                &first_layer_result[i..i + first_layer_coset_size],
                self.first_eval_point,
                &self.params,
                0,
                first_layer_queries[i] as usize,
            );
            self.query_results.push(result);
        }
    }

    fn apply_fri_layers(
        &self,
        elements: &[F],
        eval_point: Option<F>,
        params: &FriParameters<F>,
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
            assert!(curr_eval_point.is_some(), "evaluation point doesn't have a value");
            let basis = params.fft_bases.as_ref().unwrap().at(basis_index);

            let mut next_layer = Vec::with_capacity(cur_layer.len() / 2);
            for j in (0..cur_layer.len()).step_by(2) {
                next_layer.push(
                    MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
                        &cur_layer[j],
                        &cur_layer[j + 1],
                        &curr_eval_point.unwrap(),
                        &basis.elements().nth(first_element_index + j as usize).unwrap(),
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

    fn second_layer_queries_to_first_layer_queries(
        &self,
        query_indices: &[u64],
        first_fri_step: usize,
    ) -> Vec<u64> {
        let first_layer_coset_size = 1 << first_fri_step;
        let mut first_layer_queries =
            Vec::with_capacity(query_indices.len() * first_layer_coset_size);

        for &idx in query_indices {
            for i in
                (idx * first_layer_coset_size as u64)..((idx + 1) * first_layer_coset_size as u64)
            {
                first_layer_queries.push(i);
            }
        }

        first_layer_queries
    }

    pub fn verify_inner_layers(&mut self) {
        let first_fri_step = self.params.fri_step_list[0];
        let mut basis_index = 0;
    
        for i in 0..self.n_layers - 1 {
            // TODO: AnnotationScope
            // AnnotationScope scope(self.channel.as_mut(), format!("Layer {}", i + 1));
    
            let cur_fri_step = self.params.fri_step_list[i + 1];
            basis_index += self.params.fri_step_list[i];
    
            let (layer_data_queries, layer_integrity_queries) = self.next_layer_data_and_integrity_queries(i + 1);
    
            let mut to_verify = self.table_verifiers[i].query(&layer_data_queries, &layer_integrity_queries).unwrap();
    
            let basis = self.params.fft_bases.as_ref().unwrap().at(basis_index);
            let mut prev_query_index = u64::MAX;
    
            // Below codes are for annotation

            // for j in 0..self.query_results.len() {
            //     let query_index = self.query_indices[j] >> (basis_index - first_fri_step);
            //     let query_loc = self.get_table_prover_row_col(query_index, cur_fri_step);
                
            //     // TODO: insert query_results to to_verify
            //     // to_verify.insert(query_loc, self.query_results[j]);
    
            //     if query_index != prev_query_index && !self.channel.extra_annotations_disabled() {
            //         prev_query_index = query_index;
            //         // self.channel.annotate_extra_field_element(&self.query_results[j], self.element_decommit_annotation(&query_loc));
            //         let x_inv = basis.get_field_element_at(query_index as usize).inverse().unwrap();
            //         // self.channel.annotate_extra_field_element(&x_inv, format!("xInv for index {}", query_index));
            //     }
            // }
    
            let eval_point = self.eval_points[i];
            for j in 0..self.query_results.len() {
                let coset_size = 1 << cur_fri_step;
                let mut coset_elements: Vec<F> = Vec::with_capacity(coset_size);
                let coset_start = self.get_table_prover_row(self.query_indices[j] >> (basis_index - first_fri_step), cur_fri_step);
                
                for k in 0..coset_size {
                    coset_elements.push(to_verify.get(&RowCol::new(coset_start, k)).unwrap().clone());
                }
    
                self.query_results[j] = self.apply_fri_layers(
                    &coset_elements,
                    Some(eval_point),
                    &self.params,
                    i + 1,
                    (coset_start as usize) * (1 << cur_fri_step),
                );
            }
    
            // TODO: TableVerifier
            assert!(self.table_verifiers[i].verify_decommitment(&to_verify).unwrap(), "Layer {} failed decommitment", i);
        }
    
    }

    fn next_layer_data_and_integrity_queries(&self, layer: usize) -> (BTreeSet<RowCol>, BTreeSet<RowCol>) {
        let cumulative_fri_step = self.params.fri_step_list[1..layer].iter().sum::<usize>();
        let layer_fri_step = self.params.fri_step_list[layer];
    
        let mut integrity_queries: BTreeSet<RowCol> = BTreeSet::new();
        let mut data_queries: BTreeSet<RowCol> = BTreeSet::new();
    
        for &idx in &self.query_indices {
            integrity_queries.insert(self.get_table_prover_row_col(idx >> cumulative_fri_step, layer_fri_step));
        }
    
        for &idx in &self.query_indices {
            let coset_row = self.get_table_prover_row(idx >> cumulative_fri_step, layer_fri_step);
            for coset_col in 0..(1 << layer_fri_step) {
                let query = RowCol::new(coset_row, coset_col);
                if !integrity_queries.contains(&query) {
                    data_queries.insert(query);
                }
            }
        }
    
        (data_queries, integrity_queries)
    }

    fn get_table_prover_row_col(&self, query_index: u64, fri_step: usize) -> RowCol {
        RowCol::new(self.get_table_prover_row(query_index, fri_step), self.get_table_prover_col(query_index, fri_step))
    }

    fn get_table_prover_row(&self, query_index: u64, fri_step: usize) -> usize {
        return (query_index >> fri_step) as usize;
    }

    fn get_table_prover_col(&self, query_index: u64, fri_step: usize) -> usize {
        return (query_index & ((1 << fri_step) - 1)) as usize;
    }

    fn element_decommit_annotation(&self, query_loc: &(usize, usize)) -> String {
        String::new()
    }


    pub fn verify_last_layer(&self) {
        let first_fri_step = self.params.fri_step_list[0];
        let fri_step_sum: usize = self.params.fri_step_list.iter().sum();

        assert!(self.expected_last_layer.is_some(), "ReadLastLayer() must be called before VerifyLastLayer().");
        // let basis = self.params.fft_bases.as_ref().unwrap().at(fri_step_sum);

        // let mut prev_query_index = u64::MAX;
        for (j, &query_result) in self.query_results.iter().enumerate() {
            let query_index = self.query_indices[j] >> (fri_step_sum - first_fri_step);
            let expected_value = self.expected_last_layer.as_ref().unwrap()[query_index as usize];
            
            assert_eq!(
                query_result, expected_value,
                "FRI query #{} is not consistent with the coefficients of the last layer.", j
            );
            // Annotation
        }
    }
}
