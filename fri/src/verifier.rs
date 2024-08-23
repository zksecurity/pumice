use std::error::Error;

use ark_ff::FftField;
use ark_poly::domain::EvaluationDomain;

use crate::{
    folder::{fri_folder_from_field, MultiplicativeFriFolder},
    parameters::FriParameters,
};
use channel::{FSChannel, VerifierChannel};

pub trait TableVerifierFactory {}

pub struct FriVerifier<F: FftField, V: VerifierChannel<Field = F> + FSChannel<Field = F>> {
    channel: Box<V>,
    table_verifier_factory: Box<dyn TableVerifierFactory>,
    params: Box<FriParameters<F>>,
    // folder
    // first_query_callback
    n_layers: usize,
    // exepcted_last_layer
    first_eval_point: Option<F>,
    eval_points: Vec<F>,
    // table_verifier
    query_indices: Vec<u64>,
    query_results: Vec<F>,
}

impl<F: FftField, V: VerifierChannel<Field = F> + FSChannel<Field = F>> FriVerifier<F, V> {
    pub fn new(
        channel: Box<V>,
        table_verifier_factory: Box<dyn TableVerifierFactory>,
        params: Box<FriParameters<F>>,
        n_layers: usize,
    ) -> Self {
        let n_queries = params.n_queries;
        Self {
            channel,
            table_verifier_factory,
            params,
            n_layers,
            first_eval_point: None,
            eval_points: vec![F::zero(); n_layers - 1],
            // reserve table verifiers to n_layers - 1
            query_indices: vec![],
            query_results: vec![F::zero(); n_queries],
        }
    }

    pub fn verify_fri(&mut self) -> Result<(), Box<dyn Error>> {
        // commitment phase
        self.commitment_phase();

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

        self.channel.apply_proof_of_work(proof_of_work_bits);

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
                let domain_size = self
                    .params
                    .fft_bases
                    .as_ref()
                    .unwrap()
                    .at(basis_index)
                    .size()
                    / coset_size;

                // TODO: Implement TableVerifier creation and commitment reading
                // let mut commitment_scheme = self.table_verifier_factory.create(domain_size, coset_size);
                // commitment_scheme.read_commitment();
                // self.table_verifiers.push(commitment_scheme);
            }
        }
    }

    pub fn read_last_layer_coefficients(&self) {
        todo!()
    }

    pub fn verify_first_layer(&mut self) {
        // TODO: AnnotationScope

        let first_fri_step = self.params.fri_step_list[0];
        let first_layer_queries =
            self.second_layer_queries_to_first_layer_queries(&self.query_indices, first_fri_step);

        let first_layer_coset_size = 1 << first_fri_step;
        for i in (0..first_layer_queries.len()).step_by(first_layer_coset_size) {
            // TODO: Implement FRI layers application
            let result = self.apply_fri_layers(
                &vec![F::zero(); first_layer_coset_size],
                self.first_eval_point,
                &self.params,
                0,
                first_layer_queries[i],
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
        mut first_element_index: u64,
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
            let curr_eval_point = curr_eval_point.expect("evaluation point doesn't have a value");
            let basis = params.fft_bases.as_ref().unwrap().at(basis_index);

            let mut next_layer = Vec::with_capacity(cur_layer.len() / 2);
            for j in (0..cur_layer.len()).step_by(2) {
                next_layer.push(
                    MultiplicativeFriFolder::next_layer_element_from_two_previous_layer_elements(
                        &cur_layer[j],
                        &cur_layer[j + 1],
                        &curr_eval_point,
                        &basis.elements(first_element_index + j as u64),
                    ),
                );
            }

            cur_layer = next_layer;
            curr_eval_point = Some(
                params
                    .fft_bases
                    .as_ref()
                    .unwrap()
                    .apply_basis_transform(curr_eval_point, basis_index),
            );
            first_element_index /= 2;
        }

        assert_eq!(cur_layer.len(), 1, "예상된 요소의 수는 1입니다.");
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

    pub fn verify_inner_layers(&self) {
        todo!()
    }

    pub fn verify_last_layer(&self) {
        todo!()
    }
}
