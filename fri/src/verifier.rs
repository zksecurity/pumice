use ark_ff::{FftField, PrimeField};
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
use felt::byte_size;
use randomness::Prng;
use sha3::Digest;

use crate::{
    details::{
        apply_fri_layers, choose_query_indices, get_table_prover_row, get_table_prover_row_col,
        next_layer_data_and_integrity_queries, second_layer_queries_to_first_layer_queries,
    },
    lde::MultiplicativeLDE,
    parameters::FriParameters,
    stone_domain::change_order_of_elements_in_domain,
};
use channel::{fs_verifier_channel::FSVerifierChannel, Channel, VerifierChannel};
use commitment_scheme::{
    make_commitment_scheme_verifier, table_utils::RowCol, table_verifier::TableVerifier,
    CommitmentHashes,
};

#[allow(dead_code)]
pub trait FirstLayerQueriesCallback<F: FftField + PrimeField> {
    fn query(&self, indices: &[u64]) -> Vec<F>;
}

#[allow(dead_code)]
pub trait FriVerifierTrait<
    F: FftField + PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
    FQ: FirstLayerQueriesCallback<F>,
>
{
    fn verify_fri(&mut self) -> Result<(), anyhow::Error> {
        self.read_commitments()?;
        self.read_last_layer_coefficients()?;

        self.query_phase();

        self.verify_first_layer()?;
        self.verify_inner_layers()?;
        self.verify_last_layer()?;
        Ok(())
    }

    fn read_commitments(&mut self) -> Result<(), anyhow::Error>;
    fn read_last_layer_coefficients(&mut self) -> Result<(), anyhow::Error>;

    fn query_phase(&mut self);

    fn verify_first_layer(&mut self) -> Result<(), anyhow::Error>;
    fn verify_inner_layers(&mut self) -> Result<(), anyhow::Error>;
    fn verify_last_layer(&mut self) -> Result<(), anyhow::Error>;
}

#[allow(dead_code)]
pub struct FriVerifier<
    F: FftField + PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
    FQ: FirstLayerQueriesCallback<F>,
> {
    channel: FSVerifierChannel<F, P, W>,
    params: FriParameters<F, Radix2EvaluationDomain<F>>,
    commitment_hashes: CommitmentHashes,
    first_layer_callback: FQ,
    n_layers: usize,
    first_eval_point: F,
    eval_points: Vec<F>,
    table_verifiers: Vec<TableVerifier<F, P, W>>,
    query_indices: Vec<u64>,
    query_results: Vec<F>,
    expected_last_layer: Vec<F>,
}

#[allow(dead_code)]
impl<
        F: FftField + PrimeField,
        P: Prng + Clone + 'static,
        W: Digest + Clone + 'static,
        FQ: FirstLayerQueriesCallback<F>,
    > FriVerifierTrait<F, P, W, FQ> for FriVerifier<F, P, W, FQ>
{
    fn read_commitments(&mut self) -> Result<(), anyhow::Error> {
        let mut basis_index = 0;
        for i in 0..self.n_layers {
            let cur_fri_step = self.params.fri_step_list[i];
            basis_index += cur_fri_step;

            if i == 0 {
                if self.params.fri_step_list[0] != 0 {
                    self.first_eval_point = self.channel.draw_felem();
                }
            } else {
                self.eval_points.push(self.channel.draw_felem());
            }

            if i < self.n_layers - 1 {
                let coset_size = 1 << self.params.fri_step_list[i + 1];
                let n_rows = self.params.fft_domains[basis_index].size() / coset_size;
                let n_columns = coset_size;
                let size_of_row = byte_size::<F>() * n_columns;

                let commitment_scheme = make_commitment_scheme_verifier(
                    size_of_row,
                    n_rows,
                    0,
                    self.commitment_hashes.clone(),
                    n_columns,
                );

                let mut table_verifier = TableVerifier::new(
                    n_columns,
                    commitment_scheme,
                    P::should_convert_from_mont_when_initialize(),
                );
                table_verifier.read_commitment(&mut self.channel)?;
                self.table_verifiers.push(table_verifier);
            }
        }
        Ok(())
    }

    fn read_last_layer_coefficients(&mut self) -> Result<(), anyhow::Error> {
        let mut last_layer_coefficients_vector = self
            .channel
            .recv_felts(self.params.last_layer_degree_bound)?;

        let fri_step_sum: usize = self.params.fri_step_list.iter().sum();
        let last_layer_size = self.params.fft_domains[fri_step_sum].size();

        // pad last_layer_coefficients_vector with zeros to the size of last_layer_size
        while last_layer_coefficients_vector.len() < last_layer_size {
            last_layer_coefficients_vector.push(F::zero());
        }

        assert!(
            self.params.last_layer_degree_bound <= last_layer_size,
            "last_layer_degree_bound ({}) must be <= last_layer_size ({})",
            self.params.last_layer_degree_bound,
            last_layer_size
        );

        let last_layer_basis_index = fri_step_sum;
        let lde_domain = self.params.fft_domains[last_layer_basis_index];

        let mut lde = MultiplicativeLDE::new(lde_domain, true);
        lde.add_coeff(&last_layer_coefficients_vector);

        let evals = lde.batch_eval(lde_domain.element(0));
        // The stone code uses big-endian element ordering, while the arkworks code uses little-endian element ordering
        self.expected_last_layer = change_order_of_elements_in_domain(&evals[0]);

        Ok(())
    }

    fn query_phase(&mut self) {
        self.query_indices = choose_query_indices(&self.params, &mut self.channel);

        self.channel.states.begin_query_phase();
    }

    fn verify_first_layer(&mut self) -> Result<(), anyhow::Error> {
        let first_fri_step = self.params.fri_step_list[0];
        let first_layer_queries =
            second_layer_queries_to_first_layer_queries(&self.query_indices, first_fri_step);
        let first_layer_result = self.first_layer_callback.query(&first_layer_queries);

        assert_eq!(
            first_layer_result.len(),
            first_layer_queries.len(),
            "Returned number of queries does not match the number sent"
        );
        let first_layer_coset_size = 1 << first_fri_step;
        for i in (0..first_layer_queries.len()).step_by(first_layer_coset_size) {
            let result = apply_fri_layers(
                &first_layer_result[i..i + first_layer_coset_size],
                &self.first_eval_point,
                &self.params,
                0,
                first_layer_queries[i] as usize,
            );
            self.query_results.push(result);
        }
        Ok(())
    }

    fn verify_inner_layers(&mut self) -> Result<(), anyhow::Error> {
        let first_fri_step = self.params.fri_step_list[0];
        let mut basis_index = 0;

        for i in 0..self.n_layers - 1 {
            let cur_fri_step = self.params.fri_step_list[i + 1];
            basis_index += self.params.fri_step_list[i];

            let (layer_data_queries, layer_integrity_queries) =
                next_layer_data_and_integrity_queries(&self.params, &self.query_indices, i + 1);

            let mut to_verify = self.table_verifiers[i]
                .query(
                    &mut self.channel,
                    &layer_data_queries,
                    &layer_integrity_queries,
                )
                .unwrap();

            for j in 0..self.query_results.len() {
                let query_index = self.query_indices[j] >> (basis_index - first_fri_step);
                let query_loc = get_table_prover_row_col(query_index, cur_fri_step);
                to_verify.insert(query_loc, self.query_results[j]);
            }

            let eval_point = self.eval_points[i];
            for j in 0..self.query_results.len() {
                let coset_size = 1 << cur_fri_step;
                let mut coset_elements: Vec<F> = Vec::with_capacity(coset_size);
                let coset_start = get_table_prover_row(
                    self.query_indices[j] >> (basis_index - first_fri_step),
                    cur_fri_step,
                );

                for k in 0..coset_size {
                    coset_elements.push(*to_verify.get(&RowCol::new(coset_start, k)).unwrap());
                }

                self.query_results[j] = apply_fri_layers(
                    &coset_elements,
                    &eval_point,
                    &self.params,
                    i + 1,
                    coset_start * (1 << cur_fri_step),
                );
            }

            assert!(
                self.table_verifiers[i]
                    .verify_decommitment(&mut self.channel, &to_verify)
                    .unwrap(),
                "Layer {} failed decommitment",
                i
            );
        }
        Ok(())
    }

    fn verify_last_layer(&mut self) -> Result<(), anyhow::Error> {
        let first_fri_step = self.params.fri_step_list[0];
        let fri_step_sum: usize = self.params.fri_step_list.iter().sum();

        assert!(
            !self.expected_last_layer.is_empty(),
            "ReadLastLayer() must be called before VerifyLastLayer()."
        );

        for (j, &query_result) in self.query_results.iter().enumerate() {
            let query_index = self.query_indices[j] >> (fri_step_sum - first_fri_step);
            let expected_value = self.expected_last_layer[query_index as usize];

            assert_eq!(
                query_result, expected_value,
                "FRI query #{} is not consistent with the coefficients of the last layer.",
                j
            );
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl<
        F: FftField + PrimeField,
        P: Prng + Clone + 'static,
        W: Digest + Clone + 'static,
        FQ: FirstLayerQueriesCallback<F>,
    > FriVerifier<F, P, W, FQ>
{
    pub fn new(
        channel: FSVerifierChannel<F, P, W>,
        params: FriParameters<F, Radix2EvaluationDomain<F>>,
        commitment_hashes: CommitmentHashes,
        first_layer_callback: FQ,
    ) -> Self {
        let n_layers = params.fri_step_list.len();
        Self {
            channel,
            params,
            commitment_hashes,
            first_layer_callback,
            n_layers,
            first_eval_point: F::zero(),
            eval_points: vec![],
            table_verifiers: vec![],
            query_indices: vec![],
            query_results: vec![],
            expected_last_layer: vec![],
        }
    }
}
