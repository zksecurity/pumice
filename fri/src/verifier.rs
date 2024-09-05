use std::error::Error;

use ark_ff::{FftField, PrimeField};
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
use randomness::Prng;
use sha3::Digest;

use crate::parameters::FriParameters;
use channel::{fs_verifier_channel::FSVerifierChannel, Channel};
use commitment_scheme::{
    make_commitment_scheme_verifier, table_verifier::TableVerifier, CommitmentHashes,
};

#[allow(dead_code)]
pub type FirstLayerQueriesCallback<F> = fn(&[u64]) -> Vec<F>;

#[allow(dead_code)]
pub struct FriVerifier<
    F: FftField + PrimeField,
    P: Prng + Clone + 'static,
    W: Digest + Clone + 'static,
> {
    channel: FSVerifierChannel<F, P, W>,
    params: FriParameters<F, Radix2EvaluationDomain<F>>,
    commitment_hashes: CommitmentHashes,
    first_layer_callback: FirstLayerQueriesCallback<F>,
    n_layers: usize,
    first_eval_point: Option<F>,
    eval_points: Vec<F>,
    table_verifiers: Vec<TableVerifier<F, P, W>>,
    query_indices: Vec<u64>,
    query_results: Vec<F>,
    expected_last_layer: Option<Vec<F>>,
}

#[allow(dead_code)]
impl<F: FftField + PrimeField, P: Prng + Clone + 'static, W: Digest + Clone + 'static>
    FriVerifier<F, P, W>
{
    pub fn new(
        channel: FSVerifierChannel<F, P, W>,
        params: FriParameters<F, Radix2EvaluationDomain<F>>,
        commitment_hashes: CommitmentHashes,
        first_layer_callback: FirstLayerQueriesCallback<F>,
        n_layers: usize,
    ) -> Self {
        let n_queries: usize = params.n_queries;
        Self {
            channel,
            params,
            commitment_hashes,
            first_layer_callback,
            n_layers,
            first_eval_point: None,
            eval_points: vec![F::zero(); n_layers - 1],
            table_verifiers: vec![],
            query_indices: vec![],
            query_results: vec![F::zero(); n_queries],
            expected_last_layer: None,
        }
    }

    pub fn verify_fri(&mut self) -> Result<(), Box<dyn Error>> {
        self.commitment_phase()?;
        self.read_last_layer_coefficients()?;

        // // query phase
        // self.query_indices = self.choose_query_indices();
        // //self.channel.begin_query_phase();

        // // decommitment phase
        // // TODO : annotation

        // self.verify_first_layer();
        // self.verify_inner_layers();
        // self.verify_last_layer();
        Ok(())
    }

    pub fn commitment_phase(&mut self) -> Result<(), Box<dyn Error>> {
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
                let n_rows = self.params.fft_domains[basis_index].size() / coset_size;
                let n_columns = coset_size;
                let size_of_row = ((F::MODULUS_BIT_SIZE.div_ceil(8) * 8) as usize) * n_columns;

                let commitment_scheme = make_commitment_scheme_verifier(
                    size_of_row,
                    n_rows,
                    0,
                    self.commitment_hashes.clone(),
                    n_columns,
                );

                let mut table_verifier = TableVerifier::new(n_columns, commitment_scheme);
                let _ = table_verifier.read_commitment(&mut self.channel);
                self.table_verifiers.push(table_verifier);
            }
        }

        Ok(())
    }

    pub fn read_last_layer_coefficients(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
