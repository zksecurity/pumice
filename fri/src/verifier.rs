use ark_ff::{FftField, PrimeField};
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
use felt::byte_size;
use randomness::Prng;
use sha3::Digest;

use crate::{lde::MultiplicativeLDE, parameters::FriParameters};
use channel::{fs_verifier_channel::FSVerifierChannel, Channel, VerifierChannel};
use commitment_scheme::{
    make_commitment_scheme_verifier, table_verifier::TableVerifier, CommitmentHashes,
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
        self.read_eval_points()?;
        self.read_commitments()?;
        self.read_last_layer_coefficients()?;
        Ok(())
    }

    fn read_eval_points(&mut self) -> Result<(), anyhow::Error>;
    fn read_commitments(&mut self) -> Result<(), anyhow::Error>;
    fn read_last_layer_coefficients(&mut self) -> Result<(), anyhow::Error>;
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

impl<
        F: FftField + PrimeField,
        P: Prng + Clone + 'static,
        W: Digest + Clone + 'static,
        FQ: FirstLayerQueriesCallback<F>,
    > FriVerifierTrait<F, P, W, FQ> for FriVerifier<F, P, W, FQ>
{
    fn read_eval_points(&mut self) -> Result<(), anyhow::Error> {
        let mut _basis_index = 0;
        for i in 0..self.n_layers {
            let cur_fri_step = self.params.fri_step_list[i];
            _basis_index += cur_fri_step;

            if i == 0 {
                if self.params.fri_step_list[0] != 0 {
                    self.first_eval_point = self.channel.draw_felem();
                }
            } else {
                self.eval_points.push(self.channel.draw_felem());
            }
        }
        Ok(())
    }

    fn read_commitments(&mut self) -> Result<(), anyhow::Error> {
        let mut basis_index = 0;
        for i in 0..self.n_layers {
            let cur_fri_step = self.params.fri_step_list[i];
            basis_index += cur_fri_step;

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

                let mut table_verifier = TableVerifier::new(n_columns, commitment_scheme);
                let _ = table_verifier.read_commitment(&mut self.channel);
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
        self.expected_last_layer.clone_from(&evals[0]);

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
