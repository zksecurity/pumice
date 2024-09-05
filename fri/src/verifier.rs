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
    ) -> Self {
        let n_queries = params.n_queries;
        let n_layers = params.fri_step_list.len();
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

#[cfg(test)]
mod fri_tests {
    use ark_poly::{
        domain::EvaluationDomain, univariate::DensePolynomial, DenseUVPolynomial, Polynomial,
        Radix2EvaluationDomain,
    };
    use channel::{fs_prover_channel::FSProverChannel, Channel};
    use commitment_scheme::SupportedHashes;
    use felt::Felt252;
    use randomness::{keccak256::PrngKeccak256, Prng};
    use sha3::Sha3_256;

    use super::*;

    type TestProverChannel = FSProverChannel<Felt252, PrngKeccak256, Sha3_256>;
    type TestVerifierChannel = FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256>;

    fn generate_verifier_channel() -> TestVerifierChannel {
        let prng = PrngKeccak256::new_with_seed(&[0u8; 4]);
        TestVerifierChannel::new(prng, vec![])
    }

    fn generate_prover_channel() -> TestProverChannel {
        let prng = PrngKeccak256::new_with_seed(&[0u8; 4]);
        TestProverChannel::new(prng)
    }

    fn gen_random_field_element(prover_channel: &mut TestProverChannel) -> Felt252 {
        prover_channel.draw_felem()
    }

    #[test]
    fn commitment_phase() {
        let mut test_prover_channel = generate_prover_channel();

        let last_layer_degree_bound = 5;
        let proof_of_work_bits = 15;
        let domain_size_log = 10;

        let offset = gen_random_field_element(&mut test_prover_channel);
        let domains: Vec<Radix2EvaluationDomain<Felt252>> = (0..=domain_size_log)
            .rev()
            .map(|i| {
                Radix2EvaluationDomain::<Felt252>::new(1 << i)
                    .unwrap()
                    .get_coset(offset)
                    .unwrap()
            })
            .collect();
        // check domains size is domain_size_log + 1
        assert_eq!(domains.len(), domain_size_log + 1);

        let params = FriParameters::new(
            vec![2, 3, 1],
            last_layer_degree_bound,
            2,
            domains.clone(),
            proof_of_work_bits,
        );

        let poly_coeffs: Vec<Felt252> = (0..64 * last_layer_degree_bound)
            .map(|_| gen_random_field_element(&mut test_prover_channel))
            .collect();

        let test_layer = DensePolynomial::from_coefficients_vec(poly_coeffs);
        // i will use this later
        let _witness: Vec<Felt252> = domains[0]
            .elements()
            .map(|x| test_layer.evaluate(&x))
            .collect();

        // Choose evaluation points for the three layers
        let _eval_points: Vec<Felt252> = (0..3)
            .map(|_| gen_random_field_element(&mut test_prover_channel))
            .collect();

        // verifier channel
        let test_verifier_channel = generate_verifier_channel();
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Blake2s256);

        let mut fri_verifier =
            FriVerifier::new(test_verifier_channel, params, commitment_hashes, |_| vec![]);
        fri_verifier.commitment_phase().unwrap();
    }
}
