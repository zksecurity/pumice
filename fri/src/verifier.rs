use std::{collections::BTreeMap, error::Error};

use ark_ff::{FftField, PrimeField};
use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
use randomness::Prng;
use sha3::Digest;

use crate::{
    details::{
        apply_fri_layers, choose_query_indices, get_table_prover_row, get_table_prover_row_col,
        next_layer_data_and_integrity_queries, second_layer_queries_to_first_layer_queries,
    },
    lde::MultiplicativeLDE,
    parameters::FriParameters,
};
use channel::{fs_verifier_channel::FSVerifierChannel, Channel, VerifierChannel};
use commitment_scheme::{
    make_commitment_scheme_verifier, table_utils::RowCol, table_verifier::TableVerifier,
    CommitmentHashes,
};

#[allow(dead_code)]
pub type FirstLayerQueriesCallback<F> = Box<dyn Fn(&[u64]) -> Vec<F>>;

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
    query_indices_test: Option<Vec<u64>>,
    to_verify_test: Option<Vec<BTreeMap<RowCol, F>>>,
    eval_points_test: Option<Vec<F>>,
}

#[allow(dead_code)]
impl<F: FftField + PrimeField, P: Prng + Clone + 'static, W: Digest + Clone + 'static>
    FriVerifier<F, P, W>
{
    pub fn new<C>(
        channel: FSVerifierChannel<F, P, W>,
        params: FriParameters<F, Radix2EvaluationDomain<F>>,
        commitment_hashes: CommitmentHashes,
        first_layer_callback: C,
        query_indices_test: Option<Vec<u64>>,
        to_verify_test: Option<Vec<BTreeMap<RowCol, F>>>,
        eval_points_test: Option<Vec<F>>,
    ) -> Self
    where
        C: Fn(&[u64]) -> Vec<F> + 'static,
    {
        let n_layers = params.fri_step_list.len();
        Self {
            channel,
            params,
            commitment_hashes,
            first_layer_callback: Box::new(first_layer_callback),
            n_layers,
            first_eval_point: None,
            eval_points: vec![F::zero(); n_layers - 1],
            table_verifiers: vec![],
            query_indices: vec![],
            query_results: vec![],
            expected_last_layer: None,
            query_indices_test,
            to_verify_test,
            eval_points_test,
        }
    }

    pub fn verify_fri(&mut self) -> Result<(), Box<dyn Error>> {
        // commitment phase
        self.commitment_phase()?;

        // query phase
        self.query_phase();

        // decommitment phase
        self.verify_first_layer();
        self.verify_inner_layers();
        self.verify_last_layer();
        Ok(())
    }

    pub fn query_phase(&mut self) {
        if self.query_indices_test.is_some() {
            self.query_indices = self.query_indices_test.clone().unwrap();
        } else {
            self.query_indices = choose_query_indices(&self.params, &mut self.channel);
        }

        self.channel.states.begin_query_phase();
    }

    pub fn verify_first_layer(&mut self) {
        let first_fri_step = self.params.fri_step_list[0];
        let first_layer_queries =
            second_layer_queries_to_first_layer_queries(&self.query_indices, first_fri_step);
        let first_layer_result = (self.first_layer_callback)(&first_layer_queries);

        assert_eq!(
            first_layer_result.len(),
            first_layer_queries.len(),
            "Returned number of queries does not match the number sent"
        );
        let first_layer_coset_size = 1 << first_fri_step;
        for i in (0..first_layer_queries.len()).step_by(first_layer_coset_size) {
            let result = apply_fri_layers(
                &first_layer_result[i..i + first_layer_coset_size],
                self.first_eval_point,
                &self.params,
                0,
                first_layer_queries[i] as usize,
            );
            self.query_results.push(result);
        }
    }

    pub fn verify_inner_layers(&mut self) {
        let first_fri_step = self.params.fri_step_list[0];
        let mut basis_index = 0;

        for i in 0..self.n_layers - 1 {
            let cur_fri_step = self.params.fri_step_list[i + 1];
            basis_index += self.params.fri_step_list[i];

            let (layer_data_queries, layer_integrity_queries) =
                next_layer_data_and_integrity_queries(&self.params, &self.query_indices, i + 1);

            let mut to_verify = if let Some(test_data) = self.to_verify_test.as_ref() {
                test_data[i].clone()
            } else {
                self.table_verifiers[i]
                    .query(
                        &mut self.channel,
                        &layer_data_queries,
                        &layer_integrity_queries,
                    )
                    .unwrap()
            };

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
                    Some(eval_point),
                    &self.params,
                    i + 1,
                    coset_start * (1 << cur_fri_step),
                );
            }

            if self.query_indices_test.is_some() {
                continue;
            } else {
                assert!(
                    self.table_verifiers[i]
                        .verify_decommitment(&mut self.channel, &to_verify)
                        .unwrap(),
                    "Layer {} failed decommitment",
                    i
                );
            }
        }
    }

    pub fn verify_last_layer(&self) {
        let first_fri_step = self.params.fri_step_list[0];
        let fri_step_sum: usize = self.params.fri_step_list.iter().sum();

        assert!(
            self.expected_last_layer.is_some(),
            "ReadLastLayer() must be called before VerifyLastLayer()."
        );

        for (j, &query_result) in self.query_results.iter().enumerate() {
            let query_index = self.query_indices[j] >> (fri_step_sum - first_fri_step);
            let expected_value = self.expected_last_layer.as_ref().unwrap()[query_index as usize];

            assert_eq!(
                query_result, expected_value,
                "FRI query #{} is not consistent with the coefficients of the last layer.",
                j
            );
        }
    }

    pub fn commitment_phase(&mut self) -> Result<(), Box<dyn Error>> {
        let mut basis_index = 0;
        for i in 0..self.n_layers {
            let cur_fri_step = self.params.fri_step_list[i];
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

        if let Some(eval_points_test) = self.eval_points_test.as_ref() {
            self.first_eval_point = Some(eval_points_test[0]);
            self.eval_points[..(self.n_layers - 1)]
                .copy_from_slice(&eval_points_test[1..((self.n_layers - 1) + 1)]);
        }
        self.read_last_layer_coefficients()?;
        Ok(())
    }

    pub fn read_last_layer_coefficients(&mut self) -> Result<(), Box<dyn Error>> {
        let fri_step_sum: usize = self.params.fri_step_list.iter().sum();
        let last_layer_size = self.params.fft_domains[fri_step_sum].size();

        let mut last_layer_coefficients_vector = self
            .channel
            .recv_felts(self.params.last_layer_degree_bound as usize)
            .unwrap();
        // pad last_layer_coefficients_vector with zeros to the size of last_layer_size
        while last_layer_coefficients_vector.len() < last_layer_size {
            last_layer_coefficients_vector.push(F::zero());
        }

        assert!(
            self.params.last_layer_degree_bound as usize <= last_layer_size,
            "last_layer_degree_bound ({}) must be <= last_layer_size ({})",
            self.params.last_layer_degree_bound,
            last_layer_size
        );

        let last_layer_basis_index = fri_step_sum;
        let lde_domain = self.params.fft_domains[last_layer_basis_index];
        let mut lde = MultiplicativeLDE::new(lde_domain, true);

        lde.add_coeff(&last_layer_coefficients_vector);
        let evals = lde.eval(lde_domain.element(0));
        self.expected_last_layer = Some(evals[0].clone());

        Ok(())
    }
}

#[cfg(test)]
mod fri_tests {
    use ark_poly::{
        domain::EvaluationDomain, univariate::DensePolynomial, DenseUVPolynomial, Polynomial,
    };
    use channel::{fs_prover_channel::FSProverChannel, Channel, ProverChannel};
    use commitment_scheme::SupportedHashes;
    use felt::{hex, Felt252};
    use randomness::{keccak256::PrngKeccak256, Prng};
    use sha3::Sha3_256;

    use crate::stone_domain::{change_order_of_elements_in_domain, make_fft_domains};

    use super::*;

    type TestProverChannel = FSProverChannel<Felt252, PrngKeccak256, Sha3_256>;
    type TestVerifierChannel = FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256>;

    fn generate_verifier_channel(prover_channel: &TestProverChannel) -> TestVerifierChannel {
        let prng = PrngKeccak256::new_with_seed(&[0u8; 4]);
        TestVerifierChannel::new(prng, prover_channel.get_proof())
    }

    fn generate_prover_channel() -> TestProverChannel {
        let prng: PrngKeccak256 = PrngKeccak256::new_with_seed(&[0u8; 4]);
        TestProverChannel::new(prng)
    }

    fn gen_random_field_element(prover_channel: &mut TestProverChannel) -> Felt252 {
        prover_channel.draw_felem()
    }

    #[test]
    fn verifier_mock_test() {
        let mut channel_for_rng = generate_prover_channel();
        let mut test_prover_channel = generate_prover_channel();

        let last_layer_degree_bound = 5;
        let proof_of_work_bits = 15;
        let domain_size_log = 10;

        let offset = Felt252::from(777u64);
        let domains = make_fft_domains::<Felt252>(domain_size_log, offset);
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
            .map(|_| gen_random_field_element(&mut channel_for_rng))
            .collect();

        let test_layer = DensePolynomial::from_coefficients_vec(poly_coeffs);
        // i will use this later
        let _witness: Vec<Felt252> = domains[0]
            .elements()
            .map(|x| test_layer.evaluate(&x))
            .collect();

        let reordered_witness = change_order_of_elements_in_domain(&_witness);

        let fourth_layer_evaluations = vec![
            hex("0x663aa85d164d449a2a7c04698fb3f24f1d049984c1539c7ac3b71839ce485fd"),
            hex("0x16eae1252002c24abc155c65f65cdc0df65ab85219324923be3773d1c8e99ae"),
            hex("0x413a20799e9aafcbec1564442875e2b61df6ba4fc645de1764b5d60122b80fa"),
            hex("0x9421b1a9cc663ae06caf9d2b6d2fc0838ed9953bb3ff01ad5d423a3e023833"),
            hex("0x62a27bc1c62f4c9eefe90ef9e72923f684a46cf231d915fb7a5bc8341210462"),
            hex("0xe341cd1674e7b9c4b0b21873e161df37be5a112b8c8b2f884238e39aea25cd"),
            hex("0x392e66a7a39a56f907f16a32ce9a9ca7c59ad31b9da6b1b30594075b398add9"),
            hex("0x19bd01106bd63a97c491540601007b21e42afd41bcb99644842ee61ea5a2876"),
            hex("0x529c386668d5486b6342a92a69c6dd87269d956a51f0b189e86f6127132a637"),
            hex("0x4922f64192cbb0a0c390d984fdfe586d80c90378a62184d2129af6731c7c6a3"),
            hex("0x3a47a881517129e0f95bf700f820ff7c2077efce82aaa38b1782556f14b8b98"),
            hex("0x4c1a36f5f5a3a84d7a014d37bd1ccb66cc6bd3aaa8d2da67dcbe41c6e4df1d4"),
            hex("0x39ad62ac6c2b639601d3cb28537a10be0558c3795ac45e6201c9cd79950dda8"),
            hex("0x51769b8cd304f464988512d43add79c0f24b796daa9ea912d80d851db31b2e0"),
            hex("0x2c55afe71ba57d40cf2c1e16c23c1a1022087d85a99820b5044cb01da6822c4"),
            hex("0x31c909221113d4c4dd32eaa4ec9d6168669c6d13ce82e843774bd8132203bc5"),
        ];

        let mut fourth_layer_lde = MultiplicativeLDE::new(domains[6], true);
        fourth_layer_lde.add_eval(&fourth_layer_evaluations);
        let fourth_layer_coefs = fourth_layer_lde.coeffs(0);

        // Choose evaluation points for the three layers
        let _eval_points = vec![
            hex("0x7f097aaa40a3109067011986ae40f1ce97a01f4f1a72d80a52821f317504992"),
            hex("0x18bcafdd60fc70e5e8a9a18687135d0bf1a355d9882969a6b3619e56bf2d49d"),
            hex("0x2f06b17e08bc409b945b951de8102653dc48a143b87d09b6c95587679816d02"),
        ];

        // send two dummy commitments
        let _ = test_prover_channel.send_felts(&vec![Felt252::from(1u64); 2]);

        // send foruth layer coefficients to prover channel
        let _ = test_prover_channel.send_felts(&fourth_layer_coefs);

        // verifier channel
        let test_verifier_channel = generate_verifier_channel(&test_prover_channel);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Blake2s256);
        let mut to_verify_test: Vec<BTreeMap<RowCol, Felt252>> = Vec::new();
        to_verify_test.push(BTreeMap::new());
        to_verify_test[0].insert(
            RowCol::new(0, 1),
            hex("0x4a7cafcd9228ec84f21aa50b5cc0d30ee22ded1ca957c5930bd258da230fdb3"),
        );
        to_verify_test[0].insert(
            RowCol::new(0, 2),
            hex("0x1ca2bc3a41a0bcdd6e327852c2da85c356df37a3a6fdcc02a4df4097ccefa84"),
        );
        to_verify_test[0].insert(
            RowCol::new(0, 3),
            hex("0x52c7b6567dd7cbcd4d3141b2a54996e3ac0e976e8fd5f0fde3cb2b37d67f4de"),
        );
        to_verify_test[0].insert(
            RowCol::new(0, 4),
            hex("0x7d65d3975a67c265741b5fbf02edf769aa39258790ef13762ea53fd220dd948"),
        );
        to_verify_test[0].insert(
            RowCol::new(0, 5),
            hex("0x259a9cf7011586a3f057c1596602459dd079cb03290bce9d1336c8fb6ca487d"),
        );
        to_verify_test[0].insert(
            RowCol::new(0, 7),
            hex("0x4a3439104f1a9079817542e752acafd9ebb6736b2c2fd5aab0fb7b71938f582"),
        );

        to_verify_test.push(BTreeMap::new());
        to_verify_test[1].insert(
            RowCol::new(0, 1),
            hex("0x490fb8d97d64f8d4e2068a4a8845d759aed62bd79efeb2a2b34db537e49e8f0"),
        );

        to_verify_test.push(BTreeMap::new());
        to_verify_test[2].insert(
            RowCol::new(0, 0),
            hex("0x5bc3cf7c5240d0bc1278f7e860400521b996e88815534845421a1ebc71cbac4"),
        );

        let mut fri_verifier = FriVerifier::new(
            test_verifier_channel,
            params,
            commitment_hashes,
            move |_| {
                vec![
                    reordered_witness[0],
                    reordered_witness[1],
                    reordered_witness[2],
                    reordered_witness[3],
                    reordered_witness[24],
                    reordered_witness[25],
                    reordered_witness[26],
                    reordered_witness[27],
                ]
            },
            Some(vec![0, 6]),
            Some(to_verify_test),
            Some(_eval_points),
        );

        assert!(fri_verifier.verify_fri().is_ok());
    }
}
