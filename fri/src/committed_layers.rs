use crate::{
    details::next_layer_data_and_integrity_queries, layers::FriLayer, parameters::FriParameters,
};
use anyhow::Ok;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use channel::fs_prover_channel::FSProverChannel;
use commitment_scheme::table_prover::TableProver;
use commitment_scheme::CommitmentHashes;
use randomness::Prng;
use sha3::Digest;
use std::sync::Arc;

#[allow(dead_code)]
pub struct FriCommittedLayer<F: PrimeField, E: EvaluationDomain<F>, P: Prng, W: Digest> {
    fri_step: usize,
    layer: Arc<dyn FriLayer<F, E>>,
    params: FriParameters<F, E>,
    layer_num: usize,
    table_prover: TableProver<F, P, W>,
}

#[allow(dead_code)]
impl<
        F: PrimeField,
        E: EvaluationDomain<F>,
        P: Prng + Clone + 'static,
        W: Digest + Clone + 'static,
    > FriCommittedLayer<F, E, P, W>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fri_step: usize,
        layer: Arc<dyn FriLayer<F, E>>,
        params: FriParameters<F, E>,
        layer_num: usize,
        field_element_size_in_bytes: usize,
        n_verifier_friendly_commitment_layers: usize,
        commitment_hashes: CommitmentHashes,
        channel: &mut FSProverChannel<F, P, W>,
        mont_r: F,
    ) -> Self {
        let layer_size = layer.get_layer_size();

        let mut table_prover = TableProver::new(
            1,
            layer_size / (1 << fri_step),
            1 << fri_step,
            field_element_size_in_bytes,
            n_verifier_friendly_commitment_layers,
            commitment_hashes,
            mont_r,
        );

        let segment = layer.get_layer().unwrap();
        table_prover.add_segment_for_commitment(&[segment], 0, 1 << fri_step);
        table_prover.commit(channel).unwrap();

        Self {
            fri_step,
            layer,
            params,
            layer_num,
            table_prover,
        }
    }

    pub fn eval_at_points(&self, required_row_indices: &[usize]) -> Vec<Vec<F>> {
        let coset_size = 1 << self.params.fri_step_list[self.layer_num];
        let mut elements_data_vectors = Vec::with_capacity(coset_size);

        for col in 0..coset_size {
            let mut required_indices: Vec<usize> = Vec::new();

            for &row in required_row_indices {
                required_indices.push(row * coset_size + col);
            }

            let eval_result = self.layer.eval_at_points(&required_indices);
            elements_data_vectors.push(eval_result);
        }

        elements_data_vectors
    }

    pub fn decommit(
        &mut self,
        queries: &[u64],
        channel: &mut FSProverChannel<F, P, W>,
    ) -> Result<(), anyhow::Error> {
        let (data_queries, integrity_queries) =
            next_layer_data_and_integrity_queries(&self.params, queries, self.layer_num);
        let required_row_indices = self
            .table_prover
            .start_decommitment_phase(data_queries.clone(), integrity_queries.clone());

        let elements_data = self.eval_at_points(&required_row_indices);
        self.table_prover.decommit(channel, &elements_data)?;
        Ok(())
    }
}
