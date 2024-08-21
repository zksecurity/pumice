use anyhow::Ok;
use ark_ff::PrimeField;
use channel::fs_verifier_channel::FSVerifierChannel;
use channel::VerifierChannel;
use randomness::Prng;
use sha3::Digest;
use crate::CommitmentSchemeVerifier;
use crate::table_utils::{RowCol, all_query_rows, elements_to_be_transmitted};
use std::collections::HashSet;
use std::collections::HashMap;

// type TableVerifierFactory = fn::<F: PrimeField, P: Prng, W: Digest>::(&PrimeField, usize, usize) -> TableVerifier<F, P, W>;

pub struct TableVerifier<F: PrimeField, P: Prng, W: Digest> {
    field: F,
    n_columns: usize,
    commitment_scheme: Box<dyn CommitmentSchemeVerifier>,
    channel: FSVerifierChannel<F, P, W>,
}

impl<F: PrimeField, P: Prng, W: Digest> TableVerifier<F, P, W> {

    pub fn new(
        field: F,
        n_columns: usize,
        commitment_scheme: Box<dyn CommitmentSchemeVerifier>,
        channel: FSVerifierChannel<F, P, W>,
    ) -> Self {
        Self {
            field,
            n_columns,
            commitment_scheme,
            channel,
        }
    }

    pub fn read_commitment(&mut self) -> Result<(), anyhow::Error> {
        self.commitment_scheme.read_commitment()
    }

    pub fn query(
        &mut self,
        data_queries: Vec<RowCol>,
        integrity_queries: Vec<RowCol>,
    ) -> Result<Vec<(RowCol, F)>, anyhow::Error> {

        let data_queries_set: HashSet<RowCol> = data_queries.clone().into_iter().collect();
        let integrity_queries_set: HashSet<RowCol> = integrity_queries.clone().into_iter().collect();
        assert!(data_queries_set.is_disjoint(&integrity_queries_set));

        let mut response = Vec::new();
        let to_receive = elements_to_be_transmitted(
            self.n_columns,
            &all_query_rows(&data_queries, &integrity_queries),
            &integrity_queries,
        );

        for query_loc in to_receive {
            let field_element = &self.channel.recv_felts(1)?;
            response.push((query_loc, field_element[0]));
        }

        Ok(response)
    }

    pub fn verify_decommitment(
        &self,
        all_rows_data: Vec<(RowCol, F)>,
    ) -> bool {
        // Gather elements by row
        let element_size = 32;
        let mut integrity_map: HashMap<usize, Vec<u8>> = HashMap::new();

        let mut iter = all_rows_data.into_iter();

        while let Some((row_col, field_element)) = iter.next() {
            let cur_row = row_col.get_row();
            let entry = integrity_map
                .entry(cur_row)
                .or_insert_with(|| vec![0; (self.n_columns * element_size) as usize]);

            let col = row_col.get_col() as usize;
            let pos = col * element_size;

            assert!(
                pos < entry.len(),
                "Data skips to next row before finishing the current."
            );

            let buffer = &mut entry[pos..pos + element_size];
            field_element.to_bytes(buffer);
        }

        self.commitment_scheme.verify_integrity(integrity_map)
    }
}