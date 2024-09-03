use crate::table_utils::{all_query_rows, elements_to_be_transmitted, RowCol};
use crate::CommitmentSchemeProver;
use ark_ff::{BigInteger, PrimeField};
use channel::fs_prover_channel::FSProverChannel;
use channel::ProverChannel;
use randomness::Prng;
use sha3::Digest;
use std::collections::BTreeSet;

pub struct TableProver<F: PrimeField, P: Prng, W: Digest> {
    n_columns: usize,
    commitment_scheme: Box<dyn CommitmentSchemeProver<F, P, W>>,
    data_queries: BTreeSet<RowCol>,
    integrity_queries: BTreeSet<RowCol>,
    all_query_rows: BTreeSet<usize>,
}

impl<F: PrimeField, P: Prng, W: Digest> TableProver<F, P, W> {
    pub fn new(
        n_columns: usize,
        commitment_scheme: Box<dyn CommitmentSchemeProver<F, P, W>>,
    ) -> Self {
        Self {
            n_columns,
            commitment_scheme,
            data_queries: BTreeSet::new(),
            integrity_queries: BTreeSet::new(),
            all_query_rows: BTreeSet::new(),
        }
    }

    pub fn add_segment_for_commitment(
        &mut self,
        segment: &[Vec<F>],
        segment_idx: usize,
        n_interleaved_columns: usize,
    ) {
        assert_eq!(
            segment.len() * n_interleaved_columns,
            self.n_columns,
            "segment length is expected to be equal to the number of columns"
        );

        let _ = &self
            .commitment_scheme
            .add_segment_for_commitment(&serialize_field_columns(segment), segment_idx);
    }

    pub fn commit(&mut self, channel: &mut FSProverChannel<F, P, W>) -> Result<(), anyhow::Error> {
        self.commitment_scheme.commit(channel)
    }

    pub fn start_decommitment_phase(
        &mut self,
        data_queries: BTreeSet<RowCol>,
        integrity_queries: BTreeSet<RowCol>,
    ) -> Vec<usize> {
        assert!(data_queries.is_disjoint(&integrity_queries));

        self.data_queries = data_queries;
        self.integrity_queries = integrity_queries;

        self.all_query_rows = all_query_rows(&self.data_queries, &self.integrity_queries);

        let mut rows_to_request: Vec<usize> = self.all_query_rows.iter().cloned().collect();

        let requested_elements = self
            .commitment_scheme
            .start_decommitment_phase(self.all_query_rows.clone());

        let requested_elements_set: BTreeSet<usize> = requested_elements.iter().cloned().collect();
        assert!(
            requested_elements.len() == requested_elements_set.len(),
            "Found duplicate row indices in requested_elements."
        );

        rows_to_request.extend(requested_elements.iter());

        rows_to_request
    }

    pub fn decommit(
        &mut self,
        channel: &mut FSProverChannel<F, P, W>,
        elements_data: &[Vec<F>],
    ) -> Result<(), anyhow::Error> {
        assert!(
            elements_data.len() == self.n_columns,
            "Expected the size of elements_data to be the number of columns."
        );

        let mut elements_data_last_rows: Vec<Vec<F>> = Vec::new();
        for column in elements_data {
            assert!(
                column.len() >= self.all_query_rows.len(),
                "The number of rows does not match the number of requested rows in start_decommitment_phase()."
            );
            let last_rows = column[self.all_query_rows.len()..].to_vec();
            elements_data_last_rows.push(last_rows);
        }

        let to_transmit = elements_to_be_transmitted(
            self.n_columns,
            &self.all_query_rows,
            &self.integrity_queries,
        );

        let mut row_it = self.all_query_rows.iter();
        let mut to_transmit_it = to_transmit.iter();

        for i in 0..self.all_query_rows.len() {
            if let Some(row) = row_it.next() {
                for (col, data) in elements_data.iter().enumerate().take(self.n_columns) {
                    let query_loc = RowCol::new(*row, col);

                    // Skip integrity queries.
                    if self.integrity_queries.contains(&query_loc) {
                        continue;
                    }

                    if let Some(&to_transmit_loc) = to_transmit_it.next() {
                        assert!(to_transmit_loc == query_loc);
                        channel.send_felts(&[data[i]])?;
                    }
                }
            }
        }

        self.commitment_scheme
            .decommit(&serialize_field_columns(&elements_data_last_rows), channel)?;

        Ok(())
    }
}

fn get_num_rows<FieldElementT>(columns: &[Vec<FieldElementT>]) -> usize {
    assert!(
        !columns.is_empty(),
        "columns must contain at least one column."
    );
    columns[0].len()
}

fn verify_all_columns_same_length<FieldElementT>(columns: &[Vec<FieldElementT>]) -> bool {
    let n_rows = get_num_rows(columns);
    columns.iter().all(|column| column.len() == n_rows)
}

fn serialize_field_columns<F: PrimeField>(segment: &[Vec<F>]) -> Vec<u8> {
    let columns = segment;

    assert!(
        verify_all_columns_same_length(columns),
        "The sizes of the columns must be the same."
    );

    let n_columns = columns.len();
    let n_rows = get_num_rows(columns);
    let element_size_in_bytes = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;
    let n_bytes_row = n_columns * element_size_in_bytes;

    let mut serialization = Vec::with_capacity(n_rows * n_bytes_row);

    for row in 0..n_rows {
        for col_data in columns.iter().take(n_columns) {
            serialization.extend_from_slice(&col_data[row].into_bigint().to_bytes_be());
        }
    }

    serialization
}
