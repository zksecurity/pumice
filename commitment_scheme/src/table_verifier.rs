use crate::table_utils::{all_query_rows, elements_to_be_transmitted, RowCol};
use crate::CommitmentSchemeVerifier;
use anyhow::Ok;
use ark_ff::{BigInteger, PrimeField};
use channel::fs_verifier_channel::FSVerifierChannel;
use channel::VerifierChannel;
use randomness::Prng;
use sha3::Digest;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

// type TableVerifierFactory = fn::<F: PrimeField, P: Prng, W: Digest>::(&PrimeField, usize, usize) -> TableVerifier<F, P, W>;

pub struct TableVerifier<F: PrimeField, P: Prng, W: Digest> {
    n_columns: usize,
    commitment_scheme: Box<dyn CommitmentSchemeVerifier>,
    channel: Rc<RefCell<FSVerifierChannel<F, P, W>>>,
}

impl<F: PrimeField, P: Prng, W: Digest> TableVerifier<F, P, W> {
    pub fn new(
        n_columns: usize,
        commitment_scheme: Box<dyn CommitmentSchemeVerifier>,
        channel: Rc<RefCell<FSVerifierChannel<F, P, W>>>,
    ) -> Self {
        Self {
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
        data_queries: &BTreeSet<RowCol>,
        integrity_queries: &BTreeSet<RowCol>,
    ) -> Result<BTreeMap<RowCol, F>, anyhow::Error> {
        assert!(data_queries.is_disjoint(integrity_queries));

        let mut response = BTreeMap::new();
        let to_receive = elements_to_be_transmitted(
            self.n_columns,
            &all_query_rows(data_queries, integrity_queries),
            integrity_queries,
        );

        for query_loc in to_receive {
            let mut channel = self.channel.borrow_mut();
            let field_element = channel.recv_felts(1)?;
            response.insert(query_loc, field_element[0]);
        }

        Ok(response)
    }

    #[allow(dead_code)]
    fn verify_decommitment(&mut self, all_rows_data: &BTreeMap<RowCol, F>) -> Option<bool> {
        let mut integrity_map: BTreeMap<usize, Vec<u8>> = BTreeMap::new();

        let element_size = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;

        // Iterate over all rows in the map.
        let mut all_rows_it = all_rows_data.iter().peekable();
        while let Some((&row_col, _value)) = all_rows_it.peek() {
            // Insert a new vector in the integrity_map with the current row number as the key.
            let cur_row = row_col.get_row();
            let mut row_data = vec![0u8; self.n_columns * element_size];
            let mut pos = 0;

            for _ in 0..self.n_columns {
                if let Some((&row_col_next, field_element)) = all_rows_it.next() {
                    assert_eq!(
                        row_col_next.get_row(),
                        cur_row,
                        "Data skips to next row before finishing the current."
                    );
                    // Copy the field element bytes into the appropriate position in row_data.
                    let field_bytes = field_element.into_bigint().to_bytes_be();
                    row_data[pos..pos + element_size].copy_from_slice(&field_bytes);
                    pos += element_size;
                } else {
                    panic!("Not enough columns in the map.");
                }
            }

            integrity_map.insert(cur_row, row_data);
        }

        // Verify the integrity map using the commitment scheme.
        self.commitment_scheme.verify_integrity(integrity_map)
    }
}
