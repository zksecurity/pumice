use crate::table_utils::{all_query_rows, elements_to_be_transmitted, RowCol};
use crate::CommitmentSchemeVerifier;
use anyhow::{Error, Ok};
use ark_ff::{BigInteger, PrimeField};
use channel::fs_verifier_channel::FSVerifierChannel;
use channel::VerifierChannel;
use randomness::Prng;
use sha3::Digest;
use std::collections::{BTreeMap, BTreeSet};

pub struct TableVerifier<F: PrimeField, P: Prng, W: Digest> {
    n_columns: usize,
    commitment_scheme: Box<dyn CommitmentSchemeVerifier<F, P, W>>,
}

impl<F: PrimeField, P: Prng, W: Digest> TableVerifier<F, P, W> {
    /// Create new TableVerifier.
    pub fn new(
        n_columns: usize,
        commitment_scheme: Box<dyn CommitmentSchemeVerifier<F, P, W>>,
    ) -> Self {
        Self {
            n_columns,
            commitment_scheme,
        }
    }

    /// Reads the initial commitment into the scheme (e.g., Merkle root).
    pub fn read_commitment(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
    ) -> Result<(), anyhow::Error> {
        self.commitment_scheme.read_commitment(channel)
    }

    /// Returns query results from the channel.
    /// The input to this function is data queries (i.e. queries the verifier does not know the answer to)
    /// and integrity queries (i.e. queries for which the verifier can compute the answer).
    pub fn query(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
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
            let field_element = channel.recv_felts(1)?;
            response.insert(query_loc, field_element[0]);
        }

        Ok(response)
    }

    /// Given indexed field elements, verify that these field elements are indeed the ones committed to
    /// by the prover, against the commitment obtained by read_commitment().
    #[allow(dead_code)]
    fn verify_decommitment(
        &mut self,
        channel: &mut FSVerifierChannel<F, P, W>,
        all_rows_data: &BTreeMap<RowCol, F>,
    ) -> Result<bool, Error> {
        let mut integrity_map: BTreeMap<usize, Vec<u8>> = BTreeMap::new();

        let element_size = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;

        // Iterate over all rows in the map.
        let mut all_rows_it = all_rows_data.iter().peekable();
        while let Some((&row_col, _value)) = all_rows_it.peek() {
            // Insert a new vector in the integrity_map with the current row number as the key.
            let cur_row = row_col.get_row();
            let mut row_data = Vec::with_capacity(self.n_columns * element_size);

            for _ in 0..self.n_columns {
                if let Some((&row_col_next, field_element)) = all_rows_it.next() {
                    assert_eq!(
                        row_col_next.get_row(),
                        cur_row,
                        "Data skips to next row before finishing the current."
                    );
                    // Copy the field element bytes into the appropriate position in row_data.
                    let field_bytes = field_element.into_bigint().to_bytes_be();
                    assert_eq!(field_bytes.len(), element_size);
                    row_data.extend_from_slice(&field_bytes);
                } else {
                    return Err(anyhow::anyhow!("Not enough columns in the map."));
                }
            }

            integrity_map.insert(cur_row, row_data);
        }

        // Verify the integrity map using the commitment scheme.
        self.commitment_scheme
            .verify_integrity(channel, integrity_map)
    }
}

// Tests to check completeness of TableProver and TableVerifier.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::SupportedHashes;
    use crate::{
        make_commitment_scheme_prover, make_commitment_scheme_verifier, table_prover::TableProver,
        CommitmentHashes,
    };
    use channel::fs_prover_channel::FSProverChannel;
    use channel::ProverChannel;
    use felt::Felt252;
    use randomness::keccak256::PrngKeccak256;
    use sha3::Sha3_256;

    fn get_proof(
        field_element_size: usize,
        n_columns: usize,
        n_segments: usize,
        n_rows_per_segment: usize,
        table_data: Vec<Vec<Felt252>>,
        data_queries: &BTreeSet<RowCol>,
        integrity_queries: &BTreeSet<RowCol>,
    ) -> Vec<u8> {
        let n_rows = n_rows_per_segment * n_segments;
        let size_of_row = field_element_size * n_columns;

        assert_eq!(table_data.len(), n_columns);

        let mut segment_data: Vec<Vec<&[Felt252]>> = Vec::with_capacity(n_segments);

        for i in 0..n_segments {
            let mut segment: Vec<&[Felt252]> = Vec::with_capacity(n_columns);

            for column in table_data.iter() {
                let start = i * n_rows_per_segment;
                let end = start + n_rows_per_segment;
                let segment_slice = &column[start..end];
                segment.push(segment_slice);
            }

            segment_data.push(segment);
        }

        let channel_prng = PrngKeccak256::new();
        let mut prover_channel: FSProverChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSProverChannel::new(channel_prng);

        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Blake2s256);

        let commitment_scheme = make_commitment_scheme_prover(
            size_of_row,
            n_rows_per_segment,
            n_segments,
            0,
            commitment_hashes,
            n_columns,
        );

        let mut table_prover = TableProver::new(n_columns, commitment_scheme);

        for (i, segment) in segment_data.iter().enumerate() {
            let segment_slice: Vec<Vec<Felt252>> =
                segment.iter().map(|slice| slice.to_vec()).collect();
            table_prover.add_segment_for_commitment(&segment_slice, i, 1);
        }

        table_prover.commit(&mut prover_channel).unwrap();

        let elements_idxs_for_decommitment =
            table_prover.start_decommitment_phase(data_queries.clone(), integrity_queries.clone());

        let mut elements_data: Vec<Vec<Felt252>> = Vec::with_capacity(n_columns);

        for column in 0..n_columns {
            let mut res: Vec<Felt252> = Vec::with_capacity(elements_idxs_for_decommitment.len());

            for &row in &elements_idxs_for_decommitment {
                assert!(row < n_rows, "Invalid row.");

                let segment = row / n_rows_per_segment;
                let index = row % n_rows_per_segment;

                res.push(segment_data[segment][column][index].clone());
            }

            elements_data.push(res);
        }

        table_prover
            .decommit(&mut prover_channel, &elements_data)
            .unwrap();

        let proof = prover_channel.get_proof();
        proof
    }

    fn test_table_verifier_with(
        field_element_size: usize,
        n_columns: usize,
        n_segments: usize,
        n_rows_per_segment: usize,
        exp_proof: Vec<u8>,
        data_queries: &BTreeSet<RowCol>,
        integrity_queries: &BTreeSet<RowCol>,
        table_data: Vec<Vec<Felt252>>,
    ) {
        let proof = get_proof(
            field_element_size,
            n_columns,
            n_segments,
            n_rows_per_segment,
            table_data.clone(),
            data_queries,
            integrity_queries,
        );
        assert_eq!(proof, exp_proof);

        let n_rows = n_rows_per_segment * n_segments;
        let size_of_row = field_element_size * n_columns;

        let channel_prng = PrngKeccak256::new();
        let mut verifier_channel: FSVerifierChannel<Felt252, PrngKeccak256, Sha3_256> =
            FSVerifierChannel::new(channel_prng, proof);
        let commitment_hashes = CommitmentHashes::from_single_hash(SupportedHashes::Blake2s256);
        let commitment_scheme =
            make_commitment_scheme_verifier(size_of_row, n_rows, 0, commitment_hashes, n_columns);

        let mut table_verifier = TableVerifier::new(n_columns, commitment_scheme);

        let _ = table_verifier.read_commitment(&mut verifier_channel);

        let mut data_for_verification = table_verifier
            .query(&mut verifier_channel, data_queries, integrity_queries)
            .unwrap();

        // Check all queries answered
        for q in data_queries.iter() {
            assert!(
                data_for_verification.contains_key(q),
                "Data query not found in response"
            );

            assert_eq!(
                *data_for_verification.get(q).unwrap(),
                table_data[q.get_col()][q.get_row()],
                "Incorrect response to data query."
            );
        }

        // Check verification
        for q in integrity_queries.iter() {
            data_for_verification.insert(*q, table_data[q.get_col()][q.get_row()]);
        }

        assert!(table_verifier
            .verify_decommitment(&mut verifier_channel, &data_for_verification)
            .unwrap());
    }

    #[test]
    fn test_table_verifier() {
        let field_element_size = 32;
        let n_columns = 2;
        let n_segments = 4;
        let n_rows_per_segment = 4;
        let exp_proof = vec![
            254, 54, 51, 40, 59, 10, 247, 47, 124, 35, 240, 199, 156, 65, 129, 175, 177, 74, 9, 96,
            120, 22, 21, 170, 31, 113, 140, 220, 114, 208, 220, 250, 6, 95, 109, 109, 251, 22, 153,
            161, 55, 125, 12, 95, 161, 104, 216, 183, 149, 115, 134, 247, 51, 163, 121, 233, 167,
            197, 132, 15, 182, 148, 117, 51, 1, 50, 67, 97, 181, 239, 72, 42, 190, 142, 239, 211,
            103, 154, 228, 168, 128, 141, 208, 173, 240, 244, 141, 181, 29, 12, 65, 197, 136, 42,
            145, 174, 6, 16, 45, 96, 119, 232, 106, 62, 44, 229, 78, 139, 155, 200, 136, 34, 17, 8,
            190, 184, 218, 52, 132, 122, 161, 121, 17, 210, 211, 74, 77, 77, 1, 107, 59, 186, 10,
            232, 45, 229, 118, 109, 108, 178, 92, 244, 148, 20, 124, 4, 160, 8, 228, 133, 118, 248,
            143, 159, 196, 141, 4, 226, 180, 147, 0, 40, 211, 121, 66, 64, 39, 25, 155, 97, 197,
            228, 152, 171, 194, 190, 100, 245, 24, 173, 188, 194, 64, 179, 104, 180, 80, 139, 169,
            34, 130, 107, 1, 171, 166, 71, 161, 193, 187, 14, 171, 177, 1, 219, 229, 30, 157, 11,
            85, 247, 93, 249, 198, 152, 177, 239, 120, 229, 120, 132, 127, 223, 218, 92, 2, 174,
            127, 23, 103, 12, 18, 62, 25, 124, 173, 148, 170, 156, 50, 90, 137, 199, 66, 125, 110,
            184, 86, 191, 35, 61, 146, 98, 34, 29, 210, 245, 124, 89, 215, 81, 31, 168, 250, 216,
            242, 206, 217, 243, 104, 110, 174, 232, 151, 108, 227, 167, 55, 188, 41, 123, 181, 143,
            107, 145, 23, 68, 72, 111, 247, 35, 58, 126, 64, 85, 91, 10, 161, 23, 64, 27, 85, 199,
            95, 174, 12, 158, 121, 194, 103, 165, 99, 100, 109, 11, 176, 187, 205, 102, 98, 194,
            86, 188, 199, 235, 147, 86, 98, 170, 224, 38, 254, 122, 27, 207, 160, 75, 221, 135,
            164, 212, 36, 210, 3, 229, 117, 44, 176, 3, 157, 9, 0, 107, 39, 186, 111, 153, 117, 32,
            131, 119, 234, 36, 0, 52, 255, 66, 106, 43, 232, 130, 89, 207, 110, 166, 220, 52, 252,
            123, 58, 129, 167, 32, 4, 17, 215, 137, 162, 238, 61, 225, 0, 235, 50, 138, 57, 175,
            96, 158, 43, 114, 241, 204, 179, 158, 98, 151, 196, 206, 180, 178, 105, 40, 22, 80, 70,
            133, 242, 83, 119, 80, 168, 206, 175, 233, 169, 116, 126, 68, 246, 128, 115, 186, 197,
            115, 58, 210, 235, 99, 203, 156, 28, 28, 193, 235, 215, 174, 97, 43,
        ];
        let table_data: Vec<Vec<Felt252>> = vec![
            vec![
                felt::hex("0x65f6d6dfb1699a1377d0c5fa168d8b7957386f733a379e9a7c5840fb6947533"),
                felt::hex("0x4ce193265b909a1b1f373f956b5c026cda37afe441a3379659120cf90867ebb"),
                felt::hex("0x6102d6077e86a3e2ce54e8b9bc888221108beb8da34847aa17911d2d34a4d4d"),
                felt::hex("0x7867f55a408590ccac3919bfe1040788453d4fb8b6ab705b2418bce53124ffe"),
                felt::hex("0x15114125a3a1a01de81b8b5fc1384e7b7d4abca0f9f078f1fa189a59d3b90b8"),
                felt::hex("0x24ab5ce86e9d9686df7734a44da1048c8b051a72234929c11e3468365e9b4a3"),
                felt::hex("0x16b3bba0ae82de5766d6cb25cf494147c04a008e48576f88f9fc48d04e2b493"),
                felt::hex("0x267ad9e76b76dc64ddeb1f41bf11164d99aef37fb56d7984a96119a42cde532"),
                felt::hex("0x5a5a401f6ddb77e08f5009d681fff854c01192397585699b46fc2996c1208d9"),
                felt::hex("0x71068b2c99ba944480fc9d0b7f78678ca49ebd2a47836f71c8c00a870eab999"),
                felt::hex("0x39d59180ffb1c5a1a9198c05ed5e9d86965276304c1a66599994f39962022d4"),
                felt::hex("0x48c660052643949216c449084afa58082ee4921bcf7f7ef2878a6580b1c89a0"),
                felt::hex("0x66fdb7b072b4217309e3aa4c4a0b66a0e7624fc635c1f48864759589917f53a"),
                felt::hex("0x33073c99572593b5f7585704eb11868234024bfbe034b7de3e2973f025ea21"),
                felt::hex("0x336331fa834eeba35da2c5538707e9c864434596162308abd2de97827b9ec0a"),
                felt::hex("0x360d067d8fa88671d6d7691dac08071b0777a5ee8e05f1f4da4c83abbe64c20"),
            ],
            vec![
                felt::hex("0x1324361b5ef482abe8eefd3679ae4a8808dd0adf0f48db51d0c41c5882a91ae"),
                felt::hex("0x3ea787108255965c626316af351fc4ab788c61372eb43f46924281d24b440e1"),
                felt::hex("0x34c8d9285643d3ef01bcea57dbcb9ab8cc7572140a9436758e10fe9aea9c06b"),
                felt::hex("0x5b88c400264850250013e86e489ddedb5a2754f0d957d0047cc8dd06497528e"),
                felt::hex("0x1143a9d6989475e6e319adfcb6be5a5f37465648a31537200412e3b1b6d6141"),
                felt::hex("0x2efa7ae3601eb7ad91122b7a0a43bc06943dfd212e93bc84034b2f4b27b588d"),
                felt::hex("0x28d379424027199b61c5e498abc2be64f518adbcc240b368b4508ba922826b"),
                felt::hex("0x1aba647a1c1bb0eabb101dbe51e9d0b55f75df9c698b1ef78e578847fdfda5c"),
                felt::hex("0x3ae328a629b7510829aa9f369bdbff56b88d04d763630a10915196ea915da19"),
                felt::hex("0x508c970a69e629fcdab35e82eaadea45a57a2468bf2b8f77401cf6471eabf8e"),
                felt::hex("0x6a8a3624b6e9801a2ff4d2f0f34ccfb7e22a2c055ac6071d9b99783f2c616c7"),
                felt::hex("0x2ae7f17670c123e197cad94aa9c325a89c7427d6eb856bf233d9262221dd2f5"),
                felt::hex("0x2e83b57723d7dd69378b113c4b50f15d2ef8b8550f8125d7f7076eeaafbd017"),
                felt::hex("0x2c88cfd74c8e77b767fcac792b9a8a65a87393fefca890557df56f0ff8e9275"),
                felt::hex("0x574248ac5a307e2ebf5070b5b3e3dc4661a652c6c9330e1c69d510ee91a8f4e"),
                felt::hex("0x10f23fcd14fbeb174d90599d5fcd35ca93c0f860c48a9c8447bc1f3220f89cc"),
            ],
        ];
        let data_queries = BTreeSet::from([RowCol::new(0, 0), RowCol::new(6, 0)]);
        let integrity_queries =
            BTreeSet::from([RowCol::new(2, 1), RowCol::new(7, 0), RowCol::new(11, 0)]);
        test_table_verifier_with(
            field_element_size,
            n_columns,
            n_segments,
            n_rows_per_segment,
            exp_proof,
            &data_queries,
            &integrity_queries,
            table_data,
        );

        let field_element_size = 32;
        let n_columns = 2;
        let n_segments = 4;
        let n_rows_per_segment = 2;
        let exp_proof = vec![
            193, 165, 8, 153, 66, 225, 55, 241, 104, 82, 160, 74, 149, 163, 243, 50, 11, 136, 152,
            41, 115, 95, 232, 181, 236, 195, 141, 18, 86, 71, 196, 24, 2, 242, 10, 108, 74, 153,
            114, 164, 139, 50, 123, 195, 68, 213, 156, 247, 134, 49, 255, 19, 201, 87, 214, 74,
            162, 52, 81, 192, 161, 90, 200, 29, 90, 234, 183, 140, 43, 51, 224, 71, 192, 111, 232,
            21, 40, 34, 8, 228, 159, 251, 208, 136, 158, 177, 78, 138, 247, 251, 234, 54, 118, 231,
            108, 205, 113, 133, 20, 120, 208, 210, 212, 69, 200, 241, 150, 184, 53, 49, 30, 119,
            160, 169, 145, 69, 70, 188, 154, 254, 220, 184, 71, 86, 181, 243, 118, 80, 183, 168,
            112, 218, 168, 45, 162, 19, 16, 56, 61, 192, 48, 201, 69, 221, 54, 206, 61, 103, 9,
            245, 149, 235, 90, 204, 14, 29, 49, 95, 7, 187,
        ];
        let table_data: Vec<Vec<Felt252>> = vec![
            vec![
                felt::hex("0x34b3c38e4e7aebf78bb19da93486e7c70046dd75ce5da061f1099782230ff30"),
                felt::hex("0x2f20a6c4a9972a48b327bc344d59cf78631ff13c957d64aa23451c0a15ac81d"),
                felt::hex("0xefa810976794351e5f2b78554c3d5bdc6dfbe76d441b33c47ce4364023042f"),
                felt::hex("0x34145cb1422ba56f8bdae62be85e5b81b122e789826cf1966490ad8db0a42e5"),
                felt::hex("0x101591ecb80ab91a577b9aad4ce5320ae793422f0534fdd2e2240d3ce530f47"),
                felt::hex("0x51d9ae1e146544be7b08f30f786cc5bc8be2ebb0b0549e8d5904d2a286b2835"),
                felt::hex("0x4da5aa9a59777642aa1a9b6701b351963f9d1f0e6226fe7ffc62fba1afb31b8"),
                felt::hex("0x279ea5b964d189390793acbe470ce189fe198fe9badb09b4382981b55c3a18f"),
            ],
            vec![
                felt::hex("0xbca7e4d5c388df65db262f2f2581e7292865365f5852d4eea5fdec7c7ff2e"),
                felt::hex("0x225f30f1c56910e184e49c3ecd669fefa8baca8e9c0f0ac90d9e62648ac5818"),
                felt::hex("0x266efd21a0eb3dfce14f674587ff74ffab37e8744e5a8b8188a6f75474b1bb8"),
                felt::hex("0x7f2cf6670d503fa47a2fcfe982ad520417694c981ec3213a6a0b315a91853f"),
                felt::hex("0x1a04f47d001c1802b130735feb4cf8ac139d60409d1df0dbc84f0d11fe14fb2"),
                felt::hex("0x14801d01e5a149db6a88d2ffb89c31c53f6f7e15ee11a0ed9c3c8a463c30a3b"),
                felt::hex("0x14a6aab15336862b05fa608bfbf6af238512678f9f748e393b3f1bb669856f6"),
                felt::hex("0x641b3182a1ecaa7770c6cdea8c5d52f9820aa511626fc7383bd8ea39d7d9556"),
            ],
        ];
        let data_queries = BTreeSet::from([RowCol::new(1, 0)]);
        let integrity_queries = BTreeSet::from([RowCol::new(1, 1)]);
        test_table_verifier_with(
            field_element_size,
            n_columns,
            n_segments,
            n_rows_per_segment,
            exp_proof,
            &data_queries,
            &integrity_queries,
            table_data,
        );

        let field_element_size = 32;
        let n_columns = 2;
        let n_segments = 2;
        let n_rows_per_segment = 2;
        let exp_proof = vec![
            163, 61, 160, 50, 58, 163, 46, 46, 144, 26, 189, 3, 73, 205, 186, 105, 80, 153, 14, 64,
            202, 89, 173, 132, 33, 0, 8, 209, 212, 80, 182, 192, 0, 210, 42, 48, 209, 245, 11, 243,
            202, 15, 91, 117, 182, 147, 221, 5, 146, 48, 120, 157, 62, 94, 190, 220, 29, 83, 207,
            175, 70, 69, 183, 180, 1, 40, 210, 59, 100, 158, 198, 58, 39, 236, 218, 238, 119, 54,
            0, 208, 242, 62, 75, 140, 46, 83, 252, 40, 207, 140, 175, 47, 214, 64, 54, 107, 6, 154,
            126, 47, 100, 203, 203, 119, 211, 24, 94, 121, 58, 135, 85, 52, 177, 154, 115, 70, 9,
            9, 240, 236, 162, 162, 154, 178, 216, 221, 148, 226, 48, 164, 217, 129, 217, 118, 121,
            65, 11, 7, 102, 122, 85, 63, 234, 229, 157, 120, 247, 56, 68, 38, 203, 203, 19, 45, 76,
            198, 216, 197, 202, 219, 48, 195, 62, 89, 68, 91, 79, 254, 27, 2, 193, 140, 159, 123,
            81, 125, 215, 66, 149, 205, 50, 167, 187, 5, 192, 3, 241, 33, 212, 82, 160, 167,
        ];
        let data_queries = BTreeSet::from([RowCol::new(0, 1)]);
        let integrity_queries = BTreeSet::from([RowCol::new(2, 1)]);
        let table_data = vec![
            vec![
                felt::hex("0xd22a30d1f50bf3ca0f5b75b693dd059230789d3e5ebedc1d53cfaf4645b7b4"),
                felt::hex("0x1ac1fb9d0eeafa19dfc56830ff2edbf581f26d789da1d3ae07b63c759378593"),
                felt::hex("0x69a7e2f64cbcb77d3185e793a875534b19a73460909f0eca2a29ab2d8dd94e2"),
                felt::hex("0x4e89b01367ed9a45b9b10975fae4d5e2d29d0f7d668651af3a5860c703ebd0e"),
            ],
            vec![
                felt::hex("0x128d23b649ec63a27ecdaee773600d0f23e4b8c2e53fc28cf8caf2fd640366b"),
                felt::hex("0x38ef7a0b6c3ec5326f1b7085f8b386772c40aa489bb6bc696b6d6a6641b58f"),
                felt::hex("0x14e5560b7d64f357ba56f9d7e1069cddd7077b08946774a6526f49e6a52df6"),
                felt::hex("0x8e3860d765b88c45198a0389f9e70fc3f80dd4ca9e3122086f3b2fd46cd49b"),
            ],
        ];
        test_table_verifier_with(
            field_element_size,
            n_columns,
            n_segments,
            n_rows_per_segment,
            exp_proof,
            &data_queries,
            &integrity_queries,
            table_data,
        );

        let field_element_size = 32;
        let n_columns = 2;
        let n_segments = 2;
        let n_rows_per_segment = 2;
        let exp_proof = vec![
            117, 154, 26, 12, 245, 174, 21, 247, 76, 146, 171, 173, 168, 69, 77, 201, 119, 255,
            216, 16, 224, 24, 236, 246, 26, 172, 156, 20, 2, 158, 208, 116, 6, 51, 58, 116, 136,
            76, 255, 130, 148, 164, 10, 94, 142, 63, 57, 36, 91, 80, 135, 9, 107, 19, 89, 70, 171,
            179, 138, 203, 65, 56, 71, 206, 0, 131, 236, 251, 134, 226, 39, 8, 28, 73, 163, 251,
            31, 136, 75, 227, 194, 44, 68, 26, 123, 71, 244, 25, 247, 87, 203, 86, 54, 207, 89,
            227, 7, 16, 235, 177, 127, 237, 120, 2, 189, 43, 76, 147, 187, 27, 40, 129, 93, 70, 78,
            114, 123, 236, 35, 190, 180, 223, 22, 244, 44, 110, 143, 211, 139, 213, 109, 53, 238,
            63, 71, 189, 49, 121, 83, 216, 81, 171, 110, 63, 244, 210, 142, 99, 113, 41, 18, 221,
            79, 229, 148, 185, 143, 115, 204, 12,
        ];
        let data_queries = BTreeSet::from([RowCol::new(2, 0)]);
        let integrity_queries = BTreeSet::from([RowCol::new(3, 0)]);
        let table_data: Vec<Vec<Felt252>> = vec![
            vec![
                felt::hex("0x6511595ef10430d2f8528d0acec2e81be1ee9e76186f6e8b2c891b6dfceda8d"),
                felt::hex("0x5022a1b86e36fd3dec29562add968244cd5ad09bbb2aa2ee918ba700fd651f0"),
                felt::hex("0x6333a74884cff8294a40a5e8e3f39245b5087096b135946abb38acb413847ce"),
                felt::hex("0x372aeaa69f776f2b6e5b18a6fa433b6dc209657bb8097f52dd1833d2187f7f0"),
            ],
            vec![
                felt::hex("0x9ddc2089369cbd1d2291933e9c58c82c819a64d36d22d5781bee83670a5e5d"),
                felt::hex("0x559f66594e0e5576e00f3d95e01bd6de98af0ab071bed5348e9d1d690ede347"),
                felt::hex("0x83ecfb86e227081c49a3fb1f884be3c22c441a7b47f419f757cb5636cf59e3"),
                felt::hex("0x710ebb17fed7802bd2b4c93bb1b28815d464e727bec23beb4df16f42c6e8fd3"),
            ],
        ];

        test_table_verifier_with(
            field_element_size,
            n_columns,
            n_segments,
            n_rows_per_segment,
            exp_proof,
            &data_queries,
            &integrity_queries,
            table_data,
        )
    }
}
