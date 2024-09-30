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
    pub fn verify_decommitment(
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
    use crate::{make_commitment_scheme_verifier, table_prover::TableProver, CommitmentHashes};
    use ark_ff::UniformRand;
    use channel::fs_prover_channel::FSProverChannel;
    use channel::ProverChannel;
    use felt::Felt252;
    use rand::Rng;
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

        let mut table_prover = TableProver::new(
            n_segments,
            n_rows_per_segment,
            n_columns,
            field_element_size,
            0,
            commitment_hashes,
            felt::hex("0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1"),
        );

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
        proof: Vec<u8>,
        data_queries: &BTreeSet<RowCol>,
        integrity_queries: &BTreeSet<RowCol>,
        table_data: Vec<Vec<Felt252>>,
    ) {
        let mont_r: Felt252 =
            felt::hex("0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1");
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

            // channel receives data in Mont form thus data_for_verification is in Mont form
            // Table Data is in Standard form, convert it to Mont form and then compare
            assert_eq!(
                *data_for_verification.get(q).unwrap(),
                mont_r * table_data[q.get_col()][q.get_row()],
                "Incorrect response to data query."
            );
        }

        // Check verification, convert data to Mont form and then insert
        for q in integrity_queries.iter() {
            data_for_verification.insert(*q, mont_r * table_data[q.get_col()][q.get_row()]);
        }

        assert!(table_verifier
            .verify_decommitment(&mut verifier_channel, &data_for_verification)
            .unwrap());
    }

    #[test]
    fn test_table_verifier() {
        let field_element_size = 32;
        let n_columns = 2;
        let n_segments = 2;
        let n_rows_per_segment = 2;
        let exp_proof = vec![
            71, 132, 165, 10, 119, 246, 172, 81, 234, 60, 193, 139, 122, 35, 61, 93, 85, 9, 22, 34,
            250, 70, 170, 255, 82, 218, 88, 82, 84, 145, 39, 11, 4, 208, 101, 14, 35, 199, 138,
            153, 75, 54, 23, 135, 115, 134, 216, 97, 166, 88, 109, 18, 69, 44, 89, 44, 9, 201, 55,
            194, 209, 49, 166, 53, 2, 73, 17, 183, 56, 6, 227, 237, 209, 59, 211, 11, 109, 20, 169,
            85, 36, 173, 230, 149, 238, 111, 108, 232, 153, 214, 98, 11, 132, 91, 27, 200, 0, 27,
            43, 14, 57, 196, 188, 170, 115, 109, 60, 183, 208, 44, 115, 250, 44, 40, 67, 107, 124,
            247, 184, 4, 195, 58, 23, 195, 137, 187, 25, 111, 224, 9, 210, 47, 106, 211, 251, 35,
            206, 220, 172, 66, 250, 42, 183, 80, 205, 160, 148, 212, 135, 235, 23, 114, 243, 42,
            33, 247, 209, 236, 1, 107, 4, 119, 6, 89, 43, 202, 223, 252, 111, 129, 170, 229, 106,
            165, 229, 53, 186, 154, 219, 87, 23, 23, 172, 53, 211, 64, 58, 149, 134, 178, 200, 64,
        ];
        let table_data: Vec<Vec<Felt252>> = vec![
            vec![
                felt::hex("0x29ec2635fe381f6dc572588d9697f3347bf6bb6598c7ba0c42b797204249a2d"),
                felt::hex("0x24c62770e0423fc3ff78c418d3036e3f435ac98c1e23eba93d2780b518486e2"),
                felt::hex("0x3a79b8864902faa95a0a33d56fc94b271e18d09122d45f14ba4fcface76ebb0"),
                felt::hex("0x60d1bc1595eddea3b03ba0161ea300b914f61a5f49f2f553e0d3e77aff026de"),
            ],
            vec![
                felt::hex("0x4dfdff911ae2581ed87e19ff875034d604bc4fa4fb38f1299d41b989aa47250"),
                felt::hex("0x5235d70e1f2230aea41a85f98316aab145f359e59942286adc8187d8005e454"),
                felt::hex("0x37603476f5d3fa4ff2b8de6e7a5cb5d845db5afd1248ea2eb39b51e973eeee4"),
                felt::hex("0x78b3b7931cdfd6cf65ffcd7a0c2c56efd7d1e718530e6b8ba2f13b32505983f"),
            ],
        ];
        let data_queries = BTreeSet::from([RowCol::new(2, 1)]);
        let integrity_queries = BTreeSet::from([RowCol::new(1, 1)]);
        let proof = get_proof(
            field_element_size,
            n_columns,
            n_segments,
            n_rows_per_segment,
            table_data.clone(),
            &data_queries,
            &integrity_queries,
        );
        assert_eq!(proof, exp_proof);
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
        let n_rows_per_segment = 4;
        let exp_proof = vec![
            213, 213, 177, 165, 226, 238, 237, 187, 239, 75, 171, 237, 159, 224, 47, 210, 113, 120,
            159, 234, 156, 171, 107, 153, 45, 134, 125, 185, 165, 124, 165, 233, 5, 237, 195, 55,
            176, 18, 11, 121, 210, 192, 153, 60, 189, 117, 57, 66, 231, 84, 41, 84, 66, 206, 224,
            249, 109, 41, 65, 150, 14, 148, 211, 232, 2, 216, 198, 72, 53, 212, 63, 183, 4, 146,
            91, 35, 60, 83, 218, 79, 179, 20, 126, 153, 119, 40, 177, 254, 36, 28, 161, 238, 102,
            198, 127, 135, 1, 200, 118, 247, 247, 78, 83, 73, 118, 161, 178, 159, 159, 65, 4, 41,
            45, 82, 178, 167, 234, 206, 188, 116, 56, 147, 74, 178, 145, 204, 2, 153, 178, 45, 50,
            72, 90, 79, 144, 182, 0, 244, 104, 208, 111, 85, 29, 175, 116, 104, 65, 57, 18, 107,
            89, 146, 44, 229, 213, 220, 123, 72, 12, 212, 252, 85, 91, 203, 200, 5, 229, 236, 68,
            173, 25, 237, 210, 121, 5, 52, 247, 90, 21, 103, 127, 84, 37, 37, 69, 40, 140, 181, 87,
            195, 90, 108, 114, 65, 181, 9, 236, 138, 141, 73, 182, 146, 120, 44, 92, 138, 222, 131,
            83, 19, 247, 213, 203, 250, 148, 186, 41, 191, 150, 119, 100, 228, 98, 126, 130, 237,
            197, 61, 214, 140, 250, 143, 57, 36, 44, 144, 103, 140, 113, 11, 207, 171, 86, 24, 246,
            39, 241, 166, 125, 204, 64, 237, 68, 32, 248, 107, 0, 139, 2, 33, 73, 191, 229, 208,
            174, 238, 94, 47, 252, 55, 92, 213, 9, 66, 150, 58, 127, 228, 239, 204, 37, 17, 54, 39,
            91, 166, 17, 185, 71, 34, 116, 141, 254, 25, 176, 131, 165, 139, 132, 173, 34, 200,
            157, 75, 92, 80, 245, 30, 92, 14, 238, 6, 61, 228, 51, 215, 105, 230, 54, 23,
        ];
        let table_data: Vec<Vec<Felt252>> = vec![
            vec![
                felt::hex("0x6b61e5e37d71e0664a158a6b0b40746ca94948919796e73542f93e17d5a3607"),
                felt::hex("0x2f398bd491bd26dc058c2ecd7bcf0258449b5014394d1f542dd7dd6d5a810f"),
                felt::hex("0x2ce4d6c5b0c41db23fc9a7d0259c810a8bf78cba78693ce1de165e84ef331fb"),
                felt::hex("0x1676f7e38853efe0993b0ca39770c85a2a74ab4410aff111ef09f731e3d8f02"),
                felt::hex("0x3ce7cbdfa3e803f88330ee9dee4cc06e9fb31acc920bb86d7fff75adfce68d1"),
                felt::hex("0x23ad43f3e074a0cabe1f4b71156ed8b3ba7c596b6093e458d4ee761ddeb54e1"),
                felt::hex("0x76f3607f255412f819de7b7bcf7f7b382a35e632da12d2d6840dc7ff14ad425"),
                felt::hex("0x569a30ef8867bf7ec22006eda33665baddc4c6821686f2d94c67dd0b2abd3f5"),
                felt::hex("0x361e712a3255b0841239fcca9e774ee3b6e3350d1ec34c1f9bc6eadd81098a2"),
                felt::hex("0x571887f985063922244e200898841d2a364397b7a06aac13e17eb0b733d2ac4"),
                felt::hex("0x224465b14e6232f7f809e543d03e16cb632e0a206e94b5c56aabdfe98ec36cc"),
                felt::hex("0x43ffbf71db9eed004425f8a2e215eb6d5d88dd12d5843605bbd8883d3b71c34"),
                felt::hex("0x35d6274d307c0de2acb0aaafa0a576068a5f44f0f24070b5a415bb9b9015c9e"),
                felt::hex("0x2ccc9300946d38a27347c686b1e065b9edfdf1a23154abc5d18ff273963bf73"),
                felt::hex("0x2d244816b937b35975812b54429b9dd2cff556d25f87eb326f4e450507b104d"),
                felt::hex("0x277c86abe7bde49b79da996f10b5907893b1af902c5a6df4b3a413ff238f73f"),
            ],
            vec![
                felt::hex("0x26a8ebb2008def3d50fd4e88d07c96abaec6a5b9905040423eb3b7a1c1437b9"),
                felt::hex("0x28fdc6a84a1e295866196d8e0ab5f0ab23aaafc2ba1aefad3ed3c9575da610e"),
                felt::hex("0x5e7e4d6c8a5be024d40682dd5be4ce44fa28d24b4d1c89104d8eb4f5c2cd6b2"),
                felt::hex("0x497dd7f9ecade7d73e5423b822caec6a77af0a1f999b4a3a8da9313b344e3e6"),
                felt::hex("0x76d1cffe494038f439b328505a8639c0a3853002362a55575f5cd93918cdf51"),
                felt::hex("0x5eb0dd4ad0149429efa97f9f0c197c45324b9aea2a8a13b6fd0b6ffc9705d26"),
                felt::hex("0xa3dd054500d84ed78114835e82b8909e46dbd76a8d26fdcf8d712f702ed7c"),
                felt::hex("0x4d86fd464ead1cc4bc9107d591b1d6d34af4eb432b53b252a82b2bfa315fa24"),
                felt::hex("0x1bf62c26db7d75f955b5f8bc4a8baf22ab9ef0856e668d7abaece61bda4662f"),
                felt::hex("0x36db5201aa25816e94904c9427518a8f69d79f91b28e8aa9e9022503e53ee2e"),
                felt::hex("0x195c33f1b5aef25657215324a9f5fa84a44b0ab837651df2457eae90957747b"),
                felt::hex("0x66e09f5b69171a5ebae282fdb794cccdb3eada1a82daceb701921db3012d292"),
                felt::hex("0x1bcd3608703d59c5be5343b3dbe98b06af419c427b3db2bd3a68d1c3b26b7f1"),
                felt::hex("0x78204fae7022e05499174460bf6de3901d8f71a530321942ed959e2a55f3ca1"),
                felt::hex("0x47ad85f8d4b82ac6733f2fa54430e0887931c2552439509b6c1f3b9fd7b3326"),
                felt::hex("0x28f69d8bb4a99e6ea11efbc845291958d83fabbfe2937be8616c62f02142c45"),
            ],
        ];
        let data_queries = BTreeSet::from([RowCol::new(7, 1), RowCol::new(11, 0)]);
        let integrity_queries =
            BTreeSet::from([RowCol::new(4, 1), RowCol::new(7, 0), RowCol::new(11, 1)]);
        let proof = get_proof(
            field_element_size,
            n_columns,
            n_segments,
            n_rows_per_segment,
            table_data.clone(),
            &data_queries,
            &integrity_queries,
        );
        assert_eq!(proof, exp_proof);
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
    }

    fn get_random_queries(
        n_rows: usize,
        n_columns: usize,
        n_data_queries: usize,
        n_integrity_queries: usize,
    ) -> (BTreeSet<RowCol>, BTreeSet<RowCol>) {
        assert!(n_data_queries + n_integrity_queries < n_columns * n_rows);
        assert!(n_columns * n_rows != 0);

        let mut rng = rand::thread_rng();

        let mut data_queries_out = BTreeSet::new();
        let mut integrity_queries_out = BTreeSet::new();

        // Generate random data queries.
        while data_queries_out.len() < n_data_queries {
            let row_col = RowCol::new(rng.gen_range(0..n_rows), rng.gen_range(0..n_columns));
            data_queries_out.insert(row_col);
        }

        // Generate random integrity queries.
        while integrity_queries_out.len() < n_integrity_queries {
            let row_col = RowCol::new(rng.gen_range(0..n_rows), rng.gen_range(0..n_columns));
            // Make sure data and integrity queries are distinct.
            if !data_queries_out.contains(&row_col) {
                integrity_queries_out.insert(row_col);
            }
        }

        (data_queries_out, integrity_queries_out)
    }

    #[test]
    fn test_table_verifier_randomised() {
        for _ in 0..20 {
            let mut rng = rand::thread_rng();

            let field_element_size = 32;
            let n_columns = 6;
            let n_segments = 128;
            let n_rows_per_segment = 8;
            let n_rows = n_rows_per_segment * n_segments;

            let mut table_data: Vec<Vec<Felt252>> = Vec::with_capacity(n_columns);
            for _ in 0..n_columns {
                let mut col: Vec<Felt252> = Vec::with_capacity(n_rows);
                for _ in 0..n_rows {
                    let random_felt = Felt252::rand(&mut rng);
                    col.push(random_felt);
                }

                table_data.push(col);
            }

            let (data_queries, integrity_queries) = get_random_queries(n_rows, n_columns, 3, 5);

            let proof = get_proof(
                field_element_size,
                n_columns,
                n_segments,
                n_rows_per_segment,
                table_data.clone(),
                &data_queries,
                &integrity_queries,
            );

            test_table_verifier_with(
                field_element_size,
                n_columns,
                n_segments,
                n_rows_per_segment,
                proof,
                &data_queries,
                &integrity_queries,
                table_data,
            );
        }
    }
}
