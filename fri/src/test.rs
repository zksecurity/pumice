#[cfg(test)]
mod fri_tests {
    use crate::{stone_domain::translate_index, verifier::FriVerifierTrait};
    use std::marker::PhantomData;

    use ark_poly::{
        domain::EvaluationDomain, univariate::DensePolynomial, DenseUVPolynomial, Polynomial,
        Radix2EvaluationDomain,
    };
    use channel::{
        fs_prover_channel::FSProverChannel, fs_verifier_channel::FSVerifierChannel, Channel,
        ProverChannel,
    };
    use commitment_scheme::{CommitmentHashes, SupportedHashes};
    use felt::{hex, Felt252};
    use num_bigint::BigUint;
    use paste::paste;
    use randomness::{keccak256::PrngKeccak256, Prng};
    use sha3::{Digest, Sha3_256};

    use crate::{
        parameters::FriParameters,
        stone_domain::make_fft_domains,
        verifier::{FirstLayerQueriesCallback, FriVerifier},
    };

    trait FriTestFixtures {
        type Prng: Prng + Clone;
        type Digest: Digest;

        fn new(
            domain_size_log: usize,
            n_layers: usize,
            last_layer_degree_bound: usize,
            fri_step_list: Vec<usize>,
            n_queries: usize,
            proof_of_work_bits: usize,
        ) -> Self;

        fn set_prover_channel(&mut self) -> FSProverChannel<Felt252, Self::Prng, Self::Digest>;

        fn params(&self) -> FriParameters<Felt252, Radix2EvaluationDomain<Felt252>>;
        fn eval_vec(&self) -> Vec<Felt252>;
        fn supported_hash(&self) -> SupportedHashes;
    }

    pub struct Keccak256FriTestTypes<W: Digest> {
        pub _ph: PhantomData<W>,
        pub params: FriParameters<Felt252, Radix2EvaluationDomain<Felt252>>,
        pub eval_vec: Vec<Felt252>,
        pub supported_hash: SupportedHashes,
        pub mont_r: Felt252,
    }

    impl<W: Digest> FriTestFixtures for Keccak256FriTestTypes<W> {
        type Prng = PrngKeccak256;
        type Digest = W;

        fn new(
            domain_size_log: usize,
            n_layers: usize,
            last_layer_degree_bound: usize,
            fri_step_list: Vec<usize>,
            n_queries: usize,
            proof_of_work_bits: usize,
        ) -> Self {
            let domain_size = 1 << domain_size_log;
            let degree_bound = (1 << n_layers) * last_layer_degree_bound;
            let mut rng: FSProverChannel<Felt252, Self::Prng, Self::Digest> =
                FSProverChannel::new(PrngKeccak256::new_with_seed(&[0u8; 4]));

            // RNG 1 : draw offset
            let offset = rng.draw_felem();
            let domains = make_fft_domains::<Felt252>(domain_size_log, offset);

            // RNG 2 : draw coefficients for the test layer
            let mut test_layer_coefs: Vec<Felt252> =
                (0..degree_bound).map(|_| rng.draw_felem()).collect();
            while test_layer_coefs.len() < domain_size {
                test_layer_coefs.push(Felt252::from(0u64));
            }

            let test_layer: DensePolynomial<Felt252> =
                DenseUVPolynomial::<Felt252>::from_coefficients_slice(&test_layer_coefs);
            let mut eval_vec = vec![];
            for elem in domains[0].elements() {
                eval_vec.push(test_layer.evaluate(&elem));
            }

            let params = FriParameters::new(
                fri_step_list.clone(),
                last_layer_degree_bound,
                n_queries,
                domains.clone(),
                proof_of_work_bits,
            );

            let mont_r = hex("0x7fffffffffffdf0ffffffffffffffffffffffffffffffffffffffffffffffe1");

            Self {
                _ph: PhantomData,
                params,
                eval_vec,
                supported_hash: SupportedHashes::Blake2s256,
                mont_r,
            }
        }

        fn set_prover_channel(&mut self) -> FSProverChannel<Felt252, Self::Prng, Self::Digest> {
            let mut prover_channel = FSProverChannel::new(PrngKeccak256::new_with_seed(&[0u8; 4]));

            // commit 3 hashes
            let hash_digests = vec![
                vec![
                    233, 207, 11, 139, 160, 23, 158, 56, 191, 33, 15, 193, 85, 79, 86, 220, 142,
                    118, 55, 98, 193, 194, 90, 230, 45, 166, 1, 161, 192, 130, 154, 241,
                ],
                vec![
                    93, 82, 252, 240, 235, 86, 238, 154, 235, 94, 165, 3, 216, 26, 138, 71, 129,
                    145, 133, 35, 250, 142, 196, 8, 77, 14, 156, 60, 151, 196, 241, 213,
                ],
                vec![
                    242, 36, 204, 11, 155, 46, 250, 149, 187, 159, 94, 203, 45, 234, 180, 157, 183,
                    77, 78, 14, 13, 89, 0, 148, 90, 245, 65, 237, 127, 48, 49, 88,
                ],
            ];

            // send 3 commit hashes while drawing random field elements
            for digest in hash_digests {
                let _ = prover_channel.send_commit_hash(digest);
                prover_channel.draw_felem();
            }

            let mut coeffs_vec = vec![
                hex("0x4d56d0b02111c2b489d41c52dc75b6503ccef051c1b3f4331955ee202722c86"),
                hex("0x3a698e872d28273e4223086c460d6f61aa0fd2586b0e4bdc1a6bad4a38ac9ae"),
                hex("0x437ad2bcc666f5ab2d2ae34aef54206f2c1b60cac67209a3f7d537c8566d20e"),
            ];

            // convert coeffs_vec to montgomery form
            coeffs_vec = coeffs_vec
                .iter()
                .map(|coeff| coeff * &self.mont_r)
                .collect();
            let _ = prover_channel.send_felts(&coeffs_vec);

            // let pow_bytes = vec![0, 0, 0, 0, 0, 60, 139];
            // let _ = self.prover_channel.send_data(&pow_bytes);

            // draw 3 numbers
            for _ in 0..4 {
                prover_channel.draw_number(1024);
            }

            let mut first_layer_evals = vec![
                hex("0x3b169859b500d9f2b4fe19e662701da2e8ae2f69ccb4f9823ae31b9db698838"),
                hex("0x328c64b926d309a915f58d93b14f6f4a14b9349e52bbff4095c892dfbb49834"),
                hex("0x5cfd45df2ef0d8d5a2e1031131c84a49af6282ccbdc4d5d1f615f7c1d5221cd"),
                hex("0x71f85e47f5d6ff258c07902a6fd2b72ab79f6f1e7db51c2c0a77dcaa6a0fdad"),
                hex("0x7db7bdd000289302e012a3b457452c57b63c006b079cecf5f72f00607f4b202"),
                hex("0x1953476dfe56292b79d510f23726bbe08bd04babb878ef7677d8ce7216db71f"),
                hex("0x5818f1fd8f6d77d99b3203bfac2adde65f27d3129f4dbfa87b27a766bb0a6d5"),
                hex("0x5e8141c3a8cf31ff6da32a8caf612c4a723c90f3e1984c690cea9a13c42f61e"),
                hex("0x3d364a04dad87c0a73ce1b816fce044f55d654a9b8c64b973413512aa3246e6"),
                hex("0x6b2e4301b309124ebf570b2416ff6edd118e8b00ca7d58de56cccea5edf392d"),
                hex("0x6c31823e1b429e57c82f73e1a46c0470c3434f7a300dbe082ca4cfa518c530c"),
                hex("0x617cc7be7cd5a3b14b76cdb12801fa7784f414112a5ffc74f826ca327a19a8e"),
            ];

            // convert coeffs_vec to montgomery form
            first_layer_evals = first_layer_evals
                .iter()
                .map(|coeff| coeff * &self.mont_r)
                .collect();
            let _ = prover_channel.send_felts(&first_layer_evals);

            let first_layer_decommitments = vec![
                vec![
                    19, 142, 150, 255, 18, 207, 251, 75, 19, 128, 141, 110, 90, 53, 208, 80, 31,
                    208, 208, 137, 93, 217, 205, 126, 148, 46, 186, 63, 160, 45, 11, 206,
                ],
                vec![
                    171, 255, 18, 164, 220, 58, 254, 119, 190, 229, 89, 14, 43, 81, 209, 201, 12,
                    68, 73, 51, 245, 112, 152, 93, 135, 180, 51, 188, 14, 168, 139, 246,
                ],
                vec![
                    87, 157, 10, 170, 91, 185, 231, 155, 188, 75, 196, 8, 129, 90, 64, 5, 247, 191,
                    197, 158, 51, 101, 159, 86, 85, 121, 33, 207, 123, 129, 238, 135,
                ],
                vec![
                    51, 232, 243, 41, 255, 205, 53, 220, 226, 213, 117, 145, 240, 197, 192, 71,
                    234, 105, 34, 204, 164, 11, 222, 167, 205, 132, 32, 115, 167, 150, 240, 194,
                ],
                vec![
                    21, 198, 234, 126, 11, 72, 136, 148, 225, 217, 74, 210, 39, 110, 34, 153, 130,
                    50, 108, 187, 100, 252, 129, 69, 211, 208, 188, 35, 127, 132, 91, 7,
                ],
                vec![
                    117, 117, 205, 62, 124, 153, 149, 237, 121, 158, 46, 80, 20, 128, 183, 31, 179,
                    167, 203, 104, 183, 82, 42, 65, 249, 118, 104, 5, 26, 139, 76, 6,
                ],
                vec![
                    35, 56, 91, 184, 178, 244, 4, 193, 244, 107, 94, 17, 108, 3, 249, 65, 211, 231,
                    117, 190, 82, 198, 40, 90, 211, 117, 203, 111, 131, 195, 228, 178,
                ],
                vec![
                    164, 28, 153, 100, 79, 169, 159, 227, 53, 237, 65, 171, 77, 174, 224, 47, 35,
                    13, 207, 62, 255, 168, 169, 23, 61, 79, 149, 60, 213, 75, 102, 179,
                ],
                vec![
                    103, 203, 122, 190, 98, 35, 68, 155, 167, 14, 101, 107, 114, 175, 126, 164,
                    178, 9, 126, 203, 220, 93, 236, 223, 81, 58, 171, 156, 69, 41, 31, 15,
                ],
                vec![
                    129, 235, 180, 77, 196, 105, 18, 20, 228, 250, 86, 159, 191, 0, 172, 186, 137,
                    35, 100, 121, 136, 148, 48, 66, 58, 60, 156, 156, 181, 144, 112, 238,
                ],
                vec![
                    119, 214, 217, 219, 118, 216, 40, 23, 78, 115, 60, 225, 214, 234, 28, 156, 108,
                    170, 151, 170, 20, 217, 116, 252, 136, 241, 36, 38, 82, 45, 195, 223,
                ],
                vec![
                    119, 142, 147, 222, 71, 149, 223, 232, 39, 82, 118, 102, 97, 13, 108, 156, 4,
                    133, 69, 59, 100, 123, 161, 27, 154, 191, 20, 172, 67, 4, 21, 43,
                ],
                vec![
                    107, 13, 50, 45, 104, 13, 117, 13, 8, 41, 120, 59, 18, 168, 97, 70, 104, 52,
                    55, 250, 47, 39, 73, 218, 4, 38, 110, 18, 227, 213, 198, 114,
                ],
                vec![
                    46, 112, 30, 2, 22, 171, 144, 77, 8, 239, 73, 124, 212, 60, 201, 172, 196, 237,
                    38, 102, 116, 245, 55, 114, 174, 32, 167, 110, 54, 253, 71, 139,
                ],
                vec![
                    116, 2, 22, 235, 63, 54, 11, 72, 147, 88, 140, 83, 104, 178, 195, 140, 18, 106,
                    151, 145, 55, 19, 95, 72, 180, 152, 0, 29, 65, 178, 132, 251,
                ],
                vec![
                    122, 6, 177, 213, 127, 13, 187, 5, 57, 206, 183, 52, 0, 241, 204, 173, 97, 217,
                    91, 69, 247, 22, 148, 30, 175, 135, 159, 71, 249, 216, 97, 8,
                ],
                vec![
                    71, 118, 152, 216, 116, 151, 174, 92, 27, 14, 231, 209, 62, 78, 209, 17, 64,
                    15, 144, 56, 52, 128, 178, 227, 91, 106, 220, 47, 119, 29, 71, 78,
                ],
            ];

            for node in first_layer_decommitments {
                let _ = prover_channel.send_decommit_node(node);
            }

            let mut second_layer_evals = vec![
                hex("0x1ed573c763647053fdb084c8ab9bd0773c78b006d9efca09f99063e0f2676da"),
                hex("0x450df06879222711f99947cc9519193eb5913ff0bdcb2b30aef4bed4a8faf74"),
                hex("0x7d2af22f1b20026d6a3802e3ec6db2cea2e95754231e252bcbaf7a09c8767d1"),
                hex("0x327be53f5e29e44c667d791b0d5ae932045aa39e0234e943cdde8113d3a2ea0"),
            ];

            // convert second_layer_evals to montgomery form
            second_layer_evals = second_layer_evals
                .iter()
                .map(|coeff| coeff * &self.mont_r)
                .collect();
            let _ = prover_channel.send_felts(&second_layer_evals);

            let second_layer_decommitment_node = vec![
                vec![
                    31, 63, 117, 110, 190, 113, 246, 173, 154, 109, 214, 90, 203, 184, 173, 138,
                    148, 233, 137, 80, 128, 113, 144, 150, 251, 77, 150, 116, 69, 106, 194, 94,
                ],
                vec![
                    68, 140, 237, 37, 191, 13, 57, 207, 1, 48, 120, 161, 87, 88, 204, 69, 102, 198,
                    194, 245, 30, 150, 96, 136, 244, 102, 108, 9, 33, 128, 231, 221,
                ],
                vec![
                    27, 82, 133, 214, 127, 48, 17, 150, 44, 150, 57, 194, 151, 160, 172, 144, 40,
                    240, 38, 111, 244, 147, 110, 2, 135, 131, 201, 246, 3, 51, 161, 113,
                ],
                vec![
                    30, 157, 189, 28, 112, 88, 218, 68, 238, 60, 236, 30, 141, 95, 254, 215, 246,
                    90, 134, 16, 180, 218, 235, 189, 25, 39, 193, 216, 27, 178, 217, 9,
                ],
                vec![
                    2, 243, 59, 137, 240, 134, 148, 136, 102, 18, 120, 210, 122, 238, 94, 65, 86,
                    70, 228, 189, 228, 194, 239, 232, 27, 162, 117, 242, 62, 44, 155, 150,
                ],
                vec![
                    7, 202, 140, 45, 238, 6, 50, 235, 98, 101, 39, 81, 243, 173, 99, 231, 230, 248,
                    121, 132, 37, 100, 129, 173, 190, 36, 196, 136, 208, 204, 166, 236,
                ],
                vec![
                    92, 26, 12, 121, 88, 255, 123, 26, 239, 218, 209, 14, 22, 246, 235, 207, 28,
                    239, 175, 21, 149, 137, 134, 212, 40, 1, 207, 143, 35, 77, 194, 202,
                ],
                vec![
                    176, 126, 19, 128, 222, 69, 147, 61, 215, 233, 216, 220, 108, 216, 84, 1, 72,
                    98, 130, 205, 182, 218, 59, 59, 144, 152, 189, 93, 230, 211, 124, 228,
                ],
                vec![
                    53, 20, 113, 127, 83, 226, 232, 208, 94, 34, 248, 124, 218, 176, 82, 237, 253,
                    0, 51, 93, 43, 248, 242, 223, 124, 158, 70, 161, 112, 66, 149, 47,
                ],
                vec![
                    39, 8, 146, 47, 73, 12, 145, 182, 248, 200, 93, 43, 251, 133, 63, 115, 226,
                    158, 1, 60, 247, 123, 93, 14, 143, 180, 134, 202, 53, 12, 43, 20,
                ],
                vec![
                    184, 0, 132, 79, 139, 239, 65, 14, 24, 245, 158, 8, 46, 138, 165, 94, 116, 145,
                    157, 9, 104, 185, 24, 173, 221, 176, 230, 223, 175, 197, 89, 71,
                ],
                vec![
                    146, 99, 138, 75, 143, 47, 17, 17, 45, 0, 129, 31, 223, 193, 191, 108, 37, 41,
                    77, 229, 185, 189, 255, 214, 16, 113, 39, 50, 108, 46, 90, 180,
                ],
                vec![
                    213, 187, 216, 203, 77, 208, 249, 179, 205, 117, 122, 143, 194, 44, 218, 214,
                    101, 126, 248, 170, 130, 126, 133, 71, 237, 44, 74, 112, 250, 122, 142, 40,
                ],
            ];

            for node in second_layer_decommitment_node {
                let _ = prover_channel.send_decommit_node(node);
            }

            let mut third_layer_evals = vec![
                hex("0x7337d35628e7bb159b48fa8ce05544f9d11bed81bd7b48969536138aaa576c1"),
                hex("0x16aa6c6d0d718bc2c6e67fdcd76433b67f5ad9a2f986f64d461d8443edead06"),
                hex("0x2428af41a81a61c18ab64cb1a9efee81d527fe0b1f774937aecb67e50ae6c39"),
                hex("0x727865094d755214d0206b41b906eeb28f9027ad239b929b9081495775f4cb2"),
                hex("0x42cd44cbf68e710f92202407604bd40538ad38b37cb9f491f3d92cfaeb07628"),
                hex("0x12e3227c59eddd1ae54c935d34ab90a169b8ef6e716db6293e6972552f76d7f"),
                hex("0x7b935cc576f89b8bb9c8703b4a88760529bc39c02da36cc4034253e4f6e4d5a"),
                hex("0x2e7e810aaf560f7fa3f512cb4f3d1a6e3e0c445613efadfb7c0334398d61670"),
                hex("0x17f8be6be90c3894453971d899951789ff3fbd2726a520aa5fc329ec13ae814"),
                hex("0x66d4cfcf5ea4b92e45bc2395d0c830825968901579f4e113d7a4b0df264e8ce"),
                hex("0x3cf8c5d1295d0f6132e265eb60fa5e89d51c8b596655ad7891563c458516b86"),
                hex("0x3897ea65ab5440c115ace8168fff0501b5f325d32c64cc12ba8c5fa57633065"),
                hex("0x1b34c828bb369bedbeae8bba6706da5071d5b891e75e06dac098bb933b0c657"),
                hex("0x2b3d78af398381e9cce5f448647762ff75a38562769114fd34f5b180231a97c"),
                hex("0x28a6fdb1de2ec731fc60c584d0c80b73e176bef55e373684c759cd1c499e23e"),
                hex("0x2521d60691fe17633c9e07620d535fb35c6ab75a6fec675cb486efde7ee6df6"),
                hex("0xec38095f902f4dac26ce00858b170e8dc3f1a63247b5b8566865e1fff45f1c"),
                hex("0x7a5c3b737b5b18bd06f89a0b5ad3a53b5b6862e5cb9fc511f2f6966cb6d8e2e"),
                hex("0xe7f2a0f5ecbebd8207f1d6f076a3d3260d330ff2765cfa1bfa6c3020e7ee50"),
                hex("0x79c5c03c63e6478dfc53d085eb370214a2c152c7e7369326a2cb5dbf136a902"),
                hex("0x17550cad64ec05c519e19d4b4b83f906316228f4a6d291e952340254ca88f88"),
                hex("0x28c35847717983621c999dbb3bd413d0a4c6821bb300a119732e3642e8c5bb3"),
                hex("0x592eec753ade908b0a8082bd753f98c7ed0f758a6cc0d0109af7c805f1b52b4"),
                hex("0x3636c914c970bddc634e450443b337c32759392d223c99465c333a21f90b117"),
                hex("0x3d4e8511c98fc1b5e63dac503ece854a9fa0bb986ae45b560270706c773920f"),
                hex("0x7fb05d9d1db243bf2b3e57420c4800624a92a13bdafec0c131df35d413669f5"),
                hex("0x5de9cf3bfc7d3192a75c476f25e6d59811f16547fe53dd30e377b6f0b4e81ea"),
                hex("0x1fc9374c591d4d9fec3e37b706392ebb77ee4efb05a868f7eb47ae7358e6595"),
            ];

            // convert third_layer_evals to montgomery form
            third_layer_evals = third_layer_evals
                .iter()
                .map(|coeff| coeff * &self.mont_r)
                .collect();
            let _ = prover_channel.send_felts(&third_layer_evals);

            let third_layer_decommitment_node = vec![
                vec![
                    122, 185, 53, 61, 112, 41, 222, 97, 247, 19, 67, 102, 245, 111, 81, 18, 249,
                    81, 20, 116, 183, 117, 121, 151, 229, 189, 163, 122, 156, 184, 88, 240,
                ],
                vec![
                    78, 18, 35, 253, 198, 0, 67, 9, 36, 71, 2, 248, 53, 29, 14, 211, 44, 131, 228,
                    49, 45, 62, 29, 145, 183, 11, 4, 252, 107, 192, 67, 179,
                ],
            ];

            for node in third_layer_decommitment_node {
                let _ = prover_channel.send_decommit_node(node);
            }

            prover_channel
        }

        fn params(&self) -> FriParameters<Felt252, Radix2EvaluationDomain<Felt252>> {
            self.params.clone()
        }

        fn eval_vec(&self) -> Vec<Felt252> {
            self.eval_vec.clone()
        }

        fn supported_hash(&self) -> SupportedHashes {
            self.supported_hash.clone()
        }
    }

    struct TestFirstLayerQueriesCallback {
        log_len: usize,
        eval_points: Vec<Felt252>,
    }

    impl TestFirstLayerQueriesCallback {
        fn new(eval_points: Vec<Felt252>) -> Self {
            Self {
                log_len: eval_points.len().ilog2() as usize,
                eval_points,
            }
        }
    }

    impl FirstLayerQueriesCallback<Felt252> for TestFirstLayerQueriesCallback {
        fn query(&self, _indices: &[u64]) -> Vec<Felt252> {
            let mut result = vec![];
            for i in _indices {
                let translated_index = translate_index(*i as usize, self.log_len);
                result.push(self.eval_points[translated_index as usize]);
            }
            result
        }
    }

    fn test_correctness<T: FriTestFixtures>() {
        let domain_size_log = 10;
        let n_layers = 7;
        let last_layer_degree_bound = 3;
        let fri_step_list = vec![0, 2, 1, 4];
        let n_queries = 4;
        let proof_of_work_bits = 0;

        let mut fixture = T::new(
            domain_size_log,
            n_layers,
            last_layer_degree_bound,
            fri_step_list,
            n_queries,
            proof_of_work_bits,
        );

        let commitment_hashes = CommitmentHashes::from_single_hash(fixture.supported_hash());
        let verifier_channel = FSVerifierChannel::<Felt252, PrngKeccak256, Sha3_256>::new(
            PrngKeccak256::new_with_seed(&[0u8; 4]),
            fixture.set_prover_channel().get_proof(),
        );

        let mut verifier = FriVerifier::new(
            verifier_channel,
            fixture.params(),
            commitment_hashes,
            TestFirstLayerQueriesCallback::new(fixture.eval_vec()),
        );

        let _ = verifier.verify_fri();
    }

    macro_rules! generate_tests {
        ($($name:ident: $type:ty),*) => {
            paste! {
                $(
                    #[test]
                    fn [<correctness_$name>]() {
                        test_correctness::<$type>();
                    }
                )*
            }

        }
    }

    generate_tests!(
        keccak256_pow_keccak256_channel: Keccak256FriTestTypes<Sha3_256>
    );
}
