use crate::{
    committed_layers::FriCommittedLayer,
    details::choose_query_indices,
    layers::{FriLayer, FriLayerProxy, FriLayerReal},
    lde::MultiplicativeLDE,
    parameters::FriParameters,
};
use anyhow::{Error, Ok};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use channel::{fs_prover_channel::FSProverChannel, Channel, ProverChannel};
use commitment_scheme::CommitmentHashes;
use num_bigint::BigUint;
use randomness::Prng;
use sha3::Digest;
use std::sync::Arc;

#[allow(dead_code)]
pub struct FriProver<F: PrimeField, P: Prng, W: Digest> {
    params: FriParameters<F, Radix2EvaluationDomain<F>>,
    witness: Vec<F>,
    n_layers: usize,
    committed_layers: Vec<FriCommittedLayer<F, Radix2EvaluationDomain<F>, P, W>>,
    mont_r: F,
}

#[allow(dead_code)]
impl<
        F: PrimeField<BigInt = ark_ff::BigInt<4>>,
        P: Prng + Clone + 'static,
        W: Digest + Clone + 'static,
    > FriProver<F, P, W>
{
    fn new(params: FriParameters<F, Radix2EvaluationDomain<F>>, witness: Vec<F>) -> Self {
        let n_layers = params.fri_step_list.len();
        let committed_layers = Vec::with_capacity(n_layers - 1);
        let mont_r = {
            let size = F::MODULUS_BIT_SIZE.div_ceil(8) * 8;
            let mont_bigint = BigUint::from(2u64).modpow(&BigUint::from(size), &F::MODULUS.into());
            F::from_bigint(<F as PrimeField>::BigInt::try_from(mont_bigint.clone()).unwrap())
                .unwrap()
        };
        Self {
            params,
            witness,
            n_layers,
            committed_layers,
            mont_r,
        }
    }

    fn create_next_fri_layer(
        channel: &mut FSProverChannel<F, P, W>,
        layer: Arc<dyn FriLayer<F, Radix2EvaluationDomain<F>>>,
        fri_step: usize,
    ) -> Arc<dyn FriLayer<F, Radix2EvaluationDomain<F>>> {
        if fri_step != 0 {
            let mut current_layer: Arc<dyn FriLayer<F, Radix2EvaluationDomain<F>>> = layer;

            let mut eval_point = channel.draw_felem();

            for _ in 0..fri_step {
                current_layer = Arc::new(FriLayerProxy::new(current_layer, eval_point));
                eval_point = eval_point.square();
            }

            current_layer
        } else {
            layer
        }
    }

    fn commitment_phase(
        &mut self,
        channel: &mut FSProverChannel<F, P, W>,
        n_verifier_friendly_commitment_layers: usize,
        commitment_hashes: CommitmentHashes,
    ) -> Arc<dyn FriLayer<F, Radix2EvaluationDomain<F>>> {
        assert_eq!(self.witness.len(), self.params.fft_domains[0].size());

        let first_layer: Arc<dyn FriLayer<F, Radix2EvaluationDomain<F>>> = Arc::new(
            FriLayerReal::new(self.params.fft_domains[0], self.witness.clone()),
        );
        let mut current_layer = first_layer;

        for layer_num in 1..=self.n_layers {
            let fri_step = self.params.fri_step_list[layer_num - 1];
            let next_fri_step = if layer_num < self.n_layers {
                self.params.fri_step_list[layer_num]
            } else {
                0
            };

            assert!((layer_num == 1) || (fri_step != 0));

            current_layer =
                FriProver::<F, P, W>::create_next_fri_layer(channel, current_layer, fri_step);

            current_layer = Arc::new(FriLayerReal::new_from_prev_layer(&*current_layer));

            if layer_num == self.n_layers {
                break;
            }

            let committed_layer = FriCommittedLayer::new(
                next_fri_step,
                current_layer.clone(),
                self.params.clone(),
                layer_num,
                F::MODULUS_BIT_SIZE.div_ceil(8) as usize,
                n_verifier_friendly_commitment_layers,
                commitment_hashes.clone(),
                channel,
                self.mont_r,
            );

            self.committed_layers.push(committed_layer);
        }

        current_layer
    }

    fn send_last_layer(
        &self,
        channel: &mut FSProverChannel<F, P, W>,
        last_layer: Arc<dyn FriLayer<F, Radix2EvaluationDomain<F>>>,
    ) -> Result<(), Error> {
        let last_layer_basis_index: usize = self.params.fri_step_list.iter().sum();
        let last_layer_evaluations = last_layer.get_layer()?;

        let lde_domain = self.params.fft_domains[last_layer_basis_index];
        let mut lde_manager: MultiplicativeLDE<F> = MultiplicativeLDE::new(lde_domain, true);
        lde_manager.add_eval(&last_layer_evaluations);

        let coefficients = lde_manager.coeffs(0);
        let degree = {
            let mut deg = 0;
            for i in (0..coefficients.len()).rev() {
                if coefficients[i] != F::ZERO {
                    deg = i;
                    break;
                }
            }
            deg
        };
        let degree_bound = self.params.last_layer_degree_bound;
        assert!(degree < degree_bound);

        let coeffs_mont = to_mont_repr(&[coefficients.to_vec()], self.mont_r);

        assert_eq!(coeffs_mont.len(), 1);

        channel.send_felts(&coeffs_mont[0][0..degree_bound])?;

        Ok(())
    }

    fn prove_fri(
        &mut self,
        channel: &mut FSProverChannel<F, P, W>,
        n_verifier_friendly_commitment_layers: usize,
        commitment_hashes: CommitmentHashes,
    ) -> Result<(), Error> {
        // Commitment phase.
        let last_layer = self.commitment_phase(
            channel,
            n_verifier_friendly_commitment_layers,
            commitment_hashes,
        );

        self.send_last_layer(channel, last_layer.clone())?;

        // Query phase.
        let queries = choose_query_indices(&self.params, channel);

        // Note: following this line, the verifier must not send randomness to the prover.
        channel.states.begin_query_phase();

        // Decommitment phase.
        for layer in &mut self.committed_layers {
            layer.decommit(&queries, channel)?;
        }

        Ok(())
    }
}

pub fn to_mont_repr<F: PrimeField>(segment: &[Vec<F>], mont_r: F) -> Vec<Vec<F>> {
    let mut result: Vec<Vec<F>> = Vec::with_capacity(segment.len());

    for row in segment.iter() {
        result.push(row.iter().cloned().map(|e| e * mont_r).collect());
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::Field;

    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
        Radix2EvaluationDomain,
    };
    use channel::{fs_prover_channel::FSProverChannel, ProverChannel};
    use commitment_scheme::SupportedHashes;
    use felt::Felt252;
    use randomness::{keccak256::PrngKeccak256, Prng};
    use sha3::Keccak256;

    use crate::stone_domain::get_field_element_at_index;
    use crate::stone_domain::make_fft_domains;

    fn test_fri_correctness_with(
        log2_eval_domain: usize,
        fri_step_list: Vec<usize>,
        last_layer_degree_bound: usize,
        n_queries: usize,
        proof_of_work_bits: usize,
        seed: u64,
        offset: Felt252,
        coeffs: Vec<Felt252>,
        witness: Vec<Felt252>,
    ) -> Vec<u8> {
        // Check coeffs evaluate to witness
        {
            let domain = Radix2EvaluationDomain::new_coset(1 << log2_eval_domain, offset).unwrap();
            let poly = DensePolynomial::from_coefficients_vec(coeffs);
            let evals: Vec<Felt252> = {
                let mut values = vec![];
                for i in 0..domain.size as usize {
                    let x = &get_field_element_at_index(&domain, i);
                    values.push(poly.evaluate(&x));
                }
                values
            };
            assert_eq!(evals, witness);
        }

        let domains = make_fft_domains::<Felt252>(log2_eval_domain, offset);

        let params = FriParameters::new(
            fri_step_list,
            last_layer_degree_bound,
            n_queries,
            domains,
            proof_of_work_bits,
        );

        let channel_prng = PrngKeccak256::new_with_seed(&seed.to_be_bytes());
        let mut prover_channel: FSProverChannel<Felt252, PrngKeccak256, Keccak256> =
            FSProverChannel::new(channel_prng);

        let mut prover: FriProver<Felt252, PrngKeccak256, Keccak256> =
            FriProver::new(params, witness);
        prover
            .prove_fri(
                &mut prover_channel,
                0,
                CommitmentHashes::from_single_hash(SupportedHashes::Blake2s256),
            )
            .unwrap();

        let proof = prover_channel.get_proof();
        proof
    }

    #[test]
    fn test_fri_prover_correctness() {
        let log2_eval_domain = 5;
        let fri_step_list = vec![0, 2, 2];
        let last_layer_degree_bound = 2;
        let n_queries = 4;
        let proof_of_work_bits = 15;
        let coeffs = vec![
            felt::hex("0x586486754eaf979eaeb1a8a2db3f3cd613a38a511bb9687f89a35808c47cb71"),
            felt::hex("0x14fea6df1f7b6dc67b136b814d911817c794f8033fcd72f61c13346f4998228"),
            felt::hex("0x25d85db841b0d20c357cd5d0b185a84ac2b58bf378d9016816c10de344bbb20"),
            felt::hex("0x777c088396717c19e3afe003c757175214ee9efb76225504deff72032f55b68"),
            felt::hex("0x3e9a7deba4957c1a11789ad85023e3b39286200306a5afe2b90fca856708254"),
            felt::hex("0x2b3493f9ad93560969a2f4e3e883b92930589416a13a37d5fa3015158f0fa81"),
            felt::hex("0x3cf1da7b26dcf7ae63af541d4b08740953fa85a7a6a83e4c9fa13b4c821fac5"),
            felt::hex("0x14251a199fc5cfe5bdfcf5a7f639050edf7f5f4ca9b96983b27ae0821885606"),
            felt::hex("0xf65e7f29ff7eeb57d1ff26b589d56a13b652c0a4b4994d26c386cb31e369f8"),
            felt::hex("0x46abd1d9886774ed3434729100447968398a155f1c192c4b1927d1397af7f5b"),
            felt::hex("0x4c1d6b93d502b35aa6b5fe9905f478d55310a2e736f6b95fded0db86c7917ba"),
            felt::hex("0x3c20c2cee041eaef1349d9d071a7b9f4b550b91c21d14a79c8e0b9f02bb4da9"),
            felt::hex("0x1e9c9d130ee18553dff0c021c7d7a0a78233da6553fbed2390676ca69a32db2"),
            felt::hex("0x1545ebc9ea27c409dc96a420a5adafbdef1a59733cbbf9452f4e125934954dc"),
            felt::hex("0x10ecbc496594aac6842f6ecd5f051c8ad8f160289efea0a0cc5bd8ae987601a"),
            felt::hex("0x5ed2ef2751544ca33053a8d152715dc749ad400a6b3f17693e10a62de87da0a"),
            felt::hex("0x32b3d2b61f9722a273d31f549a35fcbdcd12f9099d6b5ae554d06b2db2f4d28"),
            felt::hex("0x2dcf34cbbc197cd1e82289950098ad8c673e67191a01f2ffe1521f6ca4c281e"),
            felt::hex("0xca612cda0a7078fe7e71db617b00db4e93e773c41014a7e58da5dba50fc9f3"),
            felt::hex("0x4ae586257c90ec66325c1e7a59183bf0f89a9e0c8240c1e57f312b809222130"),
            felt::hex("0x22b814a3d4dee809b5c4bcd1f4afd3acfc9a26a7cebcf5f3576ead25808bcf4"),
            felt::hex("0x6aeeeb3faaf43fd810ae5ac9c16f78c3588a24d829ee5a4871c9d8eb2292c7c"),
            felt::hex("0x4c7729363b7d5774e8169422bf6f031a5a5866f1b4198e8b59bba5584c03e8b"),
            felt::hex("0x7f2f9cf24dcd07127c18ee83993e38157838fb5c704f236e621bb321c4dd58e"),
            felt::hex("0x31beabb789a131ff885a3d5ba75819d3189b867f1faa8a3daf54063090a84be"),
            felt::hex("0xbe3886f70f55c1f4d92afee42571d7d1648bd008c83f207c7c935e184233"),
            felt::hex("0x4d62517f2822c8607a458224f7e6c856e1665be764f42e7f2afc3c9e1bc599a"),
            felt::hex("0x27b2d798d19f3f38391e0eebb0481ec2379debc7e72a1d868c9446fb5aa18e"),
            felt::hex("0x72f4ef956cd59cfa048abefb013409c6803d6e91afde17043420892c69bc912"),
            felt::hex("0x154a3c3b23f0ad50456519e8e701c5a819f1aea17205f3ac9a4ecc44e77ad5b"),
            felt::hex("0x3476c5e82e824b1b7a919d0a95a6b89a636f487a2374e9425995e703a0a558d"),
            felt::hex("0x8ed8523025b5b3b294ea58b4ede32d22ee3825a6c48e5a82eab1593d205af6"),
        ];
        let witness = vec![
            felt::hex("0x2037a21c5ea8104af0432ab63ab3e9a9bf66cceaeae73976ccd66de4e568417"),
            felt::hex("0x139fdcf6674bd96dc8f9430e5848b4ed6367ec95f5b8f47002a5217e3edc14e"),
            felt::hex("0x74c47cd9ad93a721c54df826e9a0d98f1e483f86345eec3cdaefb6a896486f7"),
            felt::hex("0x53e83449c0a5e804d054d42a908ab734d80c1d10e05717a791af48548cc2904"),
            felt::hex("0x712dd86d28fda2554a340d54405a2cc618e5a55d1c2dac0b9750ac9f5f6c388"),
            felt::hex("0x6e5869ccae857d03a21532a19ebe15c05ebdcae60aee1c513d3e7399e6814f2"),
            felt::hex("0x4d5e1422eb3b70e8c4e50aafacb53621a59d0610762eea29c7d427d0e40d77f"),
            felt::hex("0x387ee019c812c6103fea3938125fa83e6f5622b58e262f55f783da66c139517"),
            felt::hex("0x5c79ace9fed0d99ba88b74c062159d16d5f11b60a6560655ca1e410d88be120"),
            felt::hex("0x6224c41fbd171f66bb49710257ad11ff8423ca1c62b69a4fa725eaacb236987"),
            felt::hex("0x6e0f65996f3d3cae13241717427305d59c7791d4c44ef4e723946a337e9faf3"),
            felt::hex("0x5bca0645831877dd14da19aab5d30dce063b30d879a4338cf67cb3d03c0a40b"),
            felt::hex("0x7939504393ce11aeea9084c11e4024d12f0368ba34fa89d7ba636b1130863fd"),
            felt::hex("0xb9d779f0703ca35f595a1ff35f9511536a245dd81a7dd1409aab904e581940"),
            felt::hex("0x60610022db37f29e4c00251fb523f4979c8ac148edc6e4c90c152b3d697b66d"),
            felt::hex("0x61ee871c01255160305b5f1ef0981bc466b66e7f861c0dd7bbc1e984cf731ca"),
            felt::hex("0x14abfba914595259d38c398dfc40850550d52f5b15b168bf5cb2d25435a1e98"),
            felt::hex("0x77ece7b6a00d25c9817e4683b9289f6da0271d39229a88598b3f8da9276ed2b"),
            felt::hex("0x46a6e9c0959385b9b9cdf25950af72dab5b9e2f25ef7425f1da0fdff5816f42"),
            felt::hex("0xe5ef75df36a25f3091361ffd2a97d376c401585a1d48d2130cd289b444b15a"),
            felt::hex("0x4b1cb1c37ab03a7278e0b5189fb19858a4dfcc91dc6415987950663ef27d87a"),
            felt::hex("0x66b225825072935ccf7759d6865c2ef87212e21f55c2f496415fe449205c2cd"),
            felt::hex("0xb000298dd8707eaebab146f7d29ac602ca52144d6e856b2eb0e524accf4a6b"),
            felt::hex("0x3dd2400fbbf473d3069d50be232c6ae3b44797bdb9df84465412215318b753b"),
            felt::hex("0x315f8418be42f3ea08d7dd73bfa00fd6e337a019166fb0ec2c2f883589e9779"),
            felt::hex("0x58e219b3f490edf02c33d8dcd2b80f65a804cf6a774b62c7bf0bb28697e504b"),
            felt::hex("0x4b346fe2bff5e0eb019bb24cab1d02bc77004bbf4abfa979b0206f0c26635b6"),
            felt::hex("0x3b70da30aa9801158bbc0b455712a11b61a6cca4c2dd6e93798fa145a31b6a4"),
            felt::hex("0x7a3a6e5476513f09b87a03b3c1e9b0cfba62e7576cf0941469130cd0297164e"),
            felt::hex("0x7aeb5111daf9b7d45aac77eda98d7fccd44b8c136f4417862f4116f51be973b"),
            felt::hex("0x28d8134ef781af9ed100fab94c8da840e3a5282f2afcf847ca571b479a13a0c"),
            felt::hex("0x4fe6a2f0e9567c4eb4d1621f24e1727887fc44364650643ea566fed85bca195"),
        ];
        let exp_proof = vec![
            129, 84, 199, 117, 207, 162, 234, 141, 211, 33, 34, 12, 15, 105, 240, 212, 222, 123,
            209, 24, 30, 184, 113, 96, 122, 89, 199, 129, 213, 163, 4, 246, 103, 170, 250, 158,
            171, 208, 8, 186, 43, 105, 40, 79, 139, 247, 144, 22, 36, 195, 197, 230, 246, 135, 202,
            206, 71, 59, 9, 240, 27, 119, 126, 238, 0, 94, 248, 137, 237, 48, 112, 12, 36, 184,
            112, 87, 34, 19, 100, 20, 49, 109, 146, 227, 201, 57, 129, 131, 13, 65, 100, 205, 3,
            158, 178, 185, 3, 187, 149, 240, 94, 131, 219, 236, 250, 90, 18, 70, 100, 235, 146,
            151, 181, 194, 232, 148, 19, 161, 154, 27, 42, 86, 226, 20, 79, 117, 211, 65, 0, 0, 0,
            0, 0, 0, 74, 156, 7, 232, 221, 116, 75, 79, 52, 234, 180, 7, 248, 250, 51, 110, 88, 51,
            195, 44, 181, 145, 104, 216, 133, 85, 172, 193, 168, 230, 34, 104, 134, 9, 2, 226, 158,
            123, 49, 252, 13, 74, 165, 174, 164, 222, 242, 231, 218, 64, 228, 154, 18, 3, 13, 227,
            1, 122, 234, 77, 228, 41, 25, 47, 170, 7, 7, 133, 140, 250, 6, 49, 23, 28, 155, 39,
            157, 234, 63, 87, 246, 43, 18, 225, 74, 143, 220, 118, 250, 169, 154, 24, 185, 228,
            133, 235, 249, 85, 4, 22, 248, 202, 248, 63, 231, 219, 94, 116, 21, 177, 239, 70, 150,
            244, 235, 75, 20, 111, 32, 10, 35, 220, 139, 173, 189, 185, 137, 103, 75, 214, 7, 9, 6,
            156, 199, 244, 221, 70, 114, 17, 31, 223, 100, 40, 90, 67, 46, 87, 185, 144, 38, 240,
            119, 21, 114, 64, 59, 163, 117, 255, 202, 113, 5, 209, 227, 26, 141, 45, 32, 191, 4,
            64, 73, 228, 67, 123, 209, 39, 190, 77, 120, 94, 189, 85, 193, 249, 131, 53, 224, 50,
            214, 205, 0, 66, 3, 135, 60, 246, 225, 180, 35, 205, 72, 50, 20, 152, 45, 146, 143,
            117, 75, 212, 163, 123, 111, 198, 251, 141, 233, 131, 205, 52, 148, 46, 99, 67, 6, 41,
            229, 96, 86, 105, 79, 136, 232, 180, 224, 206, 131, 141, 234, 81, 38, 88, 6, 158, 196,
            157, 102, 40, 174, 213, 74, 8, 151, 157, 156, 48, 7, 86, 90, 57, 208, 230, 55, 32, 176,
            85, 161, 98, 136, 145, 60, 193, 225, 121, 223, 34, 87, 159, 219, 116, 52, 225, 148, 95,
            154, 223, 1, 192, 2, 132, 248, 30, 4, 214, 132, 163, 7, 96, 223, 143, 85, 116, 55, 208,
            221, 95, 32, 187, 143, 40, 60, 0, 195, 180, 87, 207, 119, 157, 180, 191, 3, 110, 206,
            4, 53, 39, 242, 78, 178, 191, 156, 7, 82, 45, 240, 202, 128, 61, 88, 74, 127, 216, 34,
            163, 31, 34, 51, 198, 28, 227, 126, 29, 3, 160, 85, 143, 232, 3, 128, 7, 244, 80, 26,
            41, 78, 13, 161, 151, 14, 126, 23, 219, 205, 14, 174, 113, 159, 95, 22, 93, 12, 166,
            13, 24, 130, 247, 254, 203, 188, 100, 172, 50, 228, 160, 116, 29, 223, 164, 165, 72,
            53, 148, 54, 224, 34, 212, 249, 138, 63, 36, 42, 4, 246, 38, 32, 221, 73, 35, 188, 47,
            42, 197, 44, 22, 207, 110, 144, 100, 5, 126, 21, 243, 105, 125, 248, 250, 171, 42, 144,
            218, 68, 21, 144, 57, 168, 200, 2, 237, 82, 252, 85, 69, 87, 36, 96, 75, 79, 171, 90,
            40, 207, 19, 140, 27, 14, 180, 147, 210, 126, 125, 227, 160, 51, 212, 43, 150, 254,
            156, 61, 235, 3, 2, 184, 204, 42, 33, 90, 14, 127, 37, 126, 89, 143, 118, 51, 123, 113,
            80, 37, 232, 204, 160, 200, 236, 87, 207, 114, 26, 128, 144, 134, 123, 7, 95, 111, 24,
            141, 1, 239, 126, 176, 214, 229, 200, 178, 55, 206, 176, 70, 196, 113, 129, 124, 228,
            46, 252, 235, 9, 157, 164, 222, 212, 201, 47, 7, 238, 94, 209, 172, 34, 76, 163, 8, 26,
            233, 142, 146, 12, 63, 207, 231, 169, 213, 77, 123, 156, 244, 31, 249, 93, 218, 235,
            18, 213, 26, 43, 5, 166, 213, 208, 30, 58, 45, 118, 139, 83, 211, 151, 100, 137, 13,
            205, 86, 177, 216, 239, 51, 137, 53, 232, 209, 42, 185, 156, 170, 53, 4, 226,
        ];
        let seed: u64 = 0x17f7a49e20d141c8;
        let proof = test_fri_correctness_with(
            log2_eval_domain,
            fri_step_list,
            last_layer_degree_bound,
            n_queries,
            proof_of_work_bits,
            seed,
            Felt252::ONE,
            coeffs,
            witness,
        );
        assert_eq!(exp_proof, proof);

        let log2_eval_domain = 4;
        let fri_step_list = vec![0, 1, 2];
        let last_layer_degree_bound = 1;
        let n_queries = 4;
        let proof_of_work_bits = 15;
        let witness = vec![
            felt::hex("0x64433913d23b0a0f2b5498872adef947abc543017a208337bbb65786a3b38de"),
            felt::hex("0x4394addfefccd998a2dfc22bc2f5650c43a6971824a5b6b3b36e2f041e83d11"),
            felt::hex("0x68c6fec68cb182cf62ba29fa531a96c961c7140e22a2cca615648bfb238d856"),
            felt::hex("0x32c1e34b197f5b31787d326d74302537dbed6a3dceb02ce797476cfb2e0cbb4"),
            felt::hex("0x5947036ad70c74c9c4c74f3127ecbbc4b25ebc2d988aa0f934710366f9e4b95"),
            felt::hex("0x1182145365c2fcc3ef93558b5be9e2643fe2854fecbd182f3f146b7ac35b25e"),
            felt::hex("0x32177b9cf753c5007d13d62c015519b2daf2b8865e272ffb36a55ad9846cb68"),
            felt::hex("0x4f0ecf2e2a9afdaf6f18f2b4649fa3fdf96738f7d66bd255cf5fbd49442c54"),
            felt::hex("0x3c8402d947eaa8cd9da9d9e8116c6c2d992cdee9f10adc893d4dd236bf5428e"),
            felt::hex("0x7ee9ee6e1726db186bf1e2156bde6dee8ab0884fb62459284ce73320cc811af"),
            felt::hex("0x755f6dac00997790320b4abddac61212126da4c6501d8e480c198da0d76ebfc"),
            felt::hex("0x758f8c7e91f3396886a2032432dbf78501e96c4c9713a0f6a2a724ffb6abf67"),
            felt::hex("0x1043858078ae89e34abecccd70fc3b8b60e97b4fcfe8b2f144de113d04e88f3"),
            felt::hex("0x11e5f9d2048fe49514d7cd0e26df0441253dfb30202bdffe28ce4618c01741"),
            felt::hex("0x5a90be5522cc6b0be211b35e96e800a1d0102e81493d5b8753a3d3f93e87037"),
            felt::hex("0x52e2ba6ed1a3810a9164ba520b55bc4c5e68c4284765a8596eecc381005ff9e"),
        ];
        let coeffs = vec![
            felt::hex("0x3ca6492a6fe0b5023a397825d012998e1b3d58bf1e1ddb38445e28a21d381f5"),
            felt::hex("0xc94631e50dfef0dde10db68d464f75595fad1ed082b9f6c09b7289d34852c5"),
            felt::hex("0x21541e075182cd345e2b6eaaa5106a012c097e55d076ed2ef95659e5f2034a2"),
            felt::hex("0x5c7b8a672c899d7a9d409198d7a63c395152a7257cb98bacea6cbac9173acac"),
            felt::hex("0x7431e916ea2d7c33f02175a0dd352d07300abd5a45e871a60295f73e27bc48a"),
            felt::hex("0x3540d89e585d708c0fc1eb0c6340be4b12aa19b3d9b8fe568ca5f179eec7896"),
            felt::hex("0x41bfa3313572f5015e93d0e82491fe938064589d9ae5e2e87747c97f2a23fd8"),
            felt::hex("0x32067f761b701cbeb927131fa4a8d843ba17c32e4c1f3cd2835a3f6108105e1"),
        ];
        let exp_proof = vec![
            212, 217, 152, 50, 15, 134, 146, 73, 137, 109, 133, 120, 138, 125, 66, 58, 164, 121,
            125, 69, 112, 114, 76, 242, 135, 239, 73, 12, 160, 57, 93, 122, 90, 12, 66, 76, 107,
            19, 167, 207, 211, 236, 179, 52, 233, 1, 48, 78, 9, 56, 157, 81, 77, 211, 219, 83, 173,
            183, 129, 212, 111, 208, 70, 65, 2, 46, 216, 28, 4, 6, 12, 193, 194, 122, 210, 143,
            106, 106, 229, 89, 180, 108, 232, 150, 164, 74, 170, 179, 40, 29, 139, 138, 184, 66, 8,
            59, 0, 0, 0, 0, 0, 0, 58, 197, 6, 144, 194, 16, 199, 69, 3, 86, 199, 11, 154, 81, 116,
            225, 125, 105, 79, 125, 62, 108, 3, 117, 38, 103, 231, 76, 128, 130, 74, 244, 236, 194,
            7, 213, 247, 39, 231, 28, 29, 46, 245, 184, 103, 161, 130, 114, 110, 250, 165, 202, 10,
            246, 234, 190, 114, 77, 56, 13, 14, 223, 172, 164, 202, 57, 54, 3, 129, 200, 134, 18,
            168, 123, 150, 28, 140, 143, 54, 235, 219, 3, 164, 39, 113, 88, 153, 140, 173, 60, 178,
            109, 102, 93, 175, 127, 205, 140, 52, 129, 105, 47, 156, 4, 249, 80, 164, 101, 0, 24,
            87, 60, 186, 161, 196, 151, 166, 241, 245, 205, 172, 195, 21, 124, 193, 145, 182, 54,
            70, 133, 122, 160, 189, 69, 173, 245, 25, 79, 65, 219, 36, 147, 98, 143, 51, 155, 4,
            146, 220, 14, 61, 140, 42, 176, 118, 219, 182, 133, 185, 211, 128, 127, 47, 137, 226,
            139, 238, 160, 169, 252, 186, 241, 50, 111, 208, 255, 205, 19, 116, 114, 254, 111, 200,
            139, 197, 69, 23, 132, 174, 176, 62, 161, 27, 107, 7, 26, 205, 172, 71, 167, 11, 144,
            139, 58, 39, 192, 7, 255, 74, 83, 167, 172, 253, 185, 154, 103, 243, 104, 227, 6, 52,
            161, 234, 47, 247, 147, 3, 140, 246, 134, 27, 207, 240, 245, 32, 32, 1, 202, 228, 212,
            23, 90, 103, 66, 55, 17, 205, 45, 121, 38, 114, 200, 183, 32, 188, 208, 28, 225, 7,
            118, 180, 203, 229, 52, 76, 138, 18, 221, 120, 62, 83, 162, 239, 140, 152, 206, 42,
            233, 63, 116, 236, 234, 49, 168, 58, 53, 249, 134, 61, 124, 5, 34, 147, 49, 78, 166,
            250, 215, 46, 82, 9, 192, 16, 233, 227, 73, 77, 147, 180, 115, 7, 168, 97, 16, 14, 220,
            10, 17, 167, 80, 223, 222, 7, 172, 249, 200, 78, 10, 219, 39, 11, 40, 183, 18, 66, 130,
            125, 37, 87, 246, 114, 19, 130, 121, 114, 129, 166, 89, 170, 62, 131, 36, 106, 107,
        ];
        let seed: u64 = 0x17f79d3b0c455630;
        let proof = test_fri_correctness_with(
            log2_eval_domain,
            fri_step_list,
            last_layer_degree_bound,
            n_queries,
            proof_of_work_bits,
            seed,
            Felt252::ONE,
            coeffs,
            witness,
        );
        assert_eq!(exp_proof, proof);

        let log2_eval_domain = 4;
        let fri_step_list = vec![0, 2, 1];
        let last_layer_degree_bound = 1;
        let n_queries = 4;
        let proof_of_work_bits = 15;
        let witness = vec![
            felt::hex("0x664ab667f47556e85164804eb1dd4d059cec3151566a5d461a1b89ffa4742e7"),
            felt::hex("0x7ad1ec137b3a592da7715ee8fa8c90b66eede4feca5b3cdbe59d8393003c992"),
            felt::hex("0xaa069c3dbe22826fb1006a2196814ad6c5169ca0ae3db9d8f5eb8d11dd5454"),
            felt::hex("0x3e3daaf4a87f822971674346fcf501f3c70346786ac8a253616143fedcc9df5"),
            felt::hex("0x5aa1ab7d90041bb147fb51d88e9e2da8dc006ac7aef53c801a4026b54618365"),
            felt::hex("0xd2027379aea66b9f81e77d2b375d1a8a2843f2a1b3af93d42f30e24e2eb277"),
            felt::hex("0x7edf5d6b0904ec6c5b1f60ecfa4466fc96c6db9d2f57c98095be91755438853"),
            felt::hex("0x21f88ff8f2be530e8ab7b91e8b30f022a0aaff94e3b7a93d30f11b2ac2f5f6f"),
            felt::hex("0x666d0d91f6916e0137abc7245055af76df8081e285a3f920c3c66cd87220fff"),
            felt::hex("0x10d49f89ee4b673aa12b9db8c9faba651dbfbfeb7599563522e9ae080497871"),
            felt::hex("0x2023c87730a44498f4a245499374fd6582795bad4ef8a1e3696d62c7f9218b5"),
            felt::hex("0x6d0c3fca9e6518de103f91195d18e509d3480c020a6f67346d11b841b658c1"),
            felt::hex("0x77d2af555d45a1157aaa48c2fb98b3755b8e69e92e2ee393d6a87f1ccf3715e"),
            felt::hex("0x1c113ad1e86bb533673bde18ded4a6812a4eab559d291bf5285a1c2c3e74111"),
            felt::hex("0x7a6279b4aea2b5c7589d80f6c033583c512bb90ba355fda74a92b97d4d55eb9"),
            felt::hex("0x617d9e16707a3c9a23cc1ccac18a309012e5f309a26dbb133d7fde9f941151"),
        ];
        let coeffs = vec![
            felt::hex("0x46528ee9a35863899167c19af14a0959bea4a976ce763811c28b7d7b9bf038c"),
            felt::hex("0x270aa48221a3d99fd50eaf9d8ad21076475c3a60f70a65c33006b55726ef342"),
            felt::hex("0x270b0a282e18cb4dbe1c06a4fb169bfe2fddb9e79a400ebe4bdad82d93c376d"),
            felt::hex("0x30705c9a1a2e53e69a83ce3c9312129816fb354b776afbeaa448d47328c88f4"),
            felt::hex("0x442c1ee359abf39807eb88ad3f67b3bd9127082dd7264df2f992c51d0be3c25"),
            felt::hex("0x1be97dee7353777dda2756d95b956ecc62039ab7b5f756e9ee8c964a5ee78df"),
            felt::hex("0x7f0499488cbab733a4fb9eaeaa6c95c886439f9bd086384df7e36c0316c0f20"),
            felt::hex("0x4257e61f8d77db710b3fbbff622ecc4cd6a41bc5219ad79d5762e321a37c797"),
        ];
        let exp_proof = vec![
            93, 179, 153, 108, 253, 65, 129, 59, 155, 222, 13, 33, 231, 64, 45, 41, 62, 59, 158,
            38, 111, 179, 71, 38, 61, 17, 31, 10, 49, 109, 17, 160, 180, 177, 128, 77, 181, 106,
            40, 38, 199, 129, 10, 14, 54, 183, 162, 7, 52, 25, 155, 5, 110, 135, 9, 236, 84, 53,
            52, 57, 234, 105, 141, 170, 5, 88, 0, 208, 22, 127, 211, 116, 28, 211, 104, 243, 186,
            240, 50, 135, 25, 235, 64, 35, 16, 50, 59, 165, 253, 240, 243, 209, 118, 242, 200, 150,
            0, 0, 0, 0, 0, 0, 164, 39, 3, 134, 169, 230, 65, 128, 157, 95, 173, 72, 148, 249, 194,
            221, 139, 98, 231, 231, 163, 68, 84, 129, 84, 27, 104, 138, 7, 166, 108, 180, 19, 161,
            6, 184, 227, 30, 76, 176, 145, 177, 159, 34, 49, 242, 244, 54, 35, 156, 31, 85, 6, 41,
            175, 9, 219, 61, 54, 210, 154, 1, 126, 221, 177, 99, 4, 27, 22, 74, 129, 244, 124, 90,
            216, 105, 188, 172, 253, 72, 124, 130, 218, 70, 146, 17, 143, 129, 119, 117, 164, 35,
            126, 101, 71, 11, 215, 39, 2, 247, 38, 85, 205, 143, 129, 13, 127, 14, 69, 12, 96, 95,
            132, 184, 212, 31, 142, 120, 214, 86, 100, 60, 17, 116, 28, 77, 223, 249, 246, 27, 97,
            233, 114, 36, 95, 250, 10, 203, 87, 62, 121, 141, 21, 239, 166, 1, 47, 112, 48, 93,
            224, 187, 26, 246, 127, 60, 126, 101, 240, 92, 36, 67, 19, 94, 70, 229, 189, 134, 198,
            14, 34, 94, 215, 96, 58, 82, 79, 112, 147, 59, 66, 197, 56, 8, 87, 103, 23, 89, 248,
            173, 142, 20, 176, 28,
        ];
        let seed: u64 = 0x17f7965703127351;
        let proof = test_fri_correctness_with(
            log2_eval_domain,
            fri_step_list,
            last_layer_degree_bound,
            n_queries,
            proof_of_work_bits,
            seed,
            Felt252::ONE,
            coeffs,
            witness,
        );
        assert_eq!(exp_proof, proof);

        let log2_eval_domain = 4;
        let fri_step_list = vec![1, 1, 1];
        let last_layer_degree_bound = 1;
        let n_queries = 4;
        let proof_of_work_bits = 15;
        let witness = vec![
            felt::hex("0x1cf9851157cb769852653697c843d11cd6ba0b0bbab690c508816d1492f49ca"),
            felt::hex("0x464435f3e7fc324d2a74cd705307f0f77132ef75509031eef10fe55e42d3643"),
            felt::hex("0x48e5dc2bcae2e2cf7a3195226a9adcb359589299f29b3e61717dc69b5d32f4"),
            felt::hex("0xcd0d6f405850d6cc8ba005fdf4ea38638e0d609e2fde87847d838ff9edec25"),
            felt::hex("0x4057dbc15290a9717c4a36d776d156db816fcee9f4b813d36f684008df22230"),
            felt::hex("0x25fc6ca01bfdceb27866cb946426c94c1bc636acabc6f1a7944ff7b4f7bcc61"),
            felt::hex("0x6842b1f4a74998de41e61229e24a6fe94d372e06874ef5415e93c1f6185a72e"),
            felt::hex("0x4d884c2f0ff179ea4a63d363ac975e62edfd88b20af6e6466da545f7b8039a0"),
            felt::hex("0x61bd351a59523778b50f0cb66eea0ea75b4bf347f11cd312de03cf26e9b9aef"),
            felt::hex("0x472264c1fd1d2b9d9c0462f88af7bf1d2d701864fb018af90f0220bc15dd623"),
            felt::hex("0x1bce23e5cc1c0858646957a00db7c4e347a314d15116fff03a3397b0bbf31e8"),
            felt::hex("0x7356aac8ce189c47d6251b4086467f11275ff67746e5ecd7de1276b48d7c491"),
            felt::hex("0x19d1adc825b37fab2f0fb1fb7a35b42ae072352fa30b392cb3d8a9bbcd79757"),
            felt::hex("0x6262ddf4f66fd4c2ae7338f656368653b759bcf33d1f7cc830d95488df3f481"),
            felt::hex("0x1fb9f3e9aea6bc46ff80439809a0e1fed50aad65b2bdb3e8dc5537635bc1a74"),
            felt::hex("0x3cc94e0f6c565810558cf49a2330d3a32a385f85a92f8b63621f739780360af"),
        ];
        let coeffs = vec![
            felt::hex("0x621786c824f88e5377c640b67163c03b31d9c2c078066802a50e54f0fa36dd1"),
            felt::hex("0x7c50eecb0a7b9bd9a09f8bb5b9558e8588ff5ee3429b47f507459dced726d0b"),
            felt::hex("0x46c142e5a4eb6deba5ae4a303203d7b83f5b215da78446db9e3154f1f08ea4a"),
            felt::hex("0x26802e8e122147f007eadefb8f1b586911b50b367db1c8ce59ae4384e9ccd55"),
            felt::hex("0x7b0fb526db862c64578786b816ed449e3bbf13acab552fc1f112050610679fa"),
            felt::hex("0x594925314f874f3b8a9d13992829161c237589d22947723f3669f11d164e154"),
            felt::hex("0x4db65eadfa79ae774970f0655351047877028575bac382b9c876fa506fb6df4"),
            felt::hex("0x2f4065044bc371c860d0b6494a03f307f49999df4b7eac68745af16a50cee12"),
        ];
        let exp_proof = vec![
            231, 46, 8, 116, 44, 9, 9, 158, 17, 79, 167, 6, 239, 134, 171, 237, 147, 101, 26, 253,
            196, 138, 4, 135, 37, 84, 149, 123, 170, 224, 31, 22, 252, 243, 193, 98, 24, 32, 104,
            233, 29, 156, 42, 182, 188, 33, 48, 225, 101, 148, 161, 79, 2, 175, 157, 139, 246, 144,
            107, 143, 5, 78, 158, 98, 7, 14, 182, 56, 154, 10, 69, 230, 36, 34, 36, 182, 180, 207,
            21, 45, 253, 70, 139, 68, 38, 7, 81, 246, 194, 56, 189, 128, 103, 237, 162, 155, 0, 0,
            0, 0, 0, 0, 8, 177, 4, 43, 247, 232, 92, 11, 222, 181, 130, 103, 254, 39, 130, 235,
            196, 254, 50, 1, 88, 182, 211, 153, 52, 50, 107, 117, 189, 218, 141, 105, 133, 9, 6,
            90, 139, 51, 137, 97, 95, 27, 114, 211, 233, 53, 89, 166, 240, 33, 195, 153, 57, 199,
            224, 250, 112, 82, 106, 178, 156, 15, 105, 227, 147, 217, 4, 102, 180, 212, 210, 150,
            128, 48, 79, 34, 37, 201, 8, 106, 151, 253, 195, 143, 49, 235, 122, 119, 253, 23, 69,
            197, 70, 23, 254, 133, 181, 58, 153, 0, 72, 198, 218, 20, 252, 107, 190, 201, 141, 8,
            113, 230, 95, 76, 31, 209, 156, 15, 200, 56, 86, 54, 76, 3, 113, 80, 201, 251, 194, 6,
            1, 185, 136, 240, 47, 199, 90, 17, 139, 158, 202, 133, 134, 67, 181, 76, 216, 111, 89,
            119, 16, 212, 213, 43, 220, 20, 142, 32, 17, 78, 82, 123,
        ];
        let seed: u64 = 0x17f795da1b1032fd;
        let proof = test_fri_correctness_with(
            log2_eval_domain,
            fri_step_list,
            last_layer_degree_bound,
            n_queries,
            proof_of_work_bits,
            seed,
            Felt252::ONE,
            coeffs,
            witness,
        );
        assert_eq!(exp_proof, proof);

        let log2_eval_domain = 3;
        let fri_step_list = vec![0, 2];
        let last_layer_degree_bound = 1;
        let n_queries = 4;
        let proof_of_work_bits = 15;
        let witness = vec![
            felt::hex("0x674252648a8cfb6eb35f61fc736f196c97aabda520898fd556d77481275e802"),
            felt::hex("0x33e82edac094f04768082c5a3bc3a5ea55b1c3b905c7ea950cf1da534f731a"),
            felt::hex("0x140b8ddeac2bfff4614885a78dbff1a17c0bb5a819697a64158e14b1b9478ed"),
            felt::hex("0x3fe54f995fa4a4b5fadd2a101fd6692665ea0d436ba92d0cb893d6b54e9808"),
            felt::hex("0x3723528cbbdd735a13bde8256fe165b9ee415f2cac28deb9e5d3ddbd3f7e37a"),
            felt::hex("0x7748cae882c5de585641080c91f40a002d736b279a4372db74b788579e90abe"),
            felt::hex("0x58dce1b40fbe083bb0f2a5512eb983ffa5df16d4543f867ee9e86a8dce02931"),
            felt::hex("0x7b41b9012a5b3ce4cfe4a7877659b8455ddc4f34665e439f444a13a0be754aa"),
        ];
        let coeffs = vec![
            felt::hex("0xa2ae0a9e2f24e8bab58f42a9ba2affc7dc0c17404286ece22f7910daa1b04"),
            felt::hex("0xef42a99a4e9f9222b64c7a967a2b5b2f0b110624c925461f401c989e5a339e"),
            felt::hex("0x349dbc9e7d1c0050da3a631e61db7ee5d6a6e0d91830805271a3d002538928a"),
            felt::hex("0x230dbd21ca57dd12f30aa7f20036b9d40876c0527b8434340f0261e413906d6"),
        ];
        let exp_proof = vec![
            145, 68, 242, 198, 199, 93, 113, 48, 74, 11, 21, 205, 232, 13, 231, 65, 147, 34, 230,
            191, 24, 37, 89, 13, 80, 143, 64, 186, 143, 155, 36, 88, 3, 60, 202, 166, 23, 135, 20,
            166, 21, 208, 170, 79, 17, 190, 196, 235, 81, 154, 111, 101, 143, 142, 223, 43, 11,
            126, 17, 71, 214, 199, 200, 191, 0, 0, 0, 0, 0, 1, 20, 249, 5, 179, 217, 181, 150, 235,
            4, 190, 110, 137, 231, 12, 159, 127, 54, 82, 34, 221, 153, 220, 222, 217, 156, 173,
            189, 252, 225, 66, 255, 3, 241, 50, 2, 233, 39, 218, 209, 81, 108, 112, 57, 141, 127,
            123, 99, 192, 207, 32, 230, 147, 216, 35, 152, 210, 180, 116, 110, 194, 57, 132, 150,
            109, 135, 150, 1, 246, 53, 190, 196, 160, 202, 245, 46, 163, 5, 211, 141, 101, 129,
            105, 9, 16, 224, 26, 47, 251, 67, 88, 240, 124, 12, 223, 139, 20, 115, 207, 3, 211,
            127, 144, 188, 170, 28, 182, 72, 220, 76, 18, 165, 4, 174, 36, 208, 247, 130, 18, 33,
            135, 12, 13, 8, 156, 136, 201, 131, 229, 12, 172, 1, 70, 185, 113, 185, 45, 32, 26, 55,
            136, 245, 229, 23, 11, 2, 191, 65, 60, 218, 198, 59, 221, 162, 86, 214, 26, 243, 127,
            76, 28, 114, 88,
        ];
        let seed: u64 = 0x17f7332f022bccbe;
        let proof = test_fri_correctness_with(
            log2_eval_domain,
            fri_step_list,
            last_layer_degree_bound,
            n_queries,
            proof_of_work_bits,
            seed,
            Felt252::ONE,
            coeffs,
            witness,
        );
        assert_eq!(exp_proof, proof);
    }
}
