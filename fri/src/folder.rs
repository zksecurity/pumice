use crate::stone_domain::get_field_element_at_index;
use anyhow::Error;
use ark_ff::fields::batch_inversion;
use ark_ff::{FftField, PrimeField};
use ark_poly::Radix2EvaluationDomain;
use std::sync::Arc;

pub struct MultiplicativeFriFolder;

#[allow(dead_code)]
impl MultiplicativeFriFolder {
    // Computes the values of the next FRI layer given the values and domain of the current layer.
    pub fn compute_next_fri_layer<F: FftField + PrimeField>(
        domain: Radix2EvaluationDomain<F>,
        input_layer: &[F],
        eval_point: &F,
    ) -> Result<Vec<F>, Error> {
        assert_eq!(input_layer.len(), domain.size as usize);

        let mut elements: Vec<F> = (0..domain.size as usize)
            .map(|i| get_field_element_at_index(&domain, i))
            .collect();
        batch_inversion(&mut elements);

        let mut next_layer = Vec::with_capacity(input_layer.len() / 2);
        for j in (0..input_layer.len()).step_by(2) {
            let x_inv = elements[j];
            next_layer.push(Self::fold(
                &input_layer[j],
                &input_layer[j + 1],
                eval_point,
                &x_inv,
            ));
        }

        assert_eq!(next_layer.len() * 2, input_layer.len());
        Ok(next_layer)
    }

    // Computes the value of a single element in the next FRI layer given
    // two corresponding elements in the current layer.
    pub fn next_layer_element_from_two_previous_layer_elements<F: FftField + PrimeField>(
        f_x: &F,
        f_minus_x: &F,
        eval_point: &F,
        x: &F,
    ) -> F {
        let x_inv = x.inverse().unwrap();
        Self::fold(f_x, f_minus_x, eval_point, &x_inv)
    }

    // Multiplicative case folding formula:
    // f(x)  = g(x^2) + xh(x^2)
    // f(-x) = g((-x)^2) - xh((-x)^2) = g(x^2) - xh(x^2)
    // =>
    // 2g(x^2) = f(x) + f(-x)
    // 2h(x^2) = (f(x) - f(-x))/x
    // =>
    // 2g(x^2) + 2ah(x^2) = f(x) + f(-x) + a(f(x) - f(-x))/x.
    fn fold<F: FftField + PrimeField>(f_x: &F, f_minus_x: &F, eval_point: &F, x_inv: &F) -> F {
        *f_x + *f_minus_x + *eval_point * (*f_x - *f_minus_x) * *x_inv
    }
}

#[allow(dead_code)]
pub fn fri_folder_from_field() -> Arc<MultiplicativeFriFolder> {
    Arc::new(MultiplicativeFriFolder)
}

#[cfg(test)]
mod tests {
    use crate::lde::MultiplicativeLDE;
    use crate::{
        folder::MultiplicativeFriFolder,
        stone_domain::{get_field_element_at_index, make_fft_domains},
    };
    use ark_ff::{FftField, Field, PrimeField, UniformRand};
    use ark_poly::{
        univariate::DensePolynomial, DenseUVPolynomial, Polynomial, Radix2EvaluationDomain,
    };
    use felt::Felt252;

    #[test]
    fn test_compute_next_fri_layer() {
        let log_domain_size = 5;
        let offset = felt::hex("0x29a0bdbcd8cd08bb6b70935546ac997e2ac9ee3574396f8407b3b6006ebf3ca");
        let domains = make_fft_domains::<Felt252>(log_domain_size, offset);

        let bases0 = [
            felt::hex("0x29a0bdbcd8cd08bb6b70935546ac997e2ac9ee3574396f8407b3b6006ebf3ca"),
            felt::hex("0x565f42432732f854948f6caab9536681d53611ca8bc6907bf84c49ff9140c37"),
            felt::hex("0x7eb86b3d389c0c36cdbbbbe1dd4f197629d60d544aae765f62156a23a8a980c"),
            felt::hex("0x14794c2c763f4d93244441e22b0e689d629f2abb55189a09dea95dc57567f5"),
            felt::hex("0x110f082f8db02b9d0c8f4af68b3fa7ded5ac00b29ee5a2ddfdb7b13cf1cd8a"),
            felt::hex("0x7eef0f7d0724fe562f370b50974c058212a53ff4d611a5d2202484ec30e3277"),
            felt::hex("0x140ae8aaff417530e4bcefbb2fddc6e290b94ac0261b6c06e31782a09c09754"),
            felt::hex("0x6bf5175500be8bdf1b431044d022391d6f46b53fd9e493f91ce87d5f63f68ad"),
            felt::hex("0x29562840a384aa192a3b4c5c5f39c4fae6cf92cdcd74b02a37f119fff0ed178"),
            felt::hex("0x56a9d7bf5c7b56f6d5c4b3a3a0c63b0519306d32328b4fd5c80ee6000f12e89"),
            felt::hex("0x642aba763ad5b11a960299fd6ea1b7817c54ea84d3ec3c99d46c519f42881a8"),
            felt::hex("0x1bd54589c52a4ff569fd6602915e487e83ab157b2c13c3662b93ae60bd77e59"),
            felt::hex("0x7b5a348e0b42b4cb5a85e9c0902a7072c47972132d5a1f27ecc9e26144d27ea"),
            felt::hex("0x4a5cb71f4bd4c44a57a163f6fd58f8d3b868decd2a5e0d813361d9ebb2d817"),
            felt::hex("0x79da2436d240e13964c027be5a677a04580d55979806d8bf3d425e23f2982a4"),
            felt::hex("0x625dbc92dbf1fd69b3fd841a59885fba7f2aa6867f92740c2bda1dc0d67d5d"),
            felt::hex("0x1d7213d302013121fe4d094450536c36471110ddc301c0a8ed190e4704d88fd"),
            felt::hex("0x628dec2cfdfecfee01b2f6bbafac93c9b8eeef223cfe3f5712e6f1b8fb27704"),
            felt::hex("0x7bc2603b6958befb333f20ecda838cbfc99f373ac8d3b4c21f3ce79379282c"),
            felt::hex("0x7843d9fc496a75204ccc0df13257c73403660c8c5372c4b3de0c3186c86d7d5"),
            felt::hex("0xd2280e83080e02ababe56f636d5f72c456c1cf9c1609a9d99734c66c77e816"),
            felt::hex("0x72dd7f17cf7f20e54541a909c92a08d3ba93e3063e9f6562668cb39938817eb"),
            felt::hex("0x2bd6d3ffd6dad2fbea1a4deece463af09e6ce5f14c9f13aea488dcf688441c5"),
            felt::hex("0x54292c0029252e1415e5b21131b9c50f61931a0eb360ec515b77230977bbe3c"),
            felt::hex("0x3894925105848561ceba7eb2bcdfe638d607bec29a8d1723e5c575910055ab2"),
            felt::hex("0x476b6daefa7b7bae3145814d432019c729f8413d6572e8dc1a3a8a6effaa54f"),
            felt::hex("0x5f1549e83128168b9b7598078357ca9fb653099395fdaba18ddde15898c88f0"),
            felt::hex("0x20eab617ced7ea84648a67f87ca8356049acf66c6a02545e72221ea76737711"),
            felt::hex("0x3b517c88b03410612cba4db9115b9fbc50c85adad71607f3fa788b9b288934d"),
            felt::hex("0x44ae83774fcbf0aed345b246eea46043af37a52528e9f80c05877464d776cb4"),
            felt::hex("0x767a575ffa686a1c3445bc62b1699e4297745e488a54858caeb2f67933ae951"),
            felt::hex("0x985a8a0059796f3cbba439d4e9661bd688ba1b775ab7a73514d0986cc516b0"),
        ];

        let bases1 = [
            felt::hex("0x46dc26589f36e03ab3959ef92a5bfd8962787912a901ddc68230d552f4406d3"),
            felt::hex("0x3923d9a760c920d54c6a6106d5a402769d8786ed56fe22397dcf2aad0bbf92e"),
            felt::hex("0x5ea5ba8e615c62cdce3c0afd7360c246fa21c06b95a3b1bdc69fe5e42d4b93c"),
            felt::hex("0x215a45719ea39e4231c3f5028c9f3db905de3f946a5c4e4239601a1bd2b46c5"),
            felt::hex("0x11f6209566fd05a5c20dfbdc6717a1004eebf6f4061b8829ca7218aed2205ad"),
            felt::hex("0x6e09df6a9902fb6a3df2042398e85effb114090bf9e477d6358de7512ddfa54"),
            felt::hex("0x643bc7a8ddf37b81a0ab4c8825a3d5e4392bbd602f6a006997f0ecb06107542"),
            felt::hex("0x1bc43857220c858e5f54b377da5c2a1bc6d4429fd095ff96680f134f9ef8abf"),
            felt::hex("0x527a01507e8dc2011d1588a3c87b20c8461e6f8747c081efd616b7137a76588"),
            felt::hex("0x2d85feaf81723f0ee2ea775c3784df37b9e19078b83f7e1029e948ec8589a79"),
            felt::hex("0x4a61a758f1dfc77232387ae88d4f0b7acfc38e6520965f1a192e9ee366a03de"),
            felt::hex("0x359e58a70e20399dcdc7851772b0f485303c719adf69a0e5e6d1611c995fc23"),
            felt::hex("0x3cd5b642a66f505dc8e7816102df6e96d63cacf24ff2454d9f094c10ca11138"),
            felt::hex("0x432a49bd5990b0b237187e9efd20916929c3530db00dbab260f6b3ef35eeec9"),
            felt::hex("0x35dab06cd31fbe633d8a2081876be2f5237d1df39b3843b4ac15970fe5ca728"),
            felt::hex("0x4a254f932ce042acc275df7e78941d0adc82e20c64c7bc4b53ea68f01a358d9"),
        ];

        let coeffs = [
            felt::hex("0x30527a7343ff56454f6f27332f67e250b0b70d5de8c3fa0785cfae7ef766d9"),
            felt::hex("0x66921873a2c48ef3aba0880ba7041a408f03aec946e965e427cbc873ba8ff33"),
            felt::hex("0x4e42a0e81f9c7a6240c43e0b90b2fc0997a11204b116c66a869c133a0d8e24d"),
            felt::hex("0x255b4d9bae24ad88d8a801d6cd63ff842fecacb170d0e003e8735ad0299549d"),
        ];

        let eval_point =
            felt::hex("0x55c2c9531a84c277bd942c1e0b5fa1ed1da580f789674359c3069a3e64359ac");

        let first_layer_evals_exp = [
            felt::hex("0x572124567f55614f764dc81e98d6601e09565db76aeb0b52d08fb0cb6d4bc41"),
            felt::hex("0x138dc3adbfe28df5d01d72be96976669a49c36f3c1b901f4db62e834fd226e0"),
            felt::hex("0x6694f5ad0df09ca8faf5ed2b5e214491eb614f8580d0b31588d4ed54c85e9e5"),
            felt::hex("0x3ad0c0eb83d74bc3127aa1c43e4aed7a92d9df26ccbc3e24acac654a8b0ce60"),
            felt::hex("0x392670fd3d1ddd54428310c07a818d7c56f8ec8958d05c852ac64940442d46e"),
            felt::hex("0x61cee05730c1d6b94d90a8f556e5971fa71d9263451439a80c96e56b38988af"),
            felt::hex("0x5253f3a3f5793f5685f1003d5e41133a2fa761ac02736c0721f384e128229cd"),
            felt::hex("0x1ecb59a46da6e44d3dd70fd99c31c0bdfe6fe2bed9d8fc4d8823381318f147c"),
            felt::hex("0x4d1b3df696e0cb34653697b67a415178d16014c759c933f0017243d48eacd33"),
            felt::hex("0x54fb02afc7a866ae80901c63928aeb31b01ca1ca3f8a0b63784a181602f44cc"),
            felt::hex("0x4e3ed4556ca4bc0f023789f1e5c7250308c030a1680ef3d97da1d20cefbd28a"),
            felt::hex("0x1bbf89a105d1e9bf6bdd8bc0d94696e6a1f0dc2478cecb54ea15bda83c7b6dd"),
            felt::hex("0x502425710cb2fdea5d0936c00c9685fe915b6e8300471c62e38216c48e72260"),
            felt::hex("0x7ce963a978182d31f873d1049fd361973047ff88b0d0af5a17dcdcbecbaf10e"),
            felt::hex("0x4b25804d497c160e1ddd4cbb5e8e360a9708dfdcc77211d5b45f96ba53a5789"),
            felt::hex("0x73e1953502b89796e081754cc0e1daf3d381756f01a720ef31b561621013070"),
            felt::hex("0x35e5d2bf549c74cb20e99228be90298ae3097b9917e5ca22633e194d24cdc2a"),
            felt::hex("0x2e69ccfd6220f3e7935225d15593bac8e3324124092762cf99de44eb999bb70"),
            felt::hex("0x1d199d9342b462d0696b3ebbe6ba82da64ace8d7fbbfdd608297c41b5d12e81"),
            felt::hex("0xaab614cd78e0b1e3634d316d0fb916601451dc25d63f42f61bfc94ba25d54a"),
            felt::hex("0x7111d9f1678f069d6261545c4c919821f9ee931815d6c98a9b86edcdcafe2a4"),
            felt::hex("0x51c261e98172d6d86c6664e57084852acd21e4f246d983fcee6003b8e0e0c71"),
            felt::hex("0x37e2d49c2109ea58e987c80921d11cb87ab20f79b1f393f82849387d7e2eb20"),
            felt::hex("0x115d8e25c6f40fe29b8c4881ecf2be8eea6b3bd36b8d1d022f43c19b93cc131"),
            felt::hex("0x24a0d7d1973067b40dffc733f6248ddbda5f4cd1fd07e1728255e94abc1e189"),
            felt::hex("0x6ed8fbf4599141d784fa1c3e8b2684ff69a7be4383fd84242db645a1bf6a88a"),
            felt::hex("0x602827aa17977a9273a53e5f8f228334f8f8f291d08f4a0e178b0f392fc4898"),
            felt::hex("0x1872a32cc8a6b3934d3ca7fabb6c6283ef2dc5b0289c4edd19dcad7a128c8bb"),
            felt::hex("0x23cbad72a9eb85ba783de63454a34ba2aed7f2fd40c7052a90d0b9fe270a276"),
            felt::hex("0x4288871d2ca0ce0e429c4db67b39afc90e7031fff1cd71612e5a2eff92916f5"),
            felt::hex("0xcc4a22640e3b9a8f9a7d168cf78d6728fe2e5d235b0369853375685c4578c3"),
            felt::hex("0x18fbc7e6b98fc92f9f59c4792c8426b5df02b88811ec515dcf11ac1c3fe6937"),
        ];

        let expected_res = [
            felt::hex("0x2a11f55decc61d165dc8351a956f7d2dfdfc15268efb5d2d0001c8e7b8690a9"),
            felt::hex("0x11b5d3c2149c246e56a0a2e1034b266feaf31b8681ecbc143a4bd3265817c7c"),
            felt::hex("0x3c94248bb909e507f82176e14c869ceeb17161bf1ad841706284a5e7faa6baa"),
            felt::hex("0x7f33a49448585d8cbc47611a4c3406af377dceedf60fd7d0d7c8f62615da17c"),
            felt::hex("0x34fd2166c84e3102cc29a460dc4032db5c28a7d191d3bb7c64e050d0ec4d59c"),
            felt::hex("0x6caa7b939141081e83f339abc7a70c28cc688db7f145dc4d56d4b3d2433789"),
            felt::hex("0x6089fd5fb2e4053c3e79c969ac8601b2659154fe9d5d8ddaab5ca2538b90ebb"),
            felt::hex("0x5b3dcbc04e7e3d5875ef0e91ec34a1eb835ddbae738a8b668ef0f9ba84efe6b"),
            felt::hex("0x7c1165685121a482862b52ebdcd13fe366701262a6c9f914fe977f87fb379b"),
            felt::hex("0x3406b2c97c50273c8c0622ccdaed8f9fb2882f86e67b79afea64241590cd58a"),
            felt::hex("0x7853c1bb0cc8f874a86f7af95dd359067ee5a0c6c3f200483d854b950076052"),
            felt::hex("0x43740764f4994a200bf95d023ae74a976a098fe64cf618f8fcc85079100acd4"),
            felt::hex("0x6f92a08705b1e9c5a2c88045184f91aaf0e00a19521744071f0e6c42e3c5cde"),
            felt::hex("0x4c352898fbb058cf11a057b6806b11f2f80f2693bed0d53a1b3f2fcb2cbb048"),
            felt::hex("0x13912e2f9322d8aec87498348eb7f52cee916919c4fe851863a834fd6b81732"),
            felt::hex("0x28369af06e3f68d5ebf43fc70a02ae70fa5dc7934be99428d6a56710a4ff5f3"),
        ];

        // check bases
        assert_eq!(domains[0].size as usize, bases0.len());
        assert_eq!(domains[1].size as usize, bases1.len());
        for (i, base) in bases0.iter().enumerate() {
            assert_eq!(get_field_element_at_index(&domains[0], i), *base);
        }
        for (i, base) in bases1.iter().enumerate() {
            assert_eq!(get_field_element_at_index(&domains[1], i), *base);
        }

        // check first layer evals
        assert_eq!(first_layer_evals_exp.len(), domains[0].size as usize);
        let mut first_layer_eval = Vec::with_capacity(domains[0].size as usize);
        for i in 0..domains[0].size as usize {
            // Multiplicative case: a_3*x^3 + a_2*x^2 + a_1*x + a_0.
            let x = &get_field_element_at_index(&domains[0], i);
            let eval = coeffs[0]
                + &coeffs[1] * x
                + &coeffs[2] * &x.square()
                + &coeffs[3] * &x.square() * x;
            assert_eq!(first_layer_evals_exp[i], eval);
            first_layer_eval.push(eval);
        }

        //check expected res
        assert_eq!(expected_res.len(), domains[1].size as usize);
        let mut res = Vec::with_capacity(domains[1].size as usize);
        for i in 0..domains[1].size as usize {
            // value: 2 * ((a_2 * x + a_0) + eval_point * (a_3 * x + a_1)).
            let x = &get_field_element_at_index(&domains[1], i);
            let val = Felt252::from(2u64)
                * (coeffs[2] * x + &coeffs[0] + eval_point * (&coeffs[3] * x + &coeffs[1]));
            assert_eq!(expected_res[i], val);
            res.push(val);
        }

        let folded_res = MultiplicativeFriFolder::compute_next_fri_layer(
            domains[0],
            &first_layer_eval,
            &eval_point,
        )
        .unwrap();
        assert_eq!(folded_res, expected_res);
    }

    #[test]
    fn test_compute_next_fri_layer_randomised() {
        let mut rng = rand::thread_rng();
        let log_domain_size = 5;
        let offset = Felt252::rand(&mut rng);
        let bases = make_fft_domains::<Felt252>(log_domain_size, offset);
        let eval_point = Felt252::rand(&mut rng);
        let coeffs: Vec<Felt252> = (0..4).map(|_| Felt252::rand(&mut rng)).collect();

        let mut first_layer_eval = Vec::with_capacity(bases[0].size as usize);
        for i in 0..bases[0].size {
            // Multiplicative case: a_3*x^3 + a_2*x^2 + a_1*x + a_0.
            let x = &get_field_element_at_index(&bases[0], i as usize);
            let eval = coeffs[0]
                + &coeffs[1] * x
                + &coeffs[2] * &x.square()
                + &coeffs[3] * &x.square() * x;
            first_layer_eval.push(eval);
        }

        let mut res = Vec::with_capacity(bases[1].size as usize);
        for i in 0..bases[1].size {
            // value: 2 * ((a_2 * x + a_0) + eval_point * (a_3 * x + a_1)).
            let x = &get_field_element_at_index(&bases[1], i as usize);
            let val = Felt252::from(2u64)
                * (coeffs[2] * x + &coeffs[0] + eval_point * (&coeffs[3] * x + &coeffs[1]));
            res.push(val);
        }

        let folded_res = MultiplicativeFriFolder::compute_next_fri_layer(
            bases[0],
            &first_layer_eval,
            &eval_point,
        )
        .unwrap();
        assert_eq!(folded_res, res);
    }

    fn extrapolate_point<F: FftField + PrimeField>(
        base: Radix2EvaluationDomain<F>,
        lde: &[F],
        eval_point: F,
    ) -> F {
        let mut lde_manager = MultiplicativeLDE::<F>::new(base, true);
        lde_manager.add_eval(lde);
        let evaluation_results = lde_manager.eval(eval_point);
        evaluation_results[0][0]
    }

    #[test]
    fn test_evaluate_at_point() {
        let mut rng = rand::thread_rng();

        let log_domain_size = 13;
        let degree = 16;
        let bases = make_fft_domains(log_domain_size, Felt252::ONE);

        let original_eval_point = Felt252::rand(&mut rng);
        let mut eval_point = original_eval_point;

        let coeffs: Vec<Felt252> = (0..degree + 1).map(|_| Felt252::rand(&mut rng)).collect();
        let poly = DensePolynomial::from_coefficients_vec(coeffs);

        let mut current_layer: Vec<Felt252> = Vec::with_capacity(bases[0].size as usize);
        for i in 0..bases[0].size {
            let x = &get_field_element_at_index(&bases[0], i as usize);
            let eval = poly.evaluate(x);
            current_layer.push(eval);
        }

        let f_e = extrapolate_point(bases[0], &current_layer, eval_point);

        for i in 1..log_domain_size {
            current_layer = MultiplicativeFriFolder::compute_next_fri_layer(
                bases[i - 1],
                &current_layer,
                &eval_point,
            )
            .unwrap();
            eval_point = eval_point.square();

            let res = extrapolate_point(bases[i], &current_layer, eval_point);
            let correction_factor = Felt252::from(1 << i);
            assert_eq!(correction_factor * f_e, res);
        }
    }
}
