use ark_ff::PrimeField;
use ark_poly::Radix2EvaluationDomain;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_poly::domain::EvaluationDomain;
use randomness::keccak256::PrngKeccak256;
use randomness::Prng;
use channel::fs_prover_channel::FSProverChannel;
use channel::{Channel, FSChannel, ProverChannel, VerifierChannel};
use felt::Felt252;
use sha3::Sha3_256;
use hex_literal::hex;

type TestProverChannel = FSProverChannel<Felt252, PrngKeccak256, Sha3_256>;
fn generate_prover_channel() -> TestProverChannel {
    let prng = PrngKeccak256::new_with_seed(&[0u8; 4]);
    TestProverChannel::new(prng)
}

#[allow(dead_code)]
fn gen_random_field_element(prover_channel: &mut TestProverChannel) -> Felt252 {
    prover_channel.draw_felem()
}

#[allow(dead_code)]
fn test_multiplicative_fft(log_n: u32) {
    let n = 1 << log_n;
    // let mut prng = PrngKeccak256::new();

    //let gen = F::get_root_of_unity(n as u64).unwrap();
    let mut test_prover_channel = generate_prover_channel();
    let offset = gen_random_field_element(&mut test_prover_channel);

    let domain = Radix2EvaluationDomain::<Felt252>::new(n).unwrap().get_coset(offset).unwrap();

    let coefs: Vec<Felt252> = (0..n).map(|_| gen_random_field_element(&mut test_prover_channel)).collect();
    let poly = DensePolynomial::from_coefficients_vec(coefs.clone());

    let fft_result = domain.fft(&poly.coeffs);

    let mut x = offset;
    for y in fft_result.iter() {
        let expected = poly.evaluate(&x);
        assert_eq!(*y, expected);
        x *= domain.group_gen();
    }
}

#[allow(dead_code)]
fn test_multiplicative_ifft(log_n: u32) {
    let n = 1 << log_n;
    let mut test_prover_channel = generate_prover_channel();

    let offset = gen_random_field_element(&mut test_prover_channel);
    let domain = Radix2EvaluationDomain::<Felt252>::new(n).unwrap().get_coset(offset).unwrap();

    let coefs: Vec<Felt252> = (0..n).map(|_| gen_random_field_element(&mut test_prover_channel)).collect();
    let poly = DensePolynomial::from_coefficients_vec(coefs.clone());

    let mut values = Vec::with_capacity(n);
    let mut x = offset;
    for _ in 0..n {
        values.push(poly.evaluate(&x));
        x *= domain.group_gen();
    }

    let ifft_result = domain.ifft(&values);

    for (i, coef) in coefs.iter().enumerate() {
        assert_eq!(*coef, ifft_result[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use felt::Felt252;
    use ark_poly::{Polynomial, univariate::DensePolynomial};
    use hex_literal::hex;

    #[test]
    fn fft_test() {
        test_multiplicative_fft(0);
        test_multiplicative_fft(3);
    }

    #[test]
    fn ifft_test() {
        test_multiplicative_ifft(0);
        test_multiplicative_ifft(3);
    }

    #[test]
    fn lde_test() {
        // let expected_coeffs: [Felt252; 1] = [
        //     Felt252::hex("0x4d614c2f287c37b89f44b229923e664da7feee9c035e426adb179326b7c6139")
        // ];

        let expected_domain_elems: [Felt252; 16] = [
            Felt252::from_be_bytes_mod_order(&hex!("01f75714e70bf7a81a472085588006caf99aa605bb0be098f25af56f9cb988dd")),
            Felt252::from_be_bytes_mod_order(&hex!("05bf3a6820dc8ea11bbd784024f90e2903933455a3c64b82b8bdb49ba97d7ae4")),
            Felt252::from_be_bytes_mod_order(&hex!("075e6195914787950180d93f1152d2805bbc6eb3f415add5e6d5adcda003e9de")),
            Felt252::from_be_bytes_mod_order(&hex!("07594a8a0e8279589de6b2c3183926241e86a8fcc7e7e8912febcc909ceb50f6")),
            Felt252::from_be_bytes_mod_order(&hex!("018d67f920a2c75af1ca7d803867edbc2bf929aa60cd9f5622abe5de02664071")),
            Felt252::from_be_bytes_mod_order(&hex!("05a070798821f88fd74cc7ead0b7aa0f798a2ce4961bdb6f782d6089b98909a1")),
            Felt252::from_be_bytes_mod_order(&hex!("03d974ffc14ca21ecf3c7dcf44df1f7dc05ef3ee6d2948ff9d68b06c7d2c02b4")),
            Felt252::from_be_bytes_mod_order(&hex!("02f48ca7addd3702f5ff7b237a91b9ace3f9c78b8d6d9476e03edd2d2225dfb0")),
            Felt252::from_be_bytes_mod_order(&hex!("0608a8eb18f40868e5b8df7aa77ff935066559fa44f41f670da50a9063467724")),
            Felt252::from_be_bytes_mod_order(&hex!("0240c597df23716fe44287bfdb06f1d6fc6ccbaa5c39b47d47424b645682851d")),
            Felt252::from_be_bytes_mod_order(&hex!("a19e6a6eb8787bfe7f26c0eead2d7fa443914c0bea522a192a52325ffc1623")),
            Felt252::from_be_bytes_mod_order(&hex!("a6b575f17d86b862194d3ce7c6d9dbe17957033818176ed014336f6314af0b")),
            Felt252::from_be_bytes_mod_order(&hex!("06729806df5d38b60e35827fc7981243d406d6559f3260a9dd541a21fd99bf90")),
            Felt252::from_be_bytes_mod_order(&hex!("025f8f8677de078128b338152f4855f08675d31b69e4249087d29f764676f660")),
            Felt252::from_be_bytes_mod_order(&hex!("04268b003eb35df230c38230bb20e0823fa10c1192d6b70062974f9382d3fd4d")),
            Felt252::from_be_bytes_mod_order(&hex!("050b73585222c90e0a0084dc856e46531c06387472926b891fc122d2ddda2051")),
        ];

        let expected_coefs: [Felt252; 2] = [
            Felt252::from_be_bytes_mod_order(&hex!("060b22b317393ca6509829cf22b8379cd9607c232836ff64ac34f89d0cc6b679")),
            Felt252::from_be_bytes_mod_order(&hex!("06225ab6b4b37edbb3bb2d694ff09fda59ae3daeafb23c93db11ddfb7511a59b")),
        ];


        let expected_felems: [Felt252; 16] = [
            Felt252::from_be_bytes_mod_order(&hex!("06fb946993da7cb4a4e2a11918a01b4063026b6b940235f3c34788da9562fe75")),
            Felt252::from_be_bytes_mod_order(&hex!("018ca1a0fbb086d4e78ebcf8861c578d18b498a708867899380672089f3afb00")),
            Felt252::from_be_bytes_mod_order(&hex!("04af40f15615d02358a2ef9a0d567340221985c529581ae52999f28b772ab8b6")),
            Felt252::from_be_bytes_mod_order(&hex!("060814ac00f633c4678602cff32e1e8915c676d6184a36f0fed3499028b23b2d")),
            Felt252::from_be_bytes_mod_order(&hex!("063bb123f77479a62489ca9d51a4305ea33240d3d66e43d47f81044069d69244")),
            Felt252::from_be_bytes_mod_order(&hex!("02a553d9700314998e57ab58acec0dc18cccd9f2861297663cdfded476a8cff9")),
            Felt252::from_be_bytes_mod_order(&hex!("07e85c3e84a3ab7887aab698563ba75c6ffb27252bfdcc483e3fb7a232b6c536")),
            Felt252::from_be_bytes_mod_order(&hex!("04bd46f73bf8d3ea83f6c4241aabc8c16d0e577a59ae784f6242f5635e08c9")),
            Felt252::from_be_bytes_mod_order(&hex!("06bc6e1bbde2998fe9e46a3a0b12ce577dc64423f9a23b50b8ede321ec0f3110")),
            Felt252::from_be_bytes_mod_order(&hex!("03903fd0f6931fbf944298b6eacbcb91d5d0096f17714649bb18b2fea44c0061")),
            Felt252::from_be_bytes_mod_order(&hex!("055176282013f2cf0d60384b6b87d6b733c1c5ba1cdba8336947f976526425a1")),
            Felt252::from_be_bytes_mod_order(&hex!("0a5107531a6e0f8fe27da3e261c27fbf92fc56c548005534ef6f7846a5f0a9")),
            Felt252::from_be_bytes_mod_order(&hex!("02eeb6e3b4b5cd4de894ca82b6d39fa9b95e7ea2d255fb4a7d0c3a50494a3677")),
            Felt252::from_be_bytes_mod_order(&hex!("04f6e0bb897706bbcf9f768cc7bc13da78e07ada8ece5c98b0ed9333d642c0c9")),
            Felt252::from_be_bytes_mod_order(&hex!("0104583fe4678cdd5762be0bd7f1c5b06ddf766728a27febf4d780644d928530")),
            Felt252::from_be_bytes_mod_order(&hex!("04121c0b5f6d150e6cd771287912379c99fff1b9256e9dfa2082282dead785cd")),
        ];    

        let log_n = 4;
        let n = 1 << log_n;
        let mut test_prover_channel = generate_prover_channel();

        let offset = gen_random_field_element(&mut test_prover_channel);
        // print offset
        println!("{:?}", offset);
        // print expected offset
        println!("252,0 {:?}", Felt252::from_be_bytes_mod_order(&hex!("01f75714e70bf7a81a472085588006caf99aa605bb0be098f25af56f9cb988dd")));

        let domain = Radix2EvaluationDomain::<Felt252>::new(n).unwrap().get_coset(offset).unwrap();
        // iterate over expected_srcs by its size and check if they are aligned with domain.elements() because domain.elements() is infinite
        for (i, x) in expected_domain_elems.iter().enumerate() {
            assert_eq!(domain.elements().nth(i).unwrap(), *x);
        }
        
        let mut coeffs: Vec<Felt252> = (0..n).map(|_| gen_random_field_element(&mut test_prover_channel)).collect();
        // reverse coeffs
        //coeffs.reverse();

        // print last coeffs 
        println!("last coeffs   {:?}", coeffs[n-1]);
        println!("expected last {:?}", Felt252::from_be_bytes_mod_order(&hex!("01c62d08b2c6b10d897739d9b217b48de0843d3225b50871bf9b12b9200fb86e")));


        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        let src: Vec<Felt252> = domain.elements().map(|x| poly.evaluate(&x)).collect();
        
        // print first domain element
        println!("first domain element {:?}", domain.elements().nth(0).unwrap());
        // print expected first domain element
        println!("expected first domain element {:?}", expected_domain_elems[0]);

        // print first src element
        println!("first src element {:?}", src[0]);
        // print expected first src element
        println!("expected first src element {:?}", expected_felems[0]);

        let mut i: usize = 0;
        for x in src.iter().take(1) {
            println!("{:?}", x);
            println!("{:?}", expected_felems[i]);
            println!("");
            i += 1;
        }

        let dst_offset = gen_random_field_element(&mut test_prover_channel);
        let dst_domain = domain.get_coset(dst_offset).unwrap();

        let lde_result = domain.fft(&src);
        //let lde_result = dst_domain.ifft(&fft_result);

        for (x, &result) in dst_domain.elements().zip(lde_result.iter()) {
            let expected = poly.evaluate(&x);
            assert_eq!(expected, result, "LDE result mismatch at x = {:?}", x);
        }
    }
}
