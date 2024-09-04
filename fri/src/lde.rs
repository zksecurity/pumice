use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;

#[allow(dead_code)]
pub struct MultiplicativeLDE<F: PrimeField, E: EvaluationDomain<F>> {
    pub ldes: Vec<Vec<F>>,
    pub base: E,
}

#[allow(dead_code)]
impl<F: PrimeField, E: EvaluationDomain<F>> MultiplicativeLDE<F, E> {
    pub fn new(base: E) -> Self {
        Self { ldes: vec![], base }
    }

    // Adds an evaluation on coset that was used to build the LDE.
    // Future eval invocations will add the lde of that evaluation to the results.
    pub fn add_from_coeffs(&mut self, coeffs: &[F]) {
        let new_lde = self.base.ifft(coeffs);
        self.ldes.push(new_lde);
    }

    // Evaluates the low degree extension of the evaluation that were previously added on a given coset.
    // The results are ordered according to the order that the LDEs were added.
    pub fn eval(&self, offset: F) -> Vec<Vec<F>> {
        let eval_domain = self.base.get_coset(offset).unwrap();
        let mut evals: Vec<Vec<F>> = vec![];
        for lde in self.ldes.iter() {
            let evals_lde = eval_domain.fft(lde);
            evals.push(evals_lde);
        }
        evals
    }
}

#[cfg(test)]
mod tests {
    use ark_poly::{
        domain::EvaluationDomain, univariate::DensePolynomial, DenseUVPolynomial, Polynomial,
        Radix2EvaluationDomain,
    };
    use channel::{fs_prover_channel::FSProverChannel, Channel};
    use felt::Felt252;
    use randomness::{keccak256::PrngKeccak256, Prng};
    use sha3::Sha3_256;

    use super::MultiplicativeLDE;

    type TestProverChannel = FSProverChannel<Felt252, PrngKeccak256, Sha3_256>;

    fn generate_prover_channel() -> TestProverChannel {
        let prng = PrngKeccak256::new_with_seed(&[0u8; 4]);
        TestProverChannel::new(prng)
    }

    fn gen_random_field_element(prover_channel: &mut TestProverChannel) -> Felt252 {
        prover_channel.draw_felem()
    }

    fn setup_test_environment() -> (
        Radix2EvaluationDomain<Felt252>,
        DensePolynomial<Felt252>,
        Vec<Felt252>,
        Felt252,
    ) {
        let log_n = 4;
        let n = 1 << log_n;
        let mut test_prover_channel = generate_prover_channel();

        let offset = gen_random_field_element(&mut test_prover_channel);
        let domain = Radix2EvaluationDomain::<Felt252>::new(n)
            .unwrap()
            .get_coset(offset)
            .unwrap();

        let coeffs: Vec<Felt252> = (0..n)
            .map(|_| gen_random_field_element(&mut test_prover_channel))
            .collect();

        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        let src: Vec<Felt252> = domain.elements().map(|x| poly.evaluate(&x)).collect();

        let eval_domain_offset = gen_random_field_element(&mut test_prover_channel);

        (domain, poly, src, eval_domain_offset)
    }

    #[test]
    fn lde_naked_test() {
        let (domain, poly, src, eval_domain_offset) = setup_test_environment();

        let dst_domain = domain.get_coset(eval_domain_offset).unwrap();

        let lde_coeffs = domain.ifft(&src);
        let lde_result = dst_domain.fft(&lde_coeffs);

        for (x, &result) in dst_domain.elements().zip(lde_result.iter()) {
            let expected = poly.evaluate(&x);
            assert_eq!(expected, result, "LDE result mismatch at x = {:?}", x);
        }
    }

    #[test]
    fn multiplicative_lde_test() {
        let (domain, poly, src, eval_domain_offset) = setup_test_environment();
        let mut lde = MultiplicativeLDE::new(domain);

        lde.add_from_coeffs(&src);
        let evals = lde.eval(eval_domain_offset);
        let eval_domain = domain.get_coset(eval_domain_offset).unwrap();

        for (x, &result) in eval_domain.elements().zip(evals[0].iter()) {
            let expected = poly.evaluate(&x);
            assert_eq!(expected, result, "LDE result mismatch at x = {:?}", x);
        }
    }
}
