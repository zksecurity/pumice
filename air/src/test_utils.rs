use crate::trace::Trace;
use ark_ff::PrimeField;
use ark_poly::evaluations::univariate::Evaluations;
use ark_poly::{EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use composition_polynomial::air::Air;
use fri::lde::MultiplicativeLDE;
use fri::stone_domain::change_order_of_elements_in_domain;

pub fn compute_composition_degree<F: PrimeField>(
    air: Box<dyn Air<F>>,
    trace: Trace<F>,
    random_coefficients: &[F],
    num_of_cosets: usize,
) -> usize {
    assert!(trace.width() > 0 && !trace.get_column(0).is_empty());

    let coset_size = trace.get_column(0).len();

    // evaluation_domain_size = Pow2(Log2Ceil(air.GetCompositionPolynomialDegreeBound() * num_of_cosets))
    let evaluation_domain_size = 1
        << ((air.get_composition_polynomial_degree_bound() * num_of_cosets) as f32)
            .log2()
            .ceil() as usize;

    assert!(coset_size != 0);
    assert_eq!(evaluation_domain_size % coset_size, 0);
    let n_cosets = evaluation_domain_size / coset_size; // 2

    // power_of_two_cosets = Pow2(Log2Ceil(n_cosets))
    let power_of_two_cosets = 1 << (n_cosets as f32).log2().ceil() as usize;

    let coset_generator: F = get_subgroup_generator(coset_size * power_of_two_cosets);
    let trace_generator = coset_generator.pow([power_of_two_cosets as u64]);
    let cosets = get_cosets_offsets(n_cosets, coset_generator, F::GENERATOR);

    let bases: Radix2EvaluationDomain<F> = Radix2EvaluationDomain::new(coset_size).unwrap();
    let mut lde_manager = MultiplicativeLDE::new(bases, false);

    for i in 0..trace.width() {
        lde_manager.add_eval(trace.get_column(i));
    }

    let comp_poly = air.create_composition_polynomial(&trace_generator, random_coefficients);

    let mut evaluation = vec![];
    for i in 0..n_cosets {
        let coset_offset = cosets[bit_reverse(i, n_cosets.ilog2() as usize)];
        let trace_lde = lde_manager.batch_eval(coset_offset);
        evaluation.push(comp_poly.eval_on_coset_bit_reversed_output(coset_offset, trace_lde));
    }
    let evaluation: Vec<F> = evaluation.iter().flatten().cloned().collect();

    let group = Radix2EvaluationDomain::new(evaluation_domain_size).unwrap();

    let eval_rev = change_order_of_elements_in_domain(&evaluation);

    let evals = Evaluations::from_vec_and_domain(eval_rev, group);

    evals.interpolate().degree()
}

fn get_cosets_offsets<F: PrimeField>(
    n_cosets: usize,
    domain_generator: F,
    common_offset: F,
) -> Vec<F> {
    let mut result = Vec::with_capacity(n_cosets);

    let mut offset = common_offset;
    result.push(offset);

    for _ in 1..n_cosets {
        offset *= domain_generator;
        result.push(offset);
    }

    result
}

pub fn get_subgroup_generator<F: PrimeField>(n: usize) -> F {
    let q_minus_1: num_bigint::BigUint = F::ONE.neg().into();

    // Calculate (q - 1) / n
    assert!(
        q_minus_1.clone() % n == num_bigint::BigUint::from(0u64),
        "No subgroup of required size exists"
    );
    let quotient = q_minus_1 / n;

    F::GENERATOR.pow(quotient.to_u64_digits())
}

fn bit_reverse(n: usize, number_of_bits: usize) -> usize {
    let mut reversed = 0;
    let mut num = n;

    for _ in 0..number_of_bits {
        reversed = (reversed << 1) | (num & 1);
        num >>= 1;
    }

    reversed
}
