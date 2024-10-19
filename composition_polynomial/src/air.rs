use crate::composition_polynomial::{batch_pow, CompositionPolynomial};
use crate::periodic_columns::PeriodicColumn;
use ark_ff::PrimeField;
use std::collections::HashMap;
use std::sync::Arc;

pub trait Air<F: PrimeField> {
    fn create_composition_polynomial(
        &self,
        trace_generator: &F,
        random_coefficients: &[F],
    ) -> CompositionPolynomial<F>;

    fn trace_length(&self) -> usize;

    fn get_composition_polynomial_degree_bound(&self) -> usize;

    fn num_random_coefficients(&self) -> usize;

    fn get_num_constraints(&self) -> usize {
        self.num_random_coefficients()
    }

    fn constraints_eval(
        &self,
        neighbors: &[F],
        periodic_columns: &[F],
        random_coefficients: &[F],
        point: &F,
        gen_powers: &[F],
        precomp_domains: &[F],
    ) -> F;

    fn get_mask(&self) -> &[(usize, usize)];

    fn num_columns(&self) -> usize;

    fn domain_evals_at_point(&self, point_powers: &[F], shifts: &[F]) -> Vec<F>;

    fn parse_dynamic_params(&self, params: &HashMap<String, usize>) -> Vec<usize>;

    fn with_interaction_elements(&self, _interaction_elms: &[F]) -> Box<dyn Air<F>> {
        panic!("Calling with_interaction_elements in an air with no interaction.");
    }

    fn get_interaction_params(&self) -> Option<InteractionParams>;

    fn get_n_columns_first(&self) -> usize {
        match self.get_interaction_params() {
            Some(params) => params.n_columns_first,
            None => self.num_columns(),
        }
    }

    fn precompute_domain_evals_on_coset(
        &self,
        point: &F,
        generator: &F,
        point_exponents: &[usize],
        shifts: &[F],
    ) -> Vec<Vec<F>>;
}

pub struct InteractionParams {
    pub n_columns_first: usize,
    pub n_columns_second: usize,
    pub n_interaction_elements: usize,
}

type ConstraintFunction<F> = Arc<dyn Fn(&[F], &[F], &[F], &F, &[F], &[F]) -> F>;

// DummyAir struct definition
#[derive(Clone)]
pub struct DummyAir<F: PrimeField> {
    pub trace_length: usize,
    pub n_constraints: usize,
    pub n_columns: usize,
    pub mask: Vec<(usize, usize)>,
    pub periodic_columns: Vec<PeriodicColumn<F>>,
    pub point_exponents: Vec<usize>,
    pub gen_exponents: Vec<usize>,
    pub constraints: Vec<ConstraintFunction<F>>,
    pub composition_polynomial_degree_bound: Option<usize>,
}

impl<F: PrimeField> DummyAir<F> {
    pub fn new(trace_length: usize) -> Self {
        assert!(trace_length.is_power_of_two());
        Self {
            trace_length,
            n_constraints: 0,
            n_columns: 0,
            mask: vec![],
            periodic_columns: vec![],
            point_exponents: vec![],
            gen_exponents: vec![],
            constraints: vec![],
            composition_polynomial_degree_bound: None,
        }
    }
}

impl<F: PrimeField> Air<F> for DummyAir<F> {
    fn trace_length(&self) -> usize {
        self.trace_length
    }

    fn get_composition_polynomial_degree_bound(&self) -> usize {
        assert!(
            self.composition_polynomial_degree_bound.is_some(),
            "composition_polynomial_degree_bound wasn't initialized."
        );
        self.composition_polynomial_degree_bound.unwrap()
    }

    fn num_random_coefficients(&self) -> usize {
        self.n_constraints
    }

    fn num_columns(&self) -> usize {
        self.n_columns
    }

    fn get_interaction_params(&self) -> Option<InteractionParams> {
        None
    }

    fn constraints_eval(
        &self,
        neighbors: &[F],
        periodic_columns: &[F],
        random_coefficients: &[F],
        point: &F,
        gen_powers: &[F],
        precomp_domains: &[F],
    ) -> F {
        assert!(
            random_coefficients.len() == self.constraints.len(),
            "This is a bug in the test."
        );

        let mut res = F::ZERO;
        for constraint in self.constraints.iter() {
            res += constraint(
                neighbors,
                periodic_columns,
                random_coefficients,
                point,
                gen_powers,
                precomp_domains,
            );
        }
        res
    }

    fn domain_evals_at_point(&self, point_powers: &[F], _shifts: &[F]) -> Vec<F> {
        if point_powers.len() <= 1 {
            return vec![];
        }
        vec![point_powers[1] - F::ONE]
    }

    fn create_composition_polynomial(
        &self,
        trace_generator: &F,
        random_coefficients: &[F],
    ) -> CompositionPolynomial<F> {
        let shifts = batch_pow(trace_generator, &self.gen_exponents);
        CompositionPolynomial::new(
            Box::new(self.clone()),
            *trace_generator,
            self.trace_length(),
            self.periodic_columns.clone(),
            random_coefficients,
            &self.point_exponents,
            &shifts,
        )
    }

    fn get_mask(&self) -> &[(usize, usize)] {
        &self.mask
    }

    fn parse_dynamic_params(
        &self,
        _params: &std::collections::HashMap<String, usize>,
    ) -> Vec<usize> {
        vec![]
    }

    fn precompute_domain_evals_on_coset(
        &self,
        point: &F,
        generator: &F,
        point_exponents: &[usize],
        _shifts: &[F],
    ) -> Vec<Vec<F>> {
        assert!(point_exponents[0] != 0);
        assert!(self.trace_length % point_exponents[0] == 0);
        let size = self.trace_length / point_exponents[0];

        let mut point_powers = Vec::with_capacity(size);
        let mut power = point.pow([point_exponents[0] as u64]);
        let gen_power = generator.pow([point_exponents[0] as u64]);

        point_powers.push(power);
        for _ in 1..size {
            power *= gen_power;
            point_powers.push(power);
        }

        let mut precomp_domains = vec![Vec::with_capacity(size)];
        for p in point_powers.iter() {
            precomp_domains[0].push(*p - F::ONE);
        }
        precomp_domains
    }
}
