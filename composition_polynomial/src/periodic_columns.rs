use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use fri::lde::MultiplicativeLDE;

#[derive(Debug, Clone)]
pub struct PeriodicColumn<F: PrimeField> {
    group_generator: F,
    column_step: usize,
    period_in_trace: usize,
    n_copies: usize,
    offset_compensation: F,
    lde_manager: MultiplicativeLDE<F>,
}

impl<F: PrimeField> PeriodicColumn<F> {
    pub fn new(
        values: Vec<F>,
        group_generator: F,
        offset: F,
        coset_size: usize,
        column_step: usize,
    ) -> Self {
        let period_in_trace = values.len() * column_step;

        assert!(period_in_trace != 0);
        assert!(coset_size % period_in_trace == 0);
        let n_copies = coset_size / period_in_trace;

        let offset_compensation = offset.pow([n_copies as u64]).inverse().unwrap();

        let base = Radix2EvaluationDomain::new_coset(values.len(), F::ONE).unwrap();
        let mut lde_manager = MultiplicativeLDE::new(base, false);
        lde_manager.add_eval(&values);

        Self {
            group_generator,
            column_step,
            period_in_trace,
            n_copies,
            offset_compensation,
            lde_manager,
        }
    }

    pub fn eval_at_point(&self, x: F) -> F {
        let point = x.pow([self.n_copies as u64]) * self.offset_compensation;
        self.lde_manager.ldes[0].evaluate(&point)
    }

    pub fn get_actual_degree(&self) -> usize {
        self.lde_manager.ldes[0].degree()
    }

    pub fn get_coset(&self, start_point: &F, coset_size: usize) -> CosetEvaluation<F> {
        let offset = start_point.pow([self.n_copies as u64]);
        let n_values = self.lde_manager.base.size as usize;

        assert!(
            coset_size == self.n_copies * self.column_step * n_values,
            "Currently coset_size must be the same as the size of the coset that was used to create the PeriodicColumn."
        );

        let mut period_on_coset = vec![F::zero(); self.period_in_trace];

        let offset_multiplier = self.group_generator.pow([self.n_copies as u64]);
        let start_offset = offset;

        for i in 0..self.column_step {
            let offset = start_offset * offset_multiplier.pow([i as u64]);

            let lde = self
                .lde_manager
                .batch_eval(offset * self.offset_compensation);
            assert_eq!(lde.len(), 1);
            assert_eq!(lde[0].len(), n_values);

            for (j, lde_value) in lde[0].iter().enumerate() {
                period_on_coset[i + j * self.column_step] = *lde_value;
            }
        }

        CosetEvaluation::new(period_on_coset)
    }
}

pub struct CosetEvaluation<F: PrimeField> {
    index_mask: usize,
    values: Vec<F>,
}

impl<F: PrimeField> CosetEvaluation<F> {
    pub fn new(values: Vec<F>) -> Self {
        Self {
            index_mask: values.len() - 1,
            values,
        }
    }

    pub fn get_value(&self, idx: usize) -> F {
        let i = idx & self.index_mask;
        self.values[i]
    }
}

#[cfg(test)]
mod tests {
    use crate::periodic_columns::PeriodicColumn;
    use ark_ff::{PrimeField, UniformRand};
    use ark_poly::evaluations::univariate::Evaluations;
    use ark_poly::{EvaluationDomain, Polynomial, Radix2EvaluationDomain};
    use felt::Felt252;
    use rand::Rng;

    fn get_subgroup_generator<F: PrimeField>(n: usize) -> F {
        let q_minus_1: num_bigint::BigUint = F::ONE.neg().into();

        // Calculate (q - 1) / n
        assert!(
            q_minus_1.clone() % n == num_bigint::BigUint::from(0u64),
            "No subgroup of required size exists"
        );
        let quotient = q_minus_1 / n;

        F::GENERATOR.pow(quotient.to_u64_digits())
    }

    fn test_periodic_column_with(n_values: usize, coset_size: usize, column_step: usize) {
        let mut rng = rand::thread_rng();

        let group_generator: Felt252 = get_subgroup_generator(coset_size);
        let offset = Felt252::rand(&mut rng);
        let values: Vec<Felt252> = (0..n_values).map(|_| Felt252::rand(&mut rng)).collect();

        let column = PeriodicColumn::new(
            values.clone(),
            group_generator,
            offset,
            coset_size,
            column_step,
        );

        let mut point = offset;
        let mut domain = Vec::with_capacity(coset_size);
        let mut values_ext = Vec::with_capacity(coset_size);
        let periodic_column_coset = column.get_coset(&offset, coset_size);

        for i in 0..coset_size {
            let iterator_value = periodic_column_coset.get_value(i);
            let col_eval = column.eval_at_point(point);
            assert_eq!(iterator_value, col_eval);

            if i % column_step == 0 {
                let expected_val = values[(i / column_step) % n_values];
                assert_eq!(expected_val, iterator_value);
            }

            domain.push(point);
            values_ext.push(iterator_value);
            point *= group_generator;
        }

        let domain_calc = Radix2EvaluationDomain::new_coset(coset_size, offset).unwrap();
        for (e, d) in domain_calc.elements().zip(domain) {
            assert_eq!(e, d);
        }
        let evals = Evaluations::from_vec_and_domain(values_ext, domain_calc);
        let interpolant = evals.interpolate();
        let random_point = Felt252::rand(&mut rng);
        assert_eq!(
            interpolant.evaluate(&random_point),
            column.eval_at_point(random_point)
        );

        let mut point = random_point;
        let periodic_column_coset2 = column.get_coset(&random_point, coset_size);
        for i in 0..coset_size {
            let iterator_value = periodic_column_coset2.get_value(i);
            assert_eq!(interpolant.evaluate(&point), iterator_value);
            point *= group_generator;
        }
    }

    #[test]
    fn test_periodic_column() {
        test_periodic_column_with(8, 32, 1);
        test_periodic_column_with(8, 32, 2);
        test_periodic_column_with(8, 32, 4);
        test_periodic_column_with(8, 8, 1);
        test_periodic_column_with(1, 8, 1);
        test_periodic_column_with(1, 8, 8);

        // Random sizes.
        let mut rng = rand::thread_rng();
        let log_coset_size = rng.gen_range(0..=5) as usize;
        let log_n_values = rng.gen_range(0..=log_coset_size) as usize;
        let log_column_step = rng.gen_range(0..=(log_coset_size - log_n_values)) as usize;
        test_periodic_column_with(1 << log_n_values, 1 << log_coset_size, 1 << log_column_step);
    }
}
