use crate::air::Air;
use crate::multiplicative_neighbors::MultiplicativeNeighbors;
use crate::periodic_columns::PeriodicColumn;
use ark_ff::PrimeField;

pub struct CompositionPolynomial<F: PrimeField> {
    air: Box<dyn Air<F>>,
    trace_generator: F,
    coset_size: usize,
    periodic_columns: Vec<PeriodicColumn<F>>,
    coefficients: Vec<F>,
    point_exponents: Vec<usize>,
    shifts: Vec<F>,
}

impl<F: PrimeField> CompositionPolynomial<F> {
    pub fn new(
        air: Box<dyn Air<F>>,
        trace_generator: F,
        coset_size: usize,
        periodic_columns: Vec<PeriodicColumn<F>>,
        coefficients: &[F],
        point_exponents: &[usize],
        shifts: &[F],
    ) -> Self {
        assert_eq!(
            coefficients.len(),
            air.num_random_coefficients(),
            "Wrong number of coefficients."
        );

        assert!(
            coset_size.is_power_of_two(),
            "Only cosets of size which is a power of two are supported."
        );

        assert_eq!(
            trace_generator.pow([coset_size as u64]),
            F::ONE,
            "Provided generator does not generate a group of expected size."
        );

        Self {
            air,
            trace_generator,
            coset_size,
            periodic_columns,
            coefficients: coefficients.to_vec(),
            point_exponents: point_exponents.to_vec(),
            shifts: shifts.to_vec(),
        }
    }

    pub fn eval_at_point(&self, point: &F, neighbors: &[F]) -> F {
        let mut periodic_column_vals = Vec::with_capacity(self.periodic_columns.len());
        for column in &self.periodic_columns {
            periodic_column_vals.push(column.eval_at_point(*point));
        }

        let point_powers = batch_pow(point, &self.point_exponents);

        let domain_evals = self.air.domain_evals_at_point(&point_powers, &self.shifts);

        self.air.constraints_eval(
            neighbors,
            &periodic_column_vals,
            &self.coefficients,
            point,
            &self.shifts,
            &domain_evals,
        )
    }

    pub fn eval_on_coset_bit_reversed_output(
        &self,
        coset_offset: F,
        trace_lde: Vec<Vec<F>>,
    ) -> Vec<F> {
        let multiplicative_neighbors =
            MultiplicativeNeighbors::new(self.air.get_mask(), &trace_lde);
        assert_eq!(multiplicative_neighbors.coset_size(), self.coset_size);

        assert!(self.coset_size.is_power_of_two());
        let log_coset_size = self.coset_size.ilog2() as usize;

        let mut point = coset_offset;

        let all_precomp_domain_evals = self.air.precompute_domain_evals_on_coset(
            &coset_offset,
            &self.trace_generator,
            &self.point_exponents,
            &self.shifts,
        );
        let precomp_domain_masks: Vec<usize> = all_precomp_domain_evals
            .iter()
            .map(|vec| vec.len() - 1)
            .collect();

        let periodic_column_cosets: Vec<_> = self
            .periodic_columns
            .iter()
            .map(|column| column.get_coset(&coset_offset, self.coset_size))
            .collect();

        let mut out_evaluation = vec![F::zero(); self.coset_size];
        let mut periodic_column_vals = vec![F::ZERO; self.periodic_columns.len()];
        let mut precomp_domain_evals = vec![F::ZERO; all_precomp_domain_evals.len()];
        let mut batch_inverse = vec![F::ZERO; self.coset_size];

        for point_idx in 0..self.coset_size {
            for (i, column_coset) in periodic_column_cosets.iter().enumerate() {
                periodic_column_vals[i] = column_coset.get_value(point_idx);
            }

            for (i, eval) in all_precomp_domain_evals.iter().enumerate() {
                precomp_domain_evals[i] = if !eval.is_empty() {
                    eval[point_idx & precomp_domain_masks[i]]
                } else {
                    F::zero()
                };
            }

            let neighbors = multiplicative_neighbors.get_neighbors(point_idx);

            batch_inverse[point_idx] = self.air.constraints_eval(
                &neighbors,
                &periodic_column_vals,
                &self.coefficients,
                &point,
                &self.shifts,
                &precomp_domain_evals,
            );

            point *= self.trace_generator;
        }

        for point_idx in 0..self.coset_size {
            out_evaluation[bit_reverse(point_idx, log_coset_size)] = batch_inverse[point_idx];
        }

        out_evaluation
    }
}

pub fn batch_pow<F: PrimeField>(base: &F, exponents: &[usize]) -> Vec<F> {
    let mut output = Vec::with_capacity(exponents.len() + 1);
    output.push(*base);

    for e in exponents {
        output.push(base.pow([*e as u64]));
    }
    output
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

#[cfg(test)]
mod tests {
    use crate::{
        air::{Air, DummyAir},
        composition_polynomial::bit_reverse,
        periodic_columns::PeriodicColumn,
    };
    use ark_ff::{Field, PrimeField, UniformRand};
    use felt::Felt252;
    use rand::Rng;
    use std::sync::Arc;

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

    #[test]
    fn test_zero_constraints() {
        let mut rng = rand::thread_rng();
        let mut air: DummyAir<Felt252> = DummyAir::new(4);
        air.composition_polynomial_degree_bound = Some(1000);
        air.n_constraints = 0;
        let poly = air.create_composition_polynomial(&Felt252::ONE, &vec![]);
        let evaluation_point = Felt252::rand(&mut rng);

        assert_eq!(
            Felt252::ZERO,
            poly.eval_at_point(&evaluation_point, &vec![])
        )
    }

    fn get_random_periodic_col(log_coset_size: usize) -> PeriodicColumn<Felt252> {
        let mut rng = rand::thread_rng();
        let log_n_values = rng.gen_range(0..=log_coset_size);
        let group_generator = get_subgroup_generator(1 << log_coset_size);
        let offset = Felt252::rand(&mut rng);

        let values = (0..(1 << log_n_values))
            .map(|_| Felt252::rand(&mut rng))
            .collect();
        PeriodicColumn::new(values, group_generator, offset, 1 << log_coset_size, 1)
    }

    fn test_eval_composition_on_coset_with(log_coset_size: usize) {
        let mut rng = rand::thread_rng();

        let n_columns = rng.gen_range(1..=20);
        let trace_length = 1 << log_coset_size;

        let mut air: DummyAir<Felt252> = DummyAir::new(trace_length);

        air.n_constraints = 1;
        air.periodic_columns
            .push(get_random_periodic_col(log_coset_size));
        air.n_columns = n_columns;
        air.mask = vec![(0, 0), (1, 0)];

        air.composition_polynomial_degree_bound = Some(2 * trace_length);

        air.point_exponents = vec![trace_length];
        air.constraints = vec![Arc::new(
            |neighbors,
             periodic_columns,
             random_coefficients,
             _point,
             _gen_power,
             precomp_evals| {
                let constraint = neighbors[0] * periodic_columns[0] - neighbors[1];

                let numerator = Felt252::ONE;

                let denominator = precomp_evals[0];

                constraint * random_coefficients[0] * numerator / denominator
            },
        )];

        let coset_group_generator: Felt252 = get_subgroup_generator(trace_length);

        let coeff: Vec<Felt252> = (0..air.num_random_coefficients())
            .map(|_| Felt252::rand(&mut rng))
            .collect();

        let poly = air.create_composition_polynomial(&coset_group_generator, &coeff);

        let coset_offset = Felt252::rand(&mut rng);

        let mut trace_lde = vec![];
        for _i in 0..n_columns {
            let rand_col: Vec<Felt252> =
                (0..trace_length).map(|_| Felt252::rand(&mut rng)).collect();
            trace_lde.push(rand_col);
        }

        let evaluation = poly.eval_on_coset_bit_reversed_output(coset_offset, trace_lde.clone());

        for i in 0..trace_length {
            let mut neighbors = Vec::with_capacity(air.mask.len());
            for mask_item in &air.mask {
                neighbors.push(trace_lde[mask_item.1][(i + mask_item.0) % trace_length]);
            }

            let curr_point = coset_offset * coset_group_generator.pow([i as u64]);

            assert_eq!(
                poly.eval_at_point(&curr_point, &neighbors),
                evaluation[bit_reverse(i, log_coset_size)]
            )
        }
    }

    #[test]
    fn test_eval_composition_on_coset() {
        let mut rng = rand::thread_rng();

        test_eval_composition_on_coset_with(rng.gen_range(4..9));
        test_eval_composition_on_coset_with(rng.gen_range(4..9));
        test_eval_composition_on_coset_with(rng.gen_range(4..9));
    }
}
