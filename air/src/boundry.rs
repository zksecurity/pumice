use ark_ff::PrimeField;
use composition_polynomial::{air::Air, composition_polynomial::CompositionPolynomial};

#[derive(Clone)]
pub struct BoundaryAir<F: PrimeField> {
    trace_length: usize,
    n_columns: usize,
    constraints: Vec<ConstraintData<F>>,
    mask: Vec<(usize, usize)>,
}

#[derive(Clone)]
pub struct ConstraintData<F> {
    coeff_idx: usize,
    column_index: usize,
    point_x: F,
    point_y: F,
}

impl<F: PrimeField> BoundaryAir<F> {
    pub fn new(
        trace_length: usize,
        n_columns: usize,
        boundary_conditions: &[(usize, F, F)],
    ) -> Self {
        let mut constraints = Vec::with_capacity(boundary_conditions.len());

        for (coeff_idx, &(column_index, ref point_x, ref point_y)) in
            boundary_conditions.iter().enumerate()
        {
            let x = *point_x;

            let pos = constraints
                .iter()
                .position(|constraint: &ConstraintData<F>| constraint.point_x == x);

            let constraint_data = ConstraintData {
                coeff_idx,
                column_index,
                point_x: x,
                point_y: *point_y,
            };

            if let Some(pos) = pos {
                constraints.insert(pos, constraint_data);
            } else {
                constraints.push(constraint_data);
            }
        }

        let mut mask = Vec::with_capacity(n_columns);
        for i in 0..n_columns {
            mask.push((0, i));
        }

        BoundaryAir {
            trace_length,
            n_columns,
            constraints,
            mask,
        }
    }
}

impl<F: PrimeField> Air<F> for BoundaryAir<F> {
    fn trace_length(&self) -> usize {
        self.trace_length
    }

    fn num_columns(&self) -> usize {
        self.n_columns
    }

    fn num_random_coefficients(&self) -> usize {
        self.constraints.len()
    }

    fn get_mask(&self) -> &[(usize, usize)] {
        &self.mask
    }

    fn constraints_eval(
        &self,
        neighbors: &[F],
        _periodic_columns: &[F],
        random_coefficients: &[F],
        point: &F,
        _shifts: &[F],
        _precomp_domains: &[F],
    ) -> F {
        assert_eq!(neighbors.len(), self.n_columns);
        assert_eq!(random_coefficients.len(), self.constraints.len());

        let mut outer_sum = F::ZERO;
        let mut inner_sum = F::ZERO;
        let mut prev_x = self.constraints[0].point_x;

        for constraint in &self.constraints {
            let constraint_value = random_coefficients[constraint.coeff_idx]
                * (neighbors[constraint.column_index] - constraint.point_y);

            if prev_x == constraint.point_x {
                inner_sum += constraint_value;
            } else {
                outer_sum += inner_sum / (*point - prev_x);
                inner_sum = constraint_value;
                prev_x = constraint.point_x;
            }
        }

        outer_sum += inner_sum / (*point - prev_x);

        outer_sum
    }

    fn domain_evals_at_point(&self, _point_powers: &[F], _shifts: &[F]) -> Vec<F> {
        vec![]
    }

    fn precompute_domain_evals_on_coset(
        &self,
        _point: &F,
        _generator: &F,
        _point_exponents: &[usize],
        _shifts: &[F],
    ) -> Vec<Vec<F>> {
        vec![]
    }

    fn get_composition_polynomial_degree_bound(&self) -> usize {
        self.trace_length()
    }

    fn parse_dynamic_params(
        &self,
        _params: &std::collections::HashMap<String, usize>,
    ) -> Vec<usize> {
        vec![]
    }

    fn get_interaction_params(&self) -> Option<composition_polynomial::air::InteractionParams> {
        None
    }

    fn create_composition_polynomial(
        &self,
        trace_generator: &F,
        random_coefficients: &[F],
    ) -> composition_polynomial::composition_polynomial::CompositionPolynomial<F> {
        CompositionPolynomial::new(
            Box::new(self.clone()),
            *trace_generator,
            self.trace_length(),
            vec![],
            random_coefficients,
            &[],
            &[],
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::compute_composition_degree;
    use crate::trace::Trace;
    use ark_ff::UniformRand;
    use ark_poly::Polynomial;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use composition_polynomial::air::Air;
    use felt::Felt252;
    use fri::lde::MultiplicativeLDE;
    use rand::Rng;

    use super::BoundaryAir;

    #[test]
    fn test_boundry_correctness() {
        let mut rng = rand::thread_rng();
        let n_columns = 10;
        let n_conditions = 20;
        let trace_length = 1024;

        let base: Radix2EvaluationDomain<Felt252> =
            Radix2EvaluationDomain::new(trace_length).unwrap();
        let mut lde_manager = MultiplicativeLDE::new(base, false);

        let mut values = vec![];
        for _ in 0..n_columns {
            let rand_col: Vec<Felt252> =
                (0..trace_length).map(|_| Felt252::rand(&mut rng)).collect();
            lde_manager.add_eval(&rand_col);
            values.push(rand_col);
        }

        let mut boundary_conditions: Vec<(usize, Felt252, Felt252)> =
            Vec::with_capacity(n_conditions);

        for _ in 0..n_conditions {
            let col_id = rng.gen_range(0..n_columns);
            let point_x = Felt252::rand(&mut rng);
            let point_y = lde_manager.ldes[col_id].evaluate(&point_x);
            boundary_conditions.push((col_id, point_x, point_y));
        }

        let boundry_air = BoundaryAir::new(trace_length, n_columns, &boundary_conditions);

        let random_coefficients: Vec<Felt252> = (0..boundry_air.num_random_coefficients())
            .map(|_| Felt252::rand(&mut rng))
            .collect();

        let actual_degree = compute_composition_degree(
            Box::new(boundry_air.clone()),
            Trace::new(values),
            &random_coefficients,
            2,
        );
        assert_eq!(trace_length - 2, actual_degree);
        assert_eq!(
            boundry_air.get_composition_polynomial_degree_bound() - 2,
            actual_degree
        );
    }

    #[test]
    fn test_boundry_soundness() {
        let mut rng = rand::thread_rng();
        let n_columns = 10;
        let n_conditions = 20;
        let trace_length = 1024;

        let base: Radix2EvaluationDomain<Felt252> =
            Radix2EvaluationDomain::new(trace_length).unwrap();
        let mut lde_manager = MultiplicativeLDE::new(base, false);

        let mut values = vec![];
        for _ in 0..n_columns {
            let rand_col: Vec<Felt252> =
                (0..trace_length).map(|_| Felt252::rand(&mut rng)).collect();
            lde_manager.add_eval(&rand_col);
            values.push(rand_col);
        }

        let mut boundary_conditions: Vec<(usize, Felt252, Felt252)> =
            Vec::with_capacity(n_conditions);

        for _ in 0..n_conditions {
            let col_id = rng.gen_range(0..n_columns);
            let point_x = Felt252::rand(&mut rng);
            let point_y = Felt252::rand(&mut rng);
            boundary_conditions.push((col_id, point_x, point_y));
        }

        let boundry_air = BoundaryAir::new(trace_length, n_columns, &boundary_conditions);

        let random_coefficients: Vec<Felt252> = (0..boundry_air.num_random_coefficients())
            .map(|_| Felt252::rand(&mut rng))
            .collect();

        let num_of_cosets = 2;
        let actual_degree = compute_composition_degree(
            Box::new(boundry_air.clone()),
            Trace::new(values),
            &random_coefficients,
            num_of_cosets,
        );
        assert_eq!(
            num_of_cosets * boundry_air.get_composition_polynomial_degree_bound() - 1,
            actual_degree
        );
    }
}
