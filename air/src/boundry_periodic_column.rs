use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use composition_polynomial::periodic_columns::PeriodicColumn;
use std::collections::BTreeSet;

fn row_indices_to_field_elements<F: PrimeField>(
    rows: &[usize],
    trace_generator: &F,
    trace_offset: &F,
) -> Vec<F> {
    let mut result = Vec::with_capacity(rows.len());
    for &row_index in rows {
        let powered_generator = trace_generator.pow([row_index as u64]);
        result.push(*trace_offset * powered_generator);
    }
    result
}

fn create_boundary_periodic_column<F: PrimeField>(
    rows: &[usize],
    values: &[F],
    trace_length: usize,
    trace_generator: &F,
    trace_offset: &F,
) -> PeriodicColumn<F> {
    assert!(
        rows.len() == values.len(),
        "Number of rows does not match number of values"
    );
    let n_values = rows.len();

    let x_values = row_indices_to_field_elements(rows, trace_generator, trace_offset);

    let log_column_height = if n_values == 0 {
        1
    } else {
        // ceil(Log_2(n_values)
        (n_values as f32).log2().ceil() as usize
    };
    let column_height = 1 << log_column_height;

    assert!(column_height != 0 && trace_length % column_height == 0);

    let mut reverse_cumulative_product = vec![F::ZERO; n_values];
    let mut periodic_column_values = Vec::with_capacity(column_height);

    let domain: Radix2EvaluationDomain<F> = Radix2EvaluationDomain::new(column_height).unwrap();

    for cur_x in domain.elements() {
        let mut prod = F::ONE;
        for i in 0..n_values {
            let reverse_i = n_values - 1 - i;
            reverse_cumulative_product[reverse_i] = prod;
            prod *= cur_x - x_values[reverse_i];
        }

        prod = F::ONE;
        let mut res = F::from(0u64);

        for i in 0..x_values.len() {
            res += values[i] * prod * reverse_cumulative_product[i];
            prod *= cur_x - x_values[i];
        }
        periodic_column_values.push(res);
    }

    assert!(column_height != 0);
    assert!(trace_length % column_height == 0);
    let col_step = trace_length / column_height;
    PeriodicColumn::new(
        periodic_column_values,
        *trace_generator,
        F::ONE,
        trace_length,
        col_step,
    )
}

pub fn create_base_boundary_periodic_column<F: PrimeField>(
    rows: &[usize],
    trace_length: usize,
    trace_generator: &F,
    trace_offset: &F,
) -> PeriodicColumn<F> {
    let values = vec![F::ONE; rows.len()];
    create_boundary_periodic_column(rows, &values, trace_length, trace_generator, trace_offset)
}

fn create_vanishing_periodic_column<F: PrimeField>(
    rows: &[usize],
    trace_length: usize,
    trace_generator: &F,
    trace_offset: &F,
) -> PeriodicColumn<F> {
    let x_values = row_indices_to_field_elements(rows, trace_generator, trace_offset);

    // ceil(Log_2(x_values.len() + 1)
    let log_column_height = ((x_values.len() + 1) as f32).log2().ceil() as usize;

    let column_height = 1 << log_column_height;

    let mut periodic_column_values = Vec::with_capacity(column_height);
    let domain: Radix2EvaluationDomain<F> = Radix2EvaluationDomain::new(column_height).unwrap();

    for cur_x in domain.elements() {
        let mut res = F::ONE;
        for x_value in &x_values {
            res *= cur_x - x_value;
        }
        periodic_column_values.push(res);
    }

    assert!(column_height != 0);
    assert!(trace_length % column_height == 0);
    let col_step = trace_length / column_height;
    PeriodicColumn::new(
        periodic_column_values,
        *trace_generator,
        F::ONE,
        trace_length,
        col_step,
    )
}

pub fn create_complement_vanishing_periodic_column<F: PrimeField>(
    rows: &[usize],
    step: usize,
    trace_length: usize,
    trace_generator: &F,
    trace_offset: &F,
) -> PeriodicColumn<F> {
    assert!(step != 0);
    assert!(trace_length % step == 0);
    let coset_size = trace_length / step;

    let rows_set: BTreeSet<usize> = rows.iter().cloned().collect();
    assert_eq!(rows_set.len(), rows.len(), "Rows must be distinct");

    let mut other_rows = Vec::with_capacity(coset_size - rows.len());
    for i in (0..trace_length).step_by(step) {
        if !rows_set.contains(&i) {
            other_rows.push(i);
        }
    }
    assert_eq!(
        other_rows.len() + rows.len(),
        coset_size,
        "All rows must be in the coset."
    );

    create_vanishing_periodic_column(&other_rows, trace_length, trace_generator, trace_offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_subgroup_generator;
    use ark_ff::Field;
    use ark_ff::UniformRand;
    use felt::Felt252;
    use rand::prelude::SliceRandom;
    use rand::Rng;

    fn sample_uniform_distinct_vector(min: usize, max: usize, n_values: usize) -> Vec<usize> {
        let mut rng = rand::thread_rng();

        let mut range: Vec<usize> = (min..max).collect();

        range.shuffle(&mut rng);

        range.into_iter().take(n_values).collect()
    }

    #[test]
    fn test_create_boundary_periodic_column() {
        let mut rng = rand::thread_rng();

        let n_values = 37;
        let trace_length = 1024;
        let trace_generator = get_subgroup_generator(trace_length);
        let trace_offset = Felt252::rand(&mut rng);

        let rows: Vec<usize> = (0..n_values)
            .map(|_| rng.gen_range(0..trace_length))
            .collect();

        let values: Vec<Felt252> = (0..n_values).map(|_| Felt252::rand(&mut rng)).collect();

        let periodic_column = create_boundary_periodic_column(
            &rows,
            &values,
            trace_length,
            &trace_generator,
            &trace_offset,
        );
        let periodic_column_base = create_base_boundary_periodic_column(
            &rows,
            trace_length,
            &trace_generator,
            &trace_offset,
        );

        assert_eq!(periodic_column.get_actual_degree(), n_values - 1,);
        assert_eq!(periodic_column_base.get_actual_degree(), n_values - 1,);

        for (i, &row) in rows.iter().enumerate() {
            let x_value = trace_offset.clone() * trace_generator.pow([row as u64]);
            let value = periodic_column.eval_at_point(x_value);
            let value_base = periodic_column_base.eval_at_point(x_value);
            assert_eq!(value, values[i] * value_base);
        }

        // Make sure the following line doesn't throw an assertion error.
        periodic_column.get_coset(&Felt252::ONE, trace_length);
    }

    #[test]
    fn test_create_boundary_periodic_column_empty() {
        let mut rng = rand::thread_rng();
        let trace_length = 1024;
        let trace_generator = get_subgroup_generator(trace_length);
        let trace_offset = Felt252::rand(&mut rng);

        let periodic_column = create_boundary_periodic_column(
            &[],
            &[],
            trace_length,
            &trace_generator,
            &trace_offset,
        );
        let periodic_column_base = create_base_boundary_periodic_column(
            &[],
            trace_length,
            &trace_generator,
            &trace_offset,
        );

        assert_eq!(periodic_column.get_actual_degree(), 0);
        assert_eq!(periodic_column_base.get_actual_degree(), 0);

        let random_point = Felt252::rand(&mut rng);
        assert_eq!(periodic_column.eval_at_point(random_point), Felt252::ZERO);
        assert_eq!(
            periodic_column_base.eval_at_point(random_point),
            Felt252::ZERO
        );
    }

    #[test]
    fn test_create_vanishing_periodic_column() {
        let mut rng = rand::thread_rng();

        let trace_length = 1024;
        let step = 4;
        let coset_size = trace_length / step;
        let trace_generator = get_subgroup_generator(trace_length);
        let trace_offset = Felt252::rand(&mut rng);

        for &n_values in &[0, 31, 32, 33, coset_size] {
            let mut rows: Vec<usize>;
            if n_values < coset_size {
                rows = sample_uniform_distinct_vector(0, coset_size, n_values)
            } else {
                assert_eq!(n_values, coset_size);
                rows = (0..coset_size).collect();
            }

            for row in &mut rows {
                *row *= step;
            }

            let rows_set: BTreeSet<usize> = rows.iter().copied().collect();

            let periodic_column = create_vanishing_periodic_column(
                &rows,
                trace_length,
                &trace_generator,
                &trace_offset,
            );
            let periodic_column_comp = create_complement_vanishing_periodic_column(
                &rows,
                step,
                trace_length,
                &trace_generator,
                &trace_offset,
            );

            assert_eq!(periodic_column.get_actual_degree(), n_values);
            assert_eq!(
                periodic_column_comp.get_actual_degree(),
                (coset_size - n_values)
            );

            for i in (0..trace_length).step_by(step as usize) {
                let x_value = trace_offset.clone() * trace_generator.pow([i as u64]);
                let value = periodic_column.eval_at_point(x_value);
                let value_comp = periodic_column_comp.eval_at_point(x_value);

                if rows_set.contains(&i) {
                    assert_eq!(value, Felt252::ZERO);
                    assert_ne!(value_comp, Felt252::ZERO);
                } else {
                    assert_ne!(value, Felt252::ZERO);
                    assert_eq!(value_comp, Felt252::ZERO);
                }
            }

            // Make sure the following line doesn't throw an assertion error.
            periodic_column.get_coset(&Felt252::ONE, trace_length);
            periodic_column_comp.get_coset(&Felt252::ONE, trace_length);
        }
    }
}
