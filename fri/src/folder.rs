use crate::FftDomainBase;
use ark_ff::FftField;
use ark_ff::Field;
use ark_poly::domain::EvaluationDomain;
use std::sync::Arc;

pub struct MultiplicativeFriFolder;

impl MultiplicativeFriFolder {
    // pub fn compute_next_fri_layer<F: FftField>(
    //     domain: &dyn FftDomainBase,
    //     values: &[F],
    //     eval_point: &F,
    // ) -> Vec<F> {
    //     let mut output_layer = vec![F::zero(); values.len() / 2];
    //     Self::compute_next_fri_layer_in_place(domain, values, eval_point, &mut output_layer);
    //     output_layer
    // }

    // pub fn compute_next_fri_layer_in_place<F: FftField>(
    //     domain: &dyn FftDomainBase,
    //     values: &[F],
    //     eval_point: &F,
    //     output_layer: &mut [F],
    // ) {
    //     let domain_tmpl = domain;
    //     Self::compute_next_fri_layer_impl(domain_tmpl, values, eval_point, output_layer);
    // }

    pub fn next_layer_element_from_two_previous_layer_elements<F: FftField>(
        f_x: &F,
        f_minus_x: &F,
        eval_point: &F,
        x_inv: &F,
    ) -> F {
        Self::fold(f_x, f_minus_x, eval_point, x_inv)
    }

    // fn compute_next_fri_layer_impl<F: FftField, D: EvaluationDomain<F>>(
    //     domain: &D,
    //     input_layer: &[F],
    //     eval_point: &F,
    //     output_layer: &mut [F],
    // ) {
    //     assert_eq!(
    //         input_layer.len(),
    //         domain.size(),
    //         "vector size does not match domain size"
    //     );
    //     assert_eq!(
    //         output_layer.len(),
    //         input_layer.len() / 2,
    //         "Output layer size must be half than the original"
    //     );

    //     // Implementation of the parallel computation logic goes here
    //     // This is a placeholder for the actual parallel computation
    //     for (i, chunk) in input_layer.chunks(2).enumerate() {
    //         let f_x = chunk[0];
    //         let f_minus_x = chunk[1];
    //         output_layer[i] =
    //             Self::fold(&f_x, &f_minus_x, eval_point, &eval_point.inverse().unwrap());
    //     }
    // }

    fn fold<F: Field>(f_x: &F, f_minus_x: &F, eval_point: &F, x_inv: &F) -> F {
        *f_x + *f_minus_x + *eval_point * (*f_x - *f_minus_x) * *x_inv
    }
}

pub fn fri_folder_from_field<F: Field>() -> Arc<MultiplicativeFriFolder> {
    Arc::new(MultiplicativeFriFolder)
}
