use crate::FftDomainBase;
use ark_ff::FftField;
use ark_ff::Field;
use ark_poly::domain::EvaluationDomain;
use std::sync::Arc;

pub struct MultiplicativeFriFolder;

impl MultiplicativeFriFolder {
    pub fn next_layer_element_from_two_previous_layer_elements<F: FftField>(
        f_x: &F,
        f_minus_x: &F,
        eval_point: &F,
        x_inv: &F,
    ) -> F {
        Self::fold(f_x, f_minus_x, eval_point, x_inv)
    }

    fn fold<F: Field>(f_x: &F, f_minus_x: &F, eval_point: &F, x_inv: &F) -> F {
        *f_x + *f_minus_x + *eval_point * (*f_x - *f_minus_x) * *x_inv
    }
}

pub fn fri_folder_from_field<F: Field>() -> Arc<MultiplicativeFriFolder> {
    Arc::new(MultiplicativeFriFolder)
}
