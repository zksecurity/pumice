use ark_ff::FftField;
use std::sync::Arc;

pub struct MultiplicativeFriFolder;

#[allow(dead_code)]
impl MultiplicativeFriFolder {
    pub fn next_layer_element_from_two_previous_layer_elements<F: FftField>(
        f_x: &F,
        f_minus_x: &F,
        eval_point: &F,
        x: &F,
    ) -> F {
        let x_inv = x.inverse().unwrap();
        Self::fold(f_x, f_minus_x, eval_point, &x_inv)
    }

    fn fold<F: FftField>(f_x: &F, f_minus_x: &F, eval_point: &F, x_inv: &F) -> F {
        *f_x + *f_minus_x + *eval_point * (*f_x - *f_minus_x) * *x_inv
    }
}

#[allow(dead_code)]
pub fn fri_folder_from_field() -> Arc<MultiplicativeFriFolder> {
    Arc::new(MultiplicativeFriFolder)
}
