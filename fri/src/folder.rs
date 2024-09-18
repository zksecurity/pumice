use ark_ff::FftField;

pub struct MultiplicativeFriFolder;

#[allow(dead_code)]
impl MultiplicativeFriFolder {
    pub fn next_layer_element_from_two_previous_layer_elements<F: FftField>(
        f_x: F,
        f_minus_x: F,
        eval_point: F,
        x_inv: F,
    ) -> F {
        Self::fold(f_x, f_minus_x, eval_point, x_inv)
    }

    /// Interpolating a line through (x, f(x)) and (-x, f(-x))
    /// then evaluating it at "eval_point"
    /// Multiplicative case folding formula:
    /// f(x)  = g(x^2) + xh(x^2)
    /// f(-x) = g((-x)^2) - xh((-x)^2) = g(x^2) - xh(x^2)
    /// =>
    /// 2g(x^2) = f(x) + f(-x)
    /// 2h(x^2) = (f(x) - f(-x))/x
    /// =>
    /// 2g(x^2) + 2ah(x^2) = f(x) + f(-x) + a(f(x) - f(-x))/x.
    fn fold<F: FftField>(f_x: F, f_minus_x: F, eval_point: F, x_inv: F) -> F {
        f_x + f_minus_x + eval_point * (f_x - f_minus_x) * x_inv
    }
}
