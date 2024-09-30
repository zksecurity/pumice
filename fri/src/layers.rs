use crate::folder::MultiplicativeFriFolder;
use anyhow::Error;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use std::sync::Arc;

pub trait FriLayer<F: PrimeField, E: EvaluationDomain<F>> {
    fn get_layer_size(&self) -> usize;
    fn get_domain(&self) -> E;
    fn get_layer(&self) -> Result<Vec<F>, Error>;
    fn eval_at_points(&self, required_indices: &[usize]) -> Vec<F>;
}

#[derive(Clone)]
pub struct FriLayerReal<F: PrimeField, E: EvaluationDomain<F>> {
    domain: E,
    evaluation: Vec<F>,
}

#[allow(dead_code)]
impl<F: PrimeField, E: EvaluationDomain<F>> FriLayerReal<F, E> {
    pub fn new(domain: E, evaluation: Vec<F>) -> Self {
        Self { domain, evaluation }
    }

    pub fn new_from_prev_layer(prev_layer: &dyn FriLayer<F, E>) -> Self {
        Self {
            domain: prev_layer.get_domain(),
            evaluation: prev_layer.get_layer().unwrap(),
        }
    }
}

impl<F: PrimeField, E: EvaluationDomain<F> + 'static> FriLayer<F, E> for FriLayerReal<F, E> {
    fn get_layer_size(&self) -> usize {
        self.domain.size()
    }

    fn get_domain(&self) -> E {
        self.domain
    }

    fn get_layer(&self) -> Result<Vec<F>, Error> {
        Ok(self.evaluation.clone())
    }

    fn eval_at_points(&self, required_indices: &[usize]) -> Vec<F> {
        required_indices
            .iter()
            .map(|&i| self.evaluation[i])
            .collect()
    }
}

pub struct FriLayerProxy<F: PrimeField, E: EvaluationDomain<F>> {
    domain: E,
    prev_layer: Arc<dyn FriLayer<F, E>>,
    eval_point: F,
}

#[allow(dead_code)]
impl<F: PrimeField, E: EvaluationDomain<F>> FriLayerProxy<F, E> {
    pub fn new(prev_layer: Arc<dyn FriLayer<F, E>>, eval_point: F) -> Self {
        let prev_layer_domain = prev_layer.get_domain();
        let current_domain = {
            assert!(prev_layer_domain.size().is_power_of_two());
            let coset_size = prev_layer_domain.size() / 2;
            let coset_offset = prev_layer_domain.coset_offset().square();
            E::new_coset(coset_size, coset_offset).unwrap()
        };

        Self {
            domain: current_domain,
            prev_layer,
            eval_point,
        }
    }
}

impl<F: PrimeField, E: EvaluationDomain<F> + 'static> FriLayer<F, E> for FriLayerProxy<F, E> {
    fn get_layer_size(&self) -> usize {
        self.domain.size()
    }

    fn get_domain(&self) -> E {
        self.domain
    }

    fn get_layer(&self) -> Result<Vec<F>, Error> {
        let prev_layer_domain = self.prev_layer.get_domain();
        let prev_eval = self.prev_layer.get_layer()?;

        MultiplicativeFriFolder::compute_next_fri_layer(
            prev_layer_domain,
            &prev_eval,
            self.eval_point,
        )
    }

    fn eval_at_points(&self, _required_indices: &[usize]) -> Vec<F> {
        unimplemented!("Should never be called")
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::lde::MultiplicativeLDE;
    use crate::stone_domain::get_field_element_at_index;

    use ark_ff::Field;
    use ark_ff::UniformRand;
    use ark_poly::{
        domain::EvaluationDomain, univariate::DensePolynomial, DenseUVPolynomial, Polynomial,
        Radix2EvaluationDomain,
    };
    use felt::Felt252;

    fn init_test(
        eval_point: Felt252,
        coeffs: Vec<Felt252>,
        log2_eval_domain: usize,
    ) -> (
        FriLayerReal<Felt252, Radix2EvaluationDomain<Felt252>>,
        FriLayerProxy<Felt252, Radix2EvaluationDomain<Felt252>>,
    ) {
        let n = 1 << log2_eval_domain;

        let offset = Felt252::ONE;
        let domain = Radix2EvaluationDomain::new_coset(n, offset).unwrap();

        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        let evals: Vec<Felt252> = {
            let mut values = vec![];
            for i in 0..domain.size as usize {
                let x = &get_field_element_at_index(&domain, i);
                values.push(poly.evaluate(&x));
            }
            values
        };

        let layer_0 = FriLayerReal::new(domain, evals);
        let layer_1_proxy = FriLayerProxy::new(Arc::new(layer_0.clone()), eval_point);

        (layer_0, layer_1_proxy)
    }

    fn init_more(
        layer_1_proxy: &FriLayerProxy<Felt252, Radix2EvaluationDomain<Felt252>>,
        eval_point: Felt252,
    ) -> (
        FriLayerReal<Felt252, Radix2EvaluationDomain<Felt252>>,
        FriLayerProxy<Felt252, Radix2EvaluationDomain<Felt252>>,
        FriLayerReal<Felt252, Radix2EvaluationDomain<Felt252>>,
    ) {
        let layer_2 = FriLayerReal::new_from_prev_layer(layer_1_proxy);
        let layer_3_proxy = FriLayerProxy::new(Arc::new(layer_2.clone()), eval_point);
        let layer_4 = FriLayerReal::new_from_prev_layer(&layer_3_proxy);
        (layer_2, layer_3_proxy, layer_4)
    }

    #[test]
    fn test_layers() {
        let eval_point =
            felt::hex("0x5603beb2e3083fd80de72875732256ff84981639ea7afd69efab1627aa8af1f");
        let coeffs = vec![
            felt::hex("0x2306affe402b4c69c033b8fbe082d4037e7a6daf1ebd5b9dc653d845f2cf4f9"),
            felt::hex("0x75d89ba077ef16d757ca6fa2ec4d725af482ed3db12c20f33a489e97b18d8a7"),
            felt::hex("0x68fc432c07c647486b44283bf8215ccd43deb6da7dae694b9eac6ffe4c3036c"),
            felt::hex("0x5ef686e27d7630ea786125d1d8262b7539d13ce7532ad2e47ca7c0df44d5f8c"),
        ];
        let exp_evals = vec![
            felt::hex("0xce883fcba8216bbe28c5bbd516b0afc7e18dcc9ffebd900931a9afc03cdeda"),
            felt::hex("0xce883fcba8216bbe28c5bbd516b0afc7e18dcc9ffebd900931a9afc03cdeda"),
            felt::hex("0xce883fcba8216bbe28c5bbd516b0afc7e18dcc9ffebd900931a9afc03cdeda"),
            felt::hex("0xce883fcba8216bbe28c5bbd516b0afc7e18dcc9ffebd900931a9afc03cdeda"),
        ];

        let first_layer_degree_bound = coeffs.len();
        let (layer_0, layer_1_proxy) = init_test(eval_point, coeffs, 4);
        let (layer_2, layer_3_proxy, layer_4) = init_more(&layer_1_proxy, eval_point);

        // Test get_layer_size()
        assert_eq!(layer_0.get_layer_size(), 16);
        assert_eq!(layer_1_proxy.get_layer_size(), 8);
        assert_eq!(layer_2.get_layer_size(), 8);
        assert_eq!(layer_3_proxy.get_layer_size(), 4);
        assert_eq!(layer_4.get_layer_size(), 4);

        // Test first layer degree check
        let layer_0_eval = layer_0.get_layer().unwrap();
        let mut layer_0_lde_manager = MultiplicativeLDE::new(layer_0.get_domain(), true);
        layer_0_lde_manager.add_eval(&layer_0_eval);
        let lde_manager_coef = layer_0_lde_manager.coeffs(0);
        let layer_0_deg = {
            let mut deg = 0;
            for i in (0..lde_manager_coef.len()).rev() {
                if lde_manager_coef[i] != Felt252::ZERO {
                    deg = i;
                    break;
                }
            }
            deg
        };
        assert_eq!(layer_0_deg, first_layer_degree_bound - 1);

        // Test Proxy Layer
        let layer_1_eval = layer_1_proxy.get_layer().unwrap();
        let mut layer_1_lde_manager = MultiplicativeLDE::new(layer_1_proxy.get_domain(), true);
        layer_1_lde_manager.add_eval(&layer_1_eval);
        let lde_1_manager_coef = layer_1_lde_manager.coeffs(0);
        let layer_1_deg = {
            let mut deg = 0;
            for i in (0..lde_1_manager_coef.len()).rev() {
                if lde_1_manager_coef[i] != Felt252::ZERO {
                    deg = i;
                    break;
                }
            }
            deg
        };
        assert_eq!(layer_1_deg, first_layer_degree_bound / 2 - 1);
        let folded_layer = MultiplicativeFriFolder::compute_next_fri_layer(
            layer_0.get_domain(),
            &layer_0_eval,
            eval_point,
        )
        .unwrap();
        assert_eq!(folded_layer, layer_1_eval);

        // Test Real Layer
        let layer_2_eval = layer_2.get_layer().unwrap();
        let mut layer_2_lde_manager = MultiplicativeLDE::new(layer_2.get_domain(), true);
        layer_2_lde_manager.add_eval(&layer_2_eval);
        let lde_2_manager_coef = layer_2_lde_manager.coeffs(0);
        let layer_2_deg = {
            let mut deg = 0;
            for i in (0..lde_2_manager_coef.len()).rev() {
                if lde_2_manager_coef[i] != Felt252::ZERO {
                    deg = i;
                    break;
                }
            }
            deg
        };
        assert_eq!(layer_2_deg, first_layer_degree_bound / 2 - 1);
        let folded_layer = MultiplicativeFriFolder::compute_next_fri_layer(
            layer_0.get_domain(),
            &layer_0_eval,
            eval_point,
        )
        .unwrap();
        assert_eq!(folded_layer, layer_2_eval);

        // Test evaluations
        let layer_eval = layer_4.get_layer().unwrap();
        let evals = layer_4.eval_at_points(&[0, 1, 2, 3]);
        assert_eq!(layer_eval, exp_evals);
        assert_eq!(layer_eval, evals);
    }

    #[test]
    fn test_layers_random() {
        let mut rng = rand::thread_rng();

        let log2_eval_domain = 10;
        let first_layer_degree_bound = 320;
        let eval_point = Felt252::rand(&mut rng);
        let coeffs: Vec<Felt252> = (0..first_layer_degree_bound)
            .map(|_| Felt252::rand(&mut rng))
            .collect();

        let (layer_0, layer_1_proxy) = init_test(eval_point, coeffs, log2_eval_domain);
        let (layer_2, layer_3_proxy, layer_4) = init_more(&layer_1_proxy, eval_point);

        // Test get_layer_size()
        assert_eq!(layer_0.get_layer_size(), 1024);
        assert_eq!(layer_1_proxy.get_layer_size(), 512);
        assert_eq!(layer_2.get_layer_size(), 512);
        assert_eq!(layer_3_proxy.get_layer_size(), 256);
        assert_eq!(layer_4.get_layer_size(), 256);

        // Test first layer degree check
        let layer_0_eval = layer_0.get_layer().unwrap();
        let mut layer_0_lde_manager = MultiplicativeLDE::new(layer_0.get_domain(), true);
        layer_0_lde_manager.add_eval(&layer_0_eval);
        let lde_manager_coef = layer_0_lde_manager.coeffs(0);
        let layer_0_deg = {
            let mut deg = 0;
            for i in (0..lde_manager_coef.len()).rev() {
                if lde_manager_coef[i] != Felt252::ZERO {
                    deg = i;
                    break;
                }
            }
            deg
        };
        assert_eq!(layer_0_deg, first_layer_degree_bound - 1);

        // Test Proxy Layer
        let layer_1_eval = layer_1_proxy.get_layer().unwrap();
        let mut layer_1_lde_manager = MultiplicativeLDE::new(layer_1_proxy.get_domain(), true);
        layer_1_lde_manager.add_eval(&layer_1_eval);
        let lde_1_manager_coef = layer_1_lde_manager.coeffs(0);
        let layer_1_deg = {
            let mut deg = 0;
            for i in (0..lde_1_manager_coef.len()).rev() {
                if lde_1_manager_coef[i] != Felt252::ZERO {
                    deg = i;
                    break;
                }
            }
            deg
        };
        assert_eq!(layer_1_deg, first_layer_degree_bound / 2 - 1);
        let folded_layer = MultiplicativeFriFolder::compute_next_fri_layer(
            layer_0.get_domain(),
            &layer_0_eval,
            eval_point,
        )
        .unwrap();
        assert_eq!(folded_layer, layer_1_eval);

        // Test Real Layer
        let layer_2_eval = layer_2.get_layer().unwrap();
        let mut layer_2_lde_manager = MultiplicativeLDE::new(layer_2.get_domain(), true);
        layer_2_lde_manager.add_eval(&layer_2_eval);
        let lde_2_manager_coef = layer_2_lde_manager.coeffs(0);
        let layer_2_deg = {
            let mut deg = 0;
            for i in (0..lde_2_manager_coef.len()).rev() {
                if lde_2_manager_coef[i] != Felt252::ZERO {
                    deg = i;
                    break;
                }
            }
            deg
        };
        assert_eq!(layer_2_deg, first_layer_degree_bound / 2 - 1);
        let folded_layer = MultiplicativeFriFolder::compute_next_fri_layer(
            layer_0.get_domain(),
            &layer_0_eval,
            eval_point,
        )
        .unwrap();
        assert_eq!(folded_layer, layer_2_eval);

        // Test evaluations
        let layer_eval = layer_4.get_layer().unwrap();
        let index: Vec<usize> = (0..256).collect();
        let evals = layer_4.eval_at_points(&index);
        assert_eq!(layer_eval, evals);
    }
}
