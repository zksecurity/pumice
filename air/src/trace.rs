use ark_ff::PrimeField;

pub struct Trace<F: PrimeField> {
    values: Vec<Vec<F>>,
}

impl<F: PrimeField> Trace<F> {
    pub fn new(values: Vec<Vec<F>>) -> Self {
        Trace { values }
    }

    pub fn length(&self) -> usize {
        self.values[0].len()
    }

    pub fn width(&self) -> usize {
        self.values.len()
    }

    pub fn get_column(&self, column: usize) -> &Vec<F> {
        &self.values[column]
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use felt::Felt252;
    use rand::Rng;

    use super::Trace;

    #[test]
    fn test_trace() {
        let mut rng = rand::thread_rng();

        let width = rng.gen_range(1..=10);
        let height = rng.gen_range(1..=10);

        let mut values = vec![];
        for _ in 0..width {
            let rand_col: Vec<Felt252> = (0..height).map(|_| Felt252::rand(&mut rng)).collect();
            values.push(rand_col);
        }

        let trace = Trace::new(values.clone());
        assert_eq!(trace.length(), height);
        assert_eq!(trace.width(), width);

        for i in 0..width {
            assert_eq!(trace.get_column(i).len(), height);

            for j in 0..height {
                assert_eq!(trace.get_column(i)[j], values[i][j]);
            }
        }
    }
}
