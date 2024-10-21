use ark_ff::PrimeField;

pub struct MultiplicativeNeighbors<F: PrimeField> {
    mask: Vec<(usize, usize)>,
    coset_size: usize,
    neighbor_wraparound_mask: usize,
    trace_lde: Vec<Vec<F>>,
}

impl<F: PrimeField> MultiplicativeNeighbors<F> {
    pub fn new(mask: &[(usize, usize)], trace_lde: &[Vec<F>]) -> Self {
        let coset_size = get_coset_size(trace_lde);
        let neighbor_wraparound_mask = coset_size - 1;

        assert!(
            coset_size.is_power_of_two(),
            "Coset size must be a power of 2"
        );

        for mask_item in mask.iter() {
            assert!(
                mask_item.1 < trace_lde.len(),
                "Too few trace LDE columns provided."
            );
        }

        MultiplicativeNeighbors {
            mask: mask.to_vec(),
            coset_size,
            neighbor_wraparound_mask,
            trace_lde: trace_lde.to_vec(),
        }
    }

    pub fn get_neighbors(&self, idx: usize) -> Vec<F> {
        let mask = &self.mask;
        let trace_lde = &self.trace_lde;
        let neighbor_wraparound_mask = self.neighbor_wraparound_mask;

        let mut neighbors = Vec::with_capacity(mask.len());

        for (relative_row, col) in mask.iter() {
            let pos = (idx + relative_row) & neighbor_wraparound_mask;
            neighbors.push(trace_lde[*col][pos]);
        }

        neighbors
    }

    pub fn coset_size(&self) -> usize {
        self.coset_size
    }
}

fn get_coset_size<F: PrimeField>(trace_lde: &[Vec<F>]) -> usize {
    assert!(
        !trace_lde.is_empty(),
        "Trace must contain at least one column."
    );
    let coset_size = trace_lde[0].len();
    for column in trace_lde.iter() {
        assert!(
            column.len() == coset_size,
            "All columns must have the same size."
        );
    }
    coset_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use felt::Felt252;

    #[test]
    fn test_multiplicative_neighbors() {
        let mut rng = rand::thread_rng();

        let trace_length = 8;
        let n_columns = 4;
        let mask: [(usize, usize); 5] = [(0, 0), (0, 1), (1, 2), (2, 0), (2, 3)];

        let mut trace: Vec<Vec<Felt252>> = Vec::with_capacity(n_columns);

        for _ in 0..n_columns {
            let rand_vec: Vec<Felt252> =
                (0..trace_length).map(|_| Felt252::rand(&mut rng)).collect();
            trace.push(rand_vec);
        }

        let neighbors = MultiplicativeNeighbors::new(&mask, &trace);

        let mut result: Vec<Vec<Felt252>> = Vec::new();
        for i in 0..trace_length {
            result.push(neighbors.get_neighbors(i));
        }

        let expected = vec![
            vec![
                trace[0][0],
                trace[1][0],
                trace[2][1],
                trace[0][2],
                trace[3][2],
            ],
            vec![
                trace[0][1],
                trace[1][1],
                trace[2][2],
                trace[0][3],
                trace[3][3],
            ],
            vec![
                trace[0][2],
                trace[1][2],
                trace[2][3],
                trace[0][4],
                trace[3][4],
            ],
            vec![
                trace[0][3],
                trace[1][3],
                trace[2][4],
                trace[0][5],
                trace[3][5],
            ],
            vec![
                trace[0][4],
                trace[1][4],
                trace[2][5],
                trace[0][6],
                trace[3][6],
            ],
            vec![
                trace[0][5],
                trace[1][5],
                trace[2][6],
                trace[0][7],
                trace[3][7],
            ],
            vec![
                trace[0][6],
                trace[1][6],
                trace[2][7],
                trace[0][0],
                trace[3][0],
            ],
            vec![
                trace[0][7],
                trace[1][7],
                trace[2][0],
                trace[0][1],
                trace[3][1],
            ],
        ];

        assert_eq!(result, expected);
    }
}
