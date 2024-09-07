use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

pub fn get_field_element_at_index<F: FftField, E: EvaluationDomain<F>>(
    domain: &E,
    index: usize,
) -> F {
    // loop index with divide by 2
    let mut i = index;
    let mut s = (domain.size() / 2) as usize;
    let mut new_index = 0;
    while index > 0 {
        if i & 1 != 0 {
            new_index += s;
        }
        i >>= 1;
        s >>= 1;
    }
    domain.elements().nth(new_index).unwrap()
}

// change order of elements in domain
pub fn change_order_of_elements_in_domain<F: FftField>(elements: &[F]) -> Vec<F> {
    assert!(elements.len().is_power_of_two());
    let mut new_elements = vec![F::zero(); elements.len()];
    let log_len = elements.len().trailing_zeros();
    let mapping_vec = (0..log_len)
        .map(|i| (1 << (log_len - 1 - i)))
        .collect::<Vec<usize>>();

    // [1, 2, 4]
    // consider array as binary number basis
    // 0 -> 000 -> 0
    // 1 -> 001 -> 4
    // 2 -> 010 -> 2
    // 3 -> 011 -> 6
    // 4 -> 100 -> 1
    // 5 -> 101 -> 5
    // 6 -> 110 -> 3
    // 7 -> 111 -> 7
    for (i, element) in elements.iter().enumerate() {
        let mut new_index = 0;
        let mut index = i;
        for base in mapping_vec.iter() {
            if index & 1 != 0 {
                new_index += base;
            }
            index >>= 1;
        }
        new_elements[new_index] = *element;
    }

    new_elements
}

#[allow(dead_code)]
pub fn make_fft_domains<F: FftField>(
    domain_size_log: usize,
    offset: F,
) -> Vec<Radix2EvaluationDomain<F>> {
    let mut current_offset = offset;
    let mut domains = Vec::with_capacity(domain_size_log + 1);
    for i in (0..=domain_size_log).rev() {
        let domain = Radix2EvaluationDomain::<F>::new(1 << i)
            .unwrap()
            .get_coset(current_offset)
            .unwrap();
        domains.push(domain);
        current_offset = current_offset * current_offset;
    }
    domains
}

#[cfg(test)]
mod tests {
    use felt::Felt252;

    use super::*;

    #[test]
    fn test_change_order_of_elements_in_domain() {
        let elements = vec![
            Felt252::from(0u64),
            Felt252::from(4u64),
            Felt252::from(2u64),
            Felt252::from(6u64),
            Felt252::from(1u64),
            Felt252::from(5u64),
            Felt252::from(3u64),
            Felt252::from(7u64),
        ];
        let new_elements = change_order_of_elements_in_domain(&elements);
        assert_eq!(
            new_elements,
            vec![
                Felt252::from(0u64),
                Felt252::from(1u64),
                Felt252::from(2u64),
                Felt252::from(3u64),
                Felt252::from(4u64),
                Felt252::from(5u64),
                Felt252::from(6u64),
                Felt252::from(7u64),
            ]
        );
    }
}
