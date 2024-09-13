use ark_ff::FftField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

#[allow(dead_code)]
pub fn get_field_element_at_index<F: FftField, E: EvaluationDomain<F>>(
    domain: &E,
    index: usize,
) -> F {
    let log_len = domain.size().trailing_zeros() as usize;
    domain
        .elements()
        .nth(translate_index(index, log_len))
        .unwrap()
}

// change order of elements in domain
pub fn change_order_of_elements_in_domain<F: FftField>(elements: &[F]) -> Vec<F> {
    // get smallest power of two that is greater than elements.len()
    let size = elements.len().next_power_of_two();
    // byte size of usize - log_len
    let log_len = size.trailing_zeros() as usize;
    // byte size of usize - log_len
    println!("log_len: {}", log_len);
    let mut new_elements = Vec::with_capacity(size);
    for i in 0..size {
        println!("i: {}", i);
        println!("translate_index(i): {}", translate_index(i, log_len));
        new_elements.push(elements[translate_index(i, log_len)])
    }

    new_elements
}

fn translate_index(index: usize, log_len: usize) -> usize {
    let sft = std::mem::size_of::<usize>() * 8 - log_len;
    index.reverse_bits() >> sft
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
