use ark_ff::Zero;
use ark_ff::{BigInteger, PrimeField};
use std::fmt::Write;

pub use container::Felt252;

#[allow(non_local_definitions)]
mod container {
    use ark_ff::{
        fields::{MontBackend, MontConfig},
        Fp256,
    };

    #[derive(MontConfig)]
    #[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
    #[generator = "3"]
    #[small_subgroup_base = "2"]
    #[small_subgroup_power = "192"]
    pub struct Felt252Config;
    pub type Felt252 = Fp256<MontBackend<Felt252Config, 4>>;
}

/// This method is used for testing / debugging purposes.
/// It provides a convenient way to create a `Felt252` from a hex string.
///
/// Warning: this method is slow and will panic if the input is not a valid hex string.
pub fn hex(hex: &str) -> Felt252 {
    let mut chars = hex.chars();
    assert!(chars.next().unwrap() == '0');
    assert!(chars.next().unwrap() == 'x');

    let mut res = Felt252::zero();
    for digit in chars {
        let val = u8::from_str_radix(&digit.to_string(), 0x10).unwrap();
        res *= Felt252::from(0x10u64);
        res += Felt252::from(val as u64);
    }
    res
}

pub fn felt_252_to_hex<F: PrimeField>(felt: &F) -> String {
    let bigint = felt.into_bigint().to_bytes_be();
    let hex_string = bigint.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{:02x}", b);
        output
    });

    // remove leading 0
    let hex_string = hex_string.trim_start_matches('0').to_string();
    // add leading 0x
    format!("0x{}", hex_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ff::{FftField, PrimeField};

    // sanity check:
    // \omega = 0x5282db87529cfa3f0464519c8b0fa5ad187148e11a61616070024f42f8ef94
    #[test]
    fn root_of_unity() {
        assert_eq!(Felt252::TWO_ADICITY, 192);
        assert_eq!(
            Felt252::TWO_ADIC_ROOT_OF_UNITY,
            Felt252::from_be_bytes_mod_order(&[
                0x52, 0x82, 0xdb, 0x87, 0x52, 0x9c, 0xfa, 0x3f, 0x04, 0x64, 0x51, 0x9c, 0x8b, 0x0f,
                0xa5, 0xad, 0x18, 0x71, 0x48, 0xe1, 0x1a, 0x61, 0x61, 0x60, 0x70, 0x02, 0x4f, 0x42,
                0xf8, 0xef, 0x94,
            ])
        );
    }
}
