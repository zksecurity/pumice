use ark_ff::{
    fields::{MontBackend, MontConfig},
    BigInteger, Fp256, PrimeField, Zero,
};
use std::fmt::Write;

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct Felt252Config;
pub type Felt252 = Fp256<MontBackend<Felt252Config, 4>>;

/// This method is used for testing / debugging purposes.
/// It provides a convenient way to create a `Felt252` from a hex string.
///
/// Warning: this method is slow and will panic if the input is not a valid hex string.
pub fn hex(hex: &str) -> Felt252 {
    let mut chars = hex.chars();
    assert_eq!(chars.next(), Some('0'));
    assert_eq!(chars.next(), Some('x'));

    let mut res = Felt252::zero();
    for digit in chars {
        let val = u8::from_str_radix(&digit.to_string(), 0x10).unwrap();
        res *= Felt252::from(0x10u64);
        res += Felt252::from(val as u64);
    }
    res
}

/// This method is used for testing / debugging purposes.
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

    use ark_ff::{FftField, Field, PrimeField};

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

    // sanity check:
    // roots of unity for 2^k, k = 0..64
    #[test]
    fn get_root_of_unity() {
        for k in 0..64 {
            let omega = Felt252::get_root_of_unity(1 << k).unwrap();
            assert_eq!(omega.pow(&[1 << k]), Felt252::ONE);
        }
    }
}
