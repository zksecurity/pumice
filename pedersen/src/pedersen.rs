use crate::{constants::PEDERSEN_CHUNK_SIZE, hash_context::PedersenHashContext};
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use felt::Felt252;
use num_bigint::BigUint;

pub struct PedersenHash {
    state: Felt252,
}

impl PedersenHash {
    pub fn init_digest_to(digest: Vec<u8>) -> Result<Self, anyhow::Error> {
        let state = bytes_to_field(&digest)?;
        Ok(PedersenHash { state })
    }

    pub fn get_digest(&self) -> Vec<u8> {
        self.state.into_bigint().to_bytes_be()
    }

    pub fn hash(val0: PedersenHash, val1: PedersenHash) -> PedersenHash {
        let cntx = PedersenHashContext::default();
        let res = cntx.hash_elements(val0.state, val1.state);
        PedersenHash { state: res }
    }

    pub fn hash_bytes_with_length(bytes: Vec<u8>) -> Result<PedersenHash, anyhow::Error> {
        assert!(
            bytes.len() % PEDERSEN_CHUNK_SIZE == 0,
            "Pedersen hash currently does not support partial blocks."
        );
        let mut state = Felt252::ZERO;
        let cntx = PedersenHashContext::default();
        let modulus = BigUint::from_bytes_be(&Felt252::MODULUS.to_bytes_be());

        let mut bytes_to_hash = bytes.len();
        let mut offset = 0;

        while bytes_to_hash >= PEDERSEN_CHUNK_SIZE {
            let word = BigUint::from_bytes_be(&bytes[offset..offset + PEDERSEN_CHUNK_SIZE]);
            let q = word.clone() / modulus.clone();
            let r = word % modulus.clone();
            let value = bytes_to_field(&r.to_bytes_be())?;
            assert!(q < BigUint::from(1000u64), "Unexpectedly large shift.");
            let shift = bytes_to_field(&q.to_bytes_be())?;

            state = cntx.hash_elements(state, value) + shift;

            offset += PEDERSEN_CHUNK_SIZE;
            bytes_to_hash -= PEDERSEN_CHUNK_SIZE;
        }

        let val1 = bytes.len() / PEDERSEN_CHUNK_SIZE;
        state = cntx.hash_elements(state, Felt252::from(val1 as i64));

        Ok(PedersenHash { state })
    }
}

fn bytes_to_field(bytes: &[u8]) -> Result<Felt252, anyhow::Error> {
    let bits = {
        let mut bits = Vec::new();
        for byte in bytes {
            for i in (0..8).rev() {
                bits.push(byte & (1 << i) != 0);
            }
        }
        bits
    };
    assert!(
        bits.len() <= 256,
        "The bit length exceeds the capacity of BigInt with 4 limbs."
    );

    let big_int = <BigInt<4> as BigInteger>::from_bits_be(&bits);

    if big_int >= Felt252::MODULUS {
        return Err(anyhow::anyhow!("big_int is larger than the modulus"));
    }

    Felt252::from_bigint(big_int).ok_or_else(|| anyhow::anyhow!("conversion failed"))
}

#[cfg(test)]
mod tests {
    use super::PedersenHash;
    use crate::constants::PEDERSEN_CHUNK_SIZE;

    fn generate_test_vector(length: usize) -> Vec<u8> {
        let mut test_vector = Vec::with_capacity(length);

        let mut val: u8 = 0x11;
        for _ in 0..length {
            test_vector.push(val);
            val = val.wrapping_add(0x11);
            if val == 0x99 {
                val = 0x11;
            }
        }

        test_vector
    }

    #[test]
    fn test_pedersen_empty() {
        let input = vec![];
        let res = PedersenHash::hash_bytes_with_length(input).unwrap();
        let exp_res =
            felt::hex("0x49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804");
        assert_eq!(exp_res, res.state);
    }

    #[test]
    fn test_pedersen() {
        let input = generate_test_vector(PEDERSEN_CHUNK_SIZE);
        let res = PedersenHash::hash_bytes_with_length(input).unwrap();
        let exp_res =
            felt::hex("0x76ee717494854a0656535e7ebd851daf6daced15363a94e3c14587187818208");
        assert_eq!(exp_res, res.state);

        let input = generate_test_vector(2 * PEDERSEN_CHUNK_SIZE);
        let res = PedersenHash::hash_bytes_with_length(input).unwrap();
        let exp_res =
            felt::hex("0x5ae166bb6f7bd5aecc639a736a38257f0913611c4967e6fb1cabd4278790e4c");
        assert_eq!(exp_res, res.state);
    }
}
