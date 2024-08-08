use crate::pow::{ProofOfWorkProver, POW_DEFAULT_CHUNK_SIZE};
use crate::{channel_states::ChannelStates, Channel, FSChannel, ProverChannel};
use ark_ff::{BigInteger, PrimeField};
use generic_array::typenum::U32;
use generic_array::GenericArray;
use num_bigint::BigUint;
use randomness::Prng;
use sha3::Digest;
use std::marker::PhantomData;
use std::ops::Div;
use std::sync::OnceLock;

pub struct FSProverChannel<F: PrimeField, P: Prng, W: Digest> {
    pub _ph: PhantomData<(F, W)>,
    pub prng: P,
    pub proof: Vec<u8>,
    pub states: ChannelStates,
}

impl<F: PrimeField, P: Prng, W: Digest> FSProverChannel<F, P, W> {
    pub fn new(prng: P) -> Self {
        Self {
            _ph: PhantomData,
            prng,
            proof: vec![],
            states: Default::default(),
        }
    }
}

#[allow(dead_code)]
impl<F: PrimeField, P: Prng, W: Digest> FSProverChannel<F, P, W> {
    fn modulus() -> &'static BigUint {
        static MODULUS: OnceLock<BigUint> = OnceLock::new();
        MODULUS.get_or_init(|| F::MODULUS.into())
    }

    fn max_divislble() -> &'static BigUint {
        static MAX_VALUE: OnceLock<BigUint> = OnceLock::new();
        MAX_VALUE.get_or_init(|| {
            let modulus = F::MODULUS.into();
            let size = F::MODULUS_BIT_SIZE.div_ceil(8) as usize;
            let max = BigUint::from_bytes_be(&vec![0xff; size]);
            let quotient = max.div(&modulus);
            quotient * modulus
        })
    }
}

impl<F: PrimeField, P: Prng, W: Digest> Channel for FSProverChannel<F, P, W> {
    type Field = F;
    type Commitment = GenericArray<u8, U32>;

    fn draw_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.states.is_query_phase(),
            "Prover can't receive randomness after query phase has begun."
        );

        self.prng.random_number(upper_bound)
    }

    fn draw_felem(&mut self) -> Self::Field {
        assert!(
            !self.states.is_query_phase(),
            "Prover can't receive randomness after query phase has begun."
        );

        let mut raw_bytes: Vec<u8>;
        let mut random_biguint: BigUint;
        loop {
            raw_bytes = self
                .prng
                .random_bytes_vec(Self::Field::MODULUS_BIT_SIZE.div_ceil(8) as usize);
            random_biguint = BigUint::from_bytes_be(&raw_bytes);
            if random_biguint < *Self::max_divislble() {
                random_biguint %= Self::modulus();
                break;
            }
        }

        let field_element: F = Self::Field::from_bigint(
            <Self::Field as PrimeField>::BigInt::try_from(random_biguint).unwrap(),
        )
        .unwrap();

        field_element
    }
}

impl<F: PrimeField, P: Prng, W: Digest> FSChannel for FSProverChannel<F, P, W> {
    type PowHash = W;

    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        if security_bits == 0 {
            return Ok(());
        }

        let worker = ProofOfWorkProver::<Self::PowHash>::default();
        let mut pow = worker.prove(
            &self.prng.prng_state(),
            security_bits,
            POW_DEFAULT_CHUNK_SIZE,
        );

        // Expand the nonce to be compatible with the size of felt
        if pow.len() < P::bytes_chunk_size() {
            pow.resize(P::bytes_chunk_size(), 0u8);
        }

        self.send_data(&pow)?;
        Ok(())
    }
}

impl<F: PrimeField, P: Prng, W: Digest> ProverChannel for FSProverChannel<F, P, W> {
    fn send_felts(&mut self, felts: &[Self::Field]) -> Result<(), anyhow::Error> {
        let mut raw_bytes = vec![0u8; 0];
        for &felem in felts {
            let big_int = felem.into_bigint();
            let bytes = big_int.to_bytes_be();
            raw_bytes.extend_from_slice(&bytes);
        }
        self.send_bytes(&raw_bytes)?;

        Ok(())
    }

    fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), anyhow::Error> {
        // XXX : should assert ?
        if bytes.len() % P::bytes_chunk_size() != 0 {
            return Err(anyhow::anyhow!(
                "Number of bytes must be a multiple of the bytes chunk size."
            ));
        }

        self.proof.extend_from_slice(bytes);

        if !self.states.is_query_phase() {
            self.prng.mix_seed_with_bytes(bytes);
        }

        Ok(())
    }

    fn send_data(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.send_bytes(data)?;
        self.states.increment_data_count();
        Ok(())
    }

    fn send_commit_hash(&mut self, commitment: Self::Commitment) -> Result<(), anyhow::Error> {
        self.send_bytes(commitment.as_ref())?;
        self.states.increment_commitment_count();
        self.states.increment_hash_count();
        Ok(())
    }

    fn send_decommit_node(&mut self, decommitment: Self::Commitment) -> Result<(), anyhow::Error> {
        self.send_bytes(decommitment.as_ref())?;
        self.states.increment_hash_count();
        Ok(())
    }

    fn get_proof(&self) -> Vec<u8> {
        self.proof.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::fs_prover_channel::{Channel, FSProverChannel, ProverChannel};
    use felt::Felt252;
    use randomness::{keccak256::PrngKeccak256, Prng};
    use sha3::Sha3_256;

    type MyFSProverChannel = FSProverChannel<Felt252, PrngKeccak256, Sha3_256>;

    #[test]
    fn test_draw_number() {
        let prng = PrngKeccak256::new();
        let mut channel = MyFSProverChannel::new(prng);

        let upper_bound = 100;
        let number = channel.draw_number(upper_bound);
        assert!(number < upper_bound);
    }

    #[test]
    fn test_recurring_calls_yield_uniform_distribution_statistical() {
        let cafe_bytes: [u8; 4] = [0xca, 0xfe, 0xca, 0xfe];
        let prng: PrngKeccak256 = PrngKeccak256::new_with_seed(&cafe_bytes);
        let mut channel = MyFSProverChannel::new(prng);

        let mut histogram: [u64; 10] = [0u64; 10];
        for _ in 0..10000 {
            let number = channel.draw_number(10);
            histogram[number as usize] += 1;
        }

        for count in histogram.iter() {
            assert!((1000 - 98..=1000 + 98).contains(count));
        }

        let mut max_random_number = 0;
        for _ in 0..1000 {
            let random_number = channel.draw_number(10000000);
            if random_number > max_random_number {
                max_random_number = random_number;
            }
        }

        assert_eq!(max_random_number, 9994934); // Empirical result. Should be roughly 9999000.
    }

    #[test]
    fn test_sending_message_affects_randomness() {
        let prng1 = PrngKeccak256::new();
        let prng2 = PrngKeccak256::new();
        let mut channel1 = MyFSProverChannel::new(prng1);
        let mut channel2 = MyFSProverChannel::new(prng2);

        assert_eq!(
            channel1.draw_number(10000000),
            channel2.draw_number(10000000)
        );
        channel1.send_felts(&[Felt252::from(1u64)]).unwrap();
        assert_ne!(
            channel1.draw_number(10000000),
            channel2.draw_number(10000000)
        );
    }

    #[test]
    fn test_sending_message_affects_randomness2() {
        let prng1 = PrngKeccak256::new();
        let prng2 = PrngKeccak256::new();
        let mut channel1 = MyFSProverChannel::new(prng1);
        let mut channel2 = MyFSProverChannel::new(prng2);

        assert_eq!(
            channel1.draw_number(10000000),
            channel2.draw_number(10000000)
        );
        channel1.send_felts(&[Felt252::from(1u64)]).unwrap();
        channel2.send_felts(&[Felt252::from(2u64)]).unwrap();
        assert_ne!(
            channel1.draw_number(10000000),
            channel2.draw_number(10000000)
        );
    }
}
