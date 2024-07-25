use crate::channel::{Channel, ChannelStates, FSChannel, ProverChannel};
use crate::randomness::prng::Prng;
use ark_ff::{BigInteger, PrimeField};
use sha3::digest::{Digest, Output};
use std::marker::PhantomData;

pub struct FSProverChannel<F: PrimeField, D: Digest, P: Prng> {
    pub _ph: PhantomData<(F, D)>,
    pub prng: P,
    pub proof: Vec<u8>,
    pub states: ChannelStates,
}

impl<F: PrimeField, D: Digest, P: Prng> FSProverChannel<F, D, P> {
    pub fn new(prng: P) -> Self {
        Self {
            _ph: PhantomData,
            prng,
            proof: vec![],
            states: Default::default(),
        }
    }
}

impl<F: PrimeField, D: Digest, P: Prng> Channel for FSProverChannel<F, D, P> {
    type Field = F;

    fn draw_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.states.is_query_phase(),
            "Prover can't receive randomness after query phase has begun."
        );

        let raw_bytes = self.draw_bytes(std::mem::size_of::<u64>());
        let number = u64::from_be_bytes(raw_bytes.try_into().unwrap());

        assert!(
            upper_bound < 0x0001_0000_0000_0000,
            "Random number with too high an upper bound"
        );

        number % upper_bound
    }

    #[inline]
    fn draw_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut raw_bytes = vec![0u8; n];
        self.prng.random_bytes(&mut raw_bytes);
        raw_bytes
    }
}

impl<F: PrimeField, D: Digest, P: Prng> FSChannel for FSProverChannel<F, D, P> {
    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        Ok(())
    }

    fn is_end_of_proof(&self) -> bool {
        true
    }
}

impl<F: PrimeField, D: Digest, P: Prng> ProverChannel for FSProverChannel<F, D, P> {
    type Digest = D;

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
        self.proof.extend_from_slice(bytes);

        if !self.states.is_query_phase() {
            self.prng.mix_seed_with_bytes(&bytes);
        }

        Ok(())
    }

    fn send_commit_hash(&mut self, commitment: Output<Self::Digest>) -> Result<(), anyhow::Error> {
        self.send_bytes(commitment.as_slice())?;
        self.states.increment_commitment_count();
        self.states.increment_hash_count();
        Ok(())
    }

    fn get_proof(&self) -> Vec<u8> {
        self.proof.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::channel::fs_prover_channel::{Channel, FSProverChannel, ProverChannel};
    use crate::felt252::Felt252;
    use crate::randomness::prng::{Prng, PrngKeccak256};
    use ark_ff::Zero;
    use sha3::Sha3_256;

    type MyFSProverChannel = FSProverChannel<Felt252, Sha3_256, PrngKeccak256>;

    #[test]
    fn test_draw_number() {
        let prng = PrngKeccak256::new();
        let mut channel = MyFSProverChannel::new(prng);

        let upper_bound = 100;
        let number = channel.draw_number(upper_bound);
        assert!(number < upper_bound);
    }

    #[test]
    fn test_receiving_bytes() {
        let prng = PrngKeccak256::new();
        let mut channel = MyFSProverChannel::new(prng);

        for &size in [4, 8, 16, 18, 32, 33, 63, 64, 65].iter() {
            let bytes = channel.draw_bytes(size);
            assert_eq!(bytes.len(), size);
        }
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
