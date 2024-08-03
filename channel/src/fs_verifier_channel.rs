use crate::pow::ProofOfWorkVerifier;
use crate::{channel_states::ChannelStates, Channel, FSChannel, VerifierChannel};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use randomness::Prng;
use sha3::digest::generic_array::GenericArray;
use sha3::digest::{Digest, Output, OutputSizeUser};
use std::io::{Cursor, Read};
use std::marker::PhantomData;
use std::ops::Div;
use std::sync::OnceLock;

pub struct FSVerifierChannel<F: PrimeField, D: Digest, P: Prng> {
    pub _ph: PhantomData<(F, D)>,
    pub prng: P,
    pub proof: Cursor<Vec<u8>>,
    pub states: ChannelStates,
}

impl<F: PrimeField, D: Digest, P: Prng> FSVerifierChannel<F, D, P> {
    pub fn new(prng: P, proof: Vec<u8>) -> Self {
        Self {
            _ph: PhantomData,
            prng,
            proof: Cursor::new(proof),
            states: Default::default(),
        }
    }
}

#[allow(dead_code)]
impl<F: PrimeField, D: Digest, P: Prng> FSVerifierChannel<F, D, P> {
    fn modulus() -> &'static BigUint {
        static MODULUS: OnceLock<BigUint> = OnceLock::new();
        MODULUS.get_or_init(|| F::MODULUS.into())
    }

    fn max_divislble() -> &'static BigUint {
        static MAX_VALUE: OnceLock<BigUint> = OnceLock::new();
        MAX_VALUE.get_or_init(|| {
            let modulus = F::MODULUS.into();
            let size: usize = ((F::MODULUS_BIT_SIZE + 7) / 8) as usize;
            let max = BigUint::from_bytes_be(&vec![0xff; size]);
            let quotient = max.div(&modulus);
            quotient * modulus
        })
    }
}

impl<F: PrimeField, D: Digest, P: Prng> Channel for FSVerifierChannel<F, D, P> {
    type Field = F;
    type FieldHash = D;

    fn draw_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.states.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );

        let raw_bytes = self.draw_bytes(std::mem::size_of::<u64>());
        let number = u64::from_be_bytes(raw_bytes.try_into().unwrap());

        assert!(
            upper_bound < 0x0001_0000_0000_0000,
            "Random number with too high an upper bound"
        );

        number % upper_bound
    }

    fn draw_felem(&mut self) -> Self::Field {
        assert!(
            !self.states.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );

        let mut raw_bytes: Vec<u8>;
        let mut random_biguint: BigUint;
        loop {
            raw_bytes = self.draw_bytes(Self::Field::MODULUS_BIT_SIZE.div_ceil(8) as usize);
            random_biguint = BigUint::from_bytes_be(&raw_bytes);
            if random_biguint < *Self::max_divislble() {
                random_biguint %= Self::modulus();
                break;
            }
        }

        // cannot use Self::Field::from_be_bytes_mod_order(), output differs
        let field_element: F = Self::Field::from_bigint(
            <Self::Field as PrimeField>::BigInt::try_from(random_biguint).unwrap(),
        )
        .unwrap();

        field_element
    }

    #[inline]
    fn draw_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut raw_bytes = vec![0u8; n];
        self.prng.random_bytes(&mut raw_bytes);
        raw_bytes
    }
}

impl<F: PrimeField, D: Digest, P: Prng> FSChannel for FSVerifierChannel<F, D, P> {
    type PowHash = P;

    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        if security_bits == 0 {
            return Ok(());
        }

        let worker: ProofOfWorkVerifier<D> = Default::default();
        let witness = self.recv_data(ProofOfWorkVerifier::<D>::NONCE_BYTES)?;
        // TODO : remove magic number ( thread count , log_chunk_size )

        match worker.verify(self.proof.get_ref(), security_bits, &witness) {
            true => Ok(()),
            false => Err(anyhow::anyhow!("Wrong proof of work.")),
        }
    }
}

impl<F: PrimeField, D: Digest, P: Prng> VerifierChannel for FSVerifierChannel<F, D, P> {
    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error> {
        let mut felts = Vec::with_capacity(n);
        let chunk_bytes_size = ((Self::Field::MODULUS_BIT_SIZE + 7) / 8) as usize;
        let raw_bytes: Vec<u8> = self.recv_bytes(n * chunk_bytes_size)?;

        for chunk in raw_bytes.chunks_exact(chunk_bytes_size) {
            let felt = Self::Field::from_be_bytes_mod_order(chunk);
            felts.push(felt);
        }

        Ok(felts)
    }

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error> {
        let mut raw_bytes = vec![0u8; n];
        let bytes_read = self.proof.read(&mut raw_bytes)?;
        if bytes_read < n {
            return Err(anyhow::anyhow!("Proof too short."));
        }

        if !self.states.is_query_phase() {
            self.prng.mix_seed_with_bytes(&raw_bytes);
        }
        self.states.increment_byte_count(raw_bytes.len());
        Ok(raw_bytes)
    }

    fn recv_data(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error> {
        let bytes = self.recv_bytes(n)?;
        self.states.increment_data_count();
        Ok(bytes)
    }

    fn recv_commit_hash(&mut self) -> Result<Output<Self::FieldHash>, anyhow::Error> {
        let size = <Self::FieldHash as OutputSizeUser>::output_size();
        let bytes = self.recv_bytes(size)?;

        let commitment = GenericArray::clone_from_slice(bytes.as_slice());

        self.states.increment_commitment_count();
        self.states.increment_hash_count();
        Ok(commitment)
    }

    fn recv_decommit_node(&mut self) -> Result<Output<Self::FieldHash>, anyhow::Error> {
        let size = <Self::FieldHash as OutputSizeUser>::output_size();
        let bytes = self.recv_bytes(size)?;

        let decommitment = GenericArray::clone_from_slice(bytes.as_slice());

        self.states.increment_hash_count();
        Ok(decommitment)
    }
}
