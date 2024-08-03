use crate::pow::ProofOfWorkVerifier;
use crate::{channel_states::ChannelStates, Channel, FSChannel, VerifierChannel};
use ark_ff::PrimeField;
use generic_array::GenericArray;
use num_bigint::BigUint;
use randomness::Prng;
use sha3::Digest;
use std::io::{Cursor, Read};
use std::marker::PhantomData;
use std::ops::Div;
use std::sync::OnceLock;

pub struct FSVerifierChannel<F: PrimeField, P: Prng, W: Digest> {
    pub _ph: PhantomData<(F, W)>,
    pub prng: P,
    pub proof: Cursor<Vec<u8>>,
    pub states: ChannelStates,
}

impl<F: PrimeField, P: Prng, W: Digest> FSVerifierChannel<F, P, W> {
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
impl<F: PrimeField, P: Prng, W: Digest> FSVerifierChannel<F, P, W> {
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

impl<F: PrimeField, P: Prng, W: Digest> Channel for FSVerifierChannel<F, P, W> {
    type Field = F;
    type Commitment = GenericArray<u8, P::CommitmentSize>;

    fn draw_number(&mut self, upper_bound: u64) -> u64 {
        assert!(
            !self.states.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
        );

        self.prng.random_number(upper_bound)
    }

    fn draw_felem(&mut self) -> Self::Field {
        assert!(
            !self.states.is_query_phase(),
            "Verifier can't send randomness after query phase has begun."
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

        // cannot use Self::Field::from_be_bytes_mod_order(), output differs
        let field_element: F = Self::Field::from_bigint(
            <Self::Field as PrimeField>::BigInt::try_from(random_biguint).unwrap(),
        )
        .unwrap();

        field_element
    }
}

impl<F: PrimeField, P: Prng, W: Digest> FSChannel for FSVerifierChannel<F, P, W> {
    type PowHash = W;

    fn apply_proof_of_work(&mut self, security_bits: usize) -> Result<(), anyhow::Error> {
        if security_bits == 0 {
            return Ok(());
        }

        let worker: ProofOfWorkVerifier<Self::PowHash> = Default::default();
        let witness = self.recv_data(ProofOfWorkVerifier::<Self::PowHash>::NONCE_BYTES)?;

        match worker.verify(self.proof.get_ref(), security_bits, &witness) {
            true => Ok(()),
            false => Err(anyhow::anyhow!("Wrong proof of work.")),
        }
    }
}

impl<F: PrimeField, P: Prng, W: Digest> VerifierChannel for FSVerifierChannel<F, P, W> {
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

    fn recv_commit_hash(&mut self) -> Result<Self::Commitment, anyhow::Error> {
        let size = std::mem::size_of::<Self::Commitment>();
        let bytes = self.recv_bytes(size)?;

        let commitment = GenericArray::try_from_iter(bytes).unwrap();

        self.states.increment_commitment_count();
        self.states.increment_hash_count();
        Ok(commitment)
    }

    fn recv_decommit_node(&mut self) -> Result<Self::Commitment, anyhow::Error> {
        let size = std::mem::size_of::<Self::Commitment>();
        let bytes = self.recv_bytes(size)?;

        let decommitment = GenericArray::try_from_iter(bytes).unwrap();

        self.states.increment_hash_count();
        Ok(decommitment)
    }
}
