mod folder;
mod parameters;
mod verifier;
use ark_ff::FftField;
use ark_poly::domain::Radix2EvaluationDomain;

struct FftBases<F: FftField> {
    pub domains: Vec<Radix2EvaluationDomain<F>>,
}

impl<F: FftField> FftBases<F> {
    pub fn new(domains: Vec<Radix2EvaluationDomain<F>>) -> Self {
        Self { domains }
    }

    pub fn num_layers(&self) -> usize {
        // last domain is empty
        self.domains.len() - 1
    }

    pub fn at(&self, index: usize) -> &Radix2EvaluationDomain<F> {
        &self.domains[index]
    }
}

pub trait FftDomainBase {}
