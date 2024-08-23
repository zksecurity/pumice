mod folder;
mod layer;
mod parameters;
mod verifier;
use ark_ff::FftField;
use ark_poly::domain::GeneralEvaluationDomain;

struct FftBases<F: FftField> {
    pub domains: Vec<GeneralEvaluationDomain<F>>,
}

impl<F: FftField> FftBases<F> {
    fn new(domains: Vec<GeneralEvaluationDomain<F>>) -> Self {
        Self { domains }
    }

    fn at(&self, index: usize) -> &GeneralEvaluationDomain<F> {
        &self.domains[index]
    }
}

pub trait FftDomainBase {}
