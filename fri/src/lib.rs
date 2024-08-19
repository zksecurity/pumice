mod folder;
mod layer;
mod parameters;
mod verifier;

pub trait FftBases {
    fn size(&self) -> u64;
}

pub trait FftDomainBase {}
