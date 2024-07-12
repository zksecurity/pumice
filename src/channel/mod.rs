pub mod annotation;
pub mod channel_statistics;

use annotation::Annotation;
use ark_ff::Field;
use channel_statistics::ChannelStatistics;
use std::fmt;

#[allow(dead_code)]
trait Channel {
    type Field: Field;

    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error>;

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn random_number(&mut self, bound: u64) -> u64;

    fn random_field(&mut self) -> Self::Field;

    fn apply_proof_of_work(&mut self, security_bits: usize);

    fn begin_query_phase(&mut self);

    /// Channel statistics related methods
    fn get_statistics(&self) -> &ChannelStatistics;
    /// XXX : dunno if this is the right approach
    fn get_statistics_mut(&mut self) -> &mut ChannelStatistics;

    /// Annotation related methods
    fn get_annotations(&self) -> &Annotation;
    fn get_annotations_mut(&mut self) -> &mut Annotation;

    fn enter_annotation_scope(&mut self, scope: String);
    fn exit_annotation_scope(&mut self);
    fn disable_annotations(&mut self);
    fn disable_extra_annotations(&mut self);

    /// Sets a vector of expected annotations. The Channel will check that the annotations it
    /// generates, match the annotations in this vector. Usually, this vector is the annotations created
    /// by the prover channel).
    fn set_expected_annotations(&mut self, expected_annotations: Vec<String>) {
        self.get_annotations_mut()
            .set_expected_annotations(expected_annotations);
    }

    fn annotate_prover_to_verifier(&mut self, annotation: String, n_bytes: usize) {
        self.get_annotations_mut()
            .annotate_prover_to_verifier(annotation, n_bytes);
    }

    fn annotate_verifier_to_prover(&mut self, annotation: String) {
        self.get_annotations_mut()
            .annotate_verifier_to_prover(annotation)
    }

    fn annotations_enabled(&self) -> bool {
        self.get_annotations().annotations_enabled()
    }

    fn extra_annotations_disabled(&self) -> bool {
        self.get_annotations().extra_annotations_disabled()
    }

    fn add_annotation(&mut self, annotation: String) {
        self.get_annotations_mut().add_annotation(annotation);
    }
}

/// XXX : Display methods needs to be refactored
struct ChannelWrapper<'a, T: Channel>(&'a T);

impl<T: Channel> fmt::Display for ChannelWrapper<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get_annotations())?;

        writeln!(f, "\nProof Statistics:\n")?;
        write!(f, "{}", self.0.get_statistics())?;

        Ok(())
    }
}

trait ChannelDisplay: Channel {
    fn display(&self) -> ChannelWrapper<'_, Self>
    where
        Self: Sized,
    {
        ChannelWrapper(self)
    }
}

impl<T: Channel> ChannelDisplay for T {}
