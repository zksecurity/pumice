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

    /// Only relevant for non-interactive channels. Changes the channel seed to a "safer" seed.
    /// 
    /// This function guarantees that randomness fetched from the channel after calling this function
    /// and before sending data from the prover to the channel, is "safe": A malicious
    /// prover will have to perform 2^security_bits operations for each attempt to randomize the fetched
    /// randomness.
    /// 
    /// Increases the amount of work a malicious prover needs to perform, in order to fake a proof.
    fn apply_proof_of_work(&mut self, security_bits: usize);

    fn begin_query_phase(&mut self);

    /// Channel statistics related methods
    fn get_statistics(&self) -> &ChannelStatistics;
    /// XXX : dunno if this is the right approach
    fn get_statistics_mut(&mut self) -> &mut ChannelStatistics;

    /// Annotation related methods
    fn get_annotations(&self) -> &Annotation;
    fn get_annotations_mut(&mut self) -> &mut Annotation;

    fn enter_annotation_scope(&mut self, scope: String) {
        self.get_annotations_mut().enter_annotation_scope(scope);
    }

    fn exit_annotation_scope(&mut self) {
        self.get_annotations_mut().exit_annotation_scope();
    }

    fn disable_annotations(&mut self) {
        self.get_annotations_mut().annotations_enabled = false;
    }

    fn disable_extra_annotations(&mut self) {
        self.get_annotations_mut().extra_annotations_enabled = false;
    }

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
        self.get_annotations().annotations_enabled
    }

    fn extra_annotations_enabled(&self) -> bool {
        self.get_annotations().extra_annotations_enabled
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
