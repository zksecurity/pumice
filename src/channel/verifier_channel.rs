use crate::channel::{Annotations, Channel, ChannelStates};
use anyhow::Error;
use ark_ff::Field;
use std::io::Write;
use std::vec::Vec;

#[derive(Default)]
pub struct VerifierChannel<F: Field> {
    annotations: Annotations,
    state: ChannelStates,
    _field: std::marker::PhantomData<F>,
}

#[allow(dead_code)]
impl<F: Field> Channel for VerifierChannel<F> {
    type Field = F;

    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, Error> {
    }

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
    }

    fn random_number(&mut self, bound: u64) -> u64 {
    }

    fn random_field(&mut self) -> Self::Field {
    }

    fn get_state(&self) -> &ChannelStates {
        &self.state
    }

    fn get_state_mut(&mut self) -> &mut ChannelStates {
        &mut self.state
    }

    fn get_annotations(&self) -> &Annotations {
        &self.annotations
    }

    fn get_annotations_mut(&mut self) -> &mut Annotations {
        &mut self.annotations
    }
}

#[allow(dead_code)]
impl<F: Field> VerifierChannel<F> {
    pub fn get_and_send_random_number(&mut self, upper_bound: u64, annotation: &str) -> u64 {
    }

    pub fn get_and_send_random_field_element(&mut self, annotation: &str) -> F {
    }

    pub fn receive_commitment_hash(&mut self, annotation: &str) -> Vec<u8> {
    }

    pub fn recv_felt(&mut self, annotation: &str) -> F {
    }

    pub fn recv_data(&mut self, num_bytes: usize, annotation: &str) -> Vec<u8> {
    }

    pub fn dump_extra_annotations<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        for annotation in &self.annotations.extra_annotations {
            writeln!(writer, "{}", annotation)?;
        }
        Ok(())
    }

    pub fn annotate_extra_field_element(&mut self, field_element: F, annotation: &str) {
        self.add_extra_annotation(format!("{}: Field Element({})", annotation, field_element));
    }

    fn add_extra_annotation(&mut self, annotation: String) {
        self.annotations.add_extra_annotation(annotation);
    }
}
