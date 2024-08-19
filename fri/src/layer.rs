use ark_ff::Field;
use std::sync::Arc;

use crate::FftBases;

#[allow(dead_code)]
pub trait FriLayer {
    type Field: Field;

    fn layer_size(&self) -> u64;
    fn chunk_size(&self) -> u64;
    fn make_storage(&self) -> Box<dyn Storage>;
    fn get_chunk(
        &self,
        storage: &mut dyn Storage,
        requested_size: usize,
        chunk_index: usize,
    ) -> Vec<Self::Field>;
    fn eval_at_points(&self, required_indices: &[u64]) -> Vec<Self::Field>;
}

pub trait Storage {}

pub struct FriLayerInMemory<F: Field> {
    domain: Arc<dyn FftBases>,
    evaluation: Vec<F>,
}

impl<F: Field> FriLayer for FriLayerInMemory<F> {
    type Field = F;

    fn layer_size(&self) -> u64 {
        self.domain.size()
    }

    fn chunk_size(&self) -> u64 {
        self.layer_size()
    }

    fn make_storage(&self) -> Box<dyn Storage> {
        Box::new(InMemoryStorage {})
    }

    fn get_chunk(
        &self,
        _storage: &mut dyn Storage,
        _requested_size: usize,
        _chunk_index: usize,
    ) -> Vec<F> {
        // Implementation here
        vec![]
    }

    fn eval_at_points(&self, required_indices: &[u64]) -> Vec<F> {
        // Implementation here
        vec![]
    }
}

struct InMemoryStorage;

impl Storage for InMemoryStorage {}
