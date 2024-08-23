// use ark_ff::Field;
// use std::sync::Arc;

// use crate::parameters::FriProverConfig;
// use crate::FftBases;

// #[allow(dead_code)]
// pub trait FriLayer {
//     type Field: Field;

//     fn layer_size(&self) -> u64;
//     fn chunk_size(&self) -> u64;
//     fn make_storage(&self) -> Box<dyn Storage>;
//     fn get_chunk(
//         &self,
//         storage: &mut dyn Storage,
//         requested_size: usize,
//         chunk_index: usize,
//     ) -> Vec<Self::Field>;
//     fn eval_at_points(&self, required_indices: &[u64]) -> Vec<Self::Field>;
// }

// pub trait Storage {}

// pub struct FriLayerInMemory<F: Field> {
//     domain: Arc<dyn FftBases>,
//     evaluation: Vec<F>,
// }

// impl<F: Field> FriLayer for FriLayerInMemory<F> {
//     type Field = F;

//     fn layer_size(&self) -> u64 {
//         self.domain.size()
//     }

//     fn chunk_size(&self) -> u64 {
//         self.layer_size()
//     }

//     fn make_storage(&self) -> Box<dyn Storage> {
//         Box::new(InMemoryStorage {})
//     }

//     fn get_chunk(
//         &self,
//         storage: &mut dyn Storage,
//         requested_size: usize,
//         chunk_index: usize,
//     ) -> Vec<F> {
//         if requested_size < self.layer_size() as usize {
//             let start = chunk_index * requested_size;
//             self.evaluation[start..start + requested_size].to_vec()
//         } else {
//             self.evaluation.clone()
//         }
//     }

//     fn eval_at_points(&self, required_indices: &[u64]) -> Vec<F> {
//         required_indices
//             .iter()
//             .map(|&i| self.evaluation[i as usize])
//             .collect()
//     }
// }

// pub struct FriLayerOutOfMemory<F: Field> {
//     coset_offsets: Vec<F>,
//     coset_size: usize,
//     coset_bases: Arc<dyn FftBases>,
//     lde_manager: Option<LdeManager>,
//     evaluation: Option<Vec<F>>,
//     is_evaluation_moved: bool,
// }

// impl<F: Field> FriLayer for FriLayerOutOfMemory<F> {
//     type Field = F;

//     fn layer_size(&self) -> u64 {
//         self.coset_bases.size()
//     }

//     fn chunk_size(&self) -> u64 {
//         self.coset_size as u64
//     }

//     fn make_storage(&self) -> Box<dyn Storage> {
//         Box::new(OutOfMemoryStorage::<F>::new())
//     }

//     fn get_chunk(
//         &self,
//         storage: &mut dyn Storage,
//         requested_size: usize,
//         chunk_index: usize,
//     ) -> Vec<Self::Field> {
//         assert!(
//             storage.is_some()
//                 && requested_size <= self.coset_size
//                 && chunk_index < self.layer_size() / self.chunk_size(),
//             "Bad parameters for FriLayerOutOfMemory::get_chunk"
//         );

//         if chunk_index == 0 && !self.is_evaluation_moved {
//             return self.evaluation.as_ref().unwrap()[..requested_size].to_vec();
//         }

//         self.init_lde_manager();
//         // TODO : cast out of memory storage to the specific type
//         let out_of_mem_storage = storage as &mut OutOfMemoryStorage<F>;

//         if out_of_mem_storage.accumulation.is_none() {
//             out_of_mem_storage.accumulation = Some(vec![F::zero(); self.chunk_size() as usize]);
//         }

//         self.lde_manager.as_ref().unwrap().eval_on_coset(
//             &self.coset_offsets[chunk_index],
//             &mut out_of_mem_storage.accumulation.as_mut().unwrap(),
//         );

//         out_of_mem_storage.accumulation.as_ref().unwrap()[..requested_size].to_vec()
//     }

//     fn eval_at_points(&self, required_indices: &[u64]) -> Vec<Self::Field> {
//         let mut res = vec![F::zero(); required_indices.len()];
//         let mut points = Vec::with_capacity(required_indices.len());

//         for &index in required_indices {
//             points.push(self.coset_bases.get_field_element_at(index));
//         }

//         self.init_lde_manager();
//         self.lde_manager
//             .as_ref()
//             .unwrap()
//             .eval_at_points(0, &points, &mut res);

//         res
//     }
// }

// impl<F: Field> FriLayerOutOfMemory<F> {
//     pub fn new(prev_layer: Arc<dyn FriLayer<Field = F>>, coset_size: usize) -> Self {
//         let domain = prev_layer.domain().clone();
//         let mut evaluation = vec![F::zero(); coset_size];
//         prev_layer.get_chunk(
//             &mut Box::new(InMemoryStorage {}),
//             coset_size,
//             0,
//             &mut evaluation,
//         );

//         let mut layer = Self {
//             coset_offsets: Vec::new(),
//             coset_size,
//             coset_bases: domain.clone(),
//             lde_manager: None,
//             evaluation: Some(evaluation),
//             is_evaluation_moved: false,
//         };
//         layer.build();
//         layer
//     }

//     pub fn from_evaluation(evaluation: Vec<F>, domain: Arc<dyn FftBases>) -> Self {
//         let mut layer = Self {
//             coset_offsets: Vec::new(),
//             coset_size: evaluation.len(),
//             coset_bases: domain,
//             lde_manager: None,
//             evaluation: Some(evaluation),
//             is_evaluation_moved: false,
//         };
//         layer.build();
//         layer
//     }

//     fn build(&mut self) {
//         let (coset_bases, coset_offsets) = split_to_cosets(&self.coset_bases, self.chunk_size());
//         self.coset_bases = coset_bases;
//         self.coset_offsets = coset_offsets;
//     }

//     fn init_lde_manager(&mut self) {
//         if self.lde_manager.is_some() {
//             return;
//         }
//         let first_bases = self
//             .coset_bases
//             .get_shifted_bases_as_unique_ptr(&self.coset_offsets[0]);
//         self.lde_manager = Some(LdeManager::new(first_bases));
//         self.lde_manager
//             .as_mut()
//             .unwrap()
//             .add_evaluation(self.evaluation.take().unwrap());
//         self.is_evaluation_moved = true;
//     }

//     fn get_precomputed_fft(
//         &self,
//         storage: &mut dyn Storage,
//         chunk_index: usize,
//     ) -> &FftWithPrecomputeBase {
//         // TODO : cast out of memory storage to the specific type
//         let out_of_mem_storage = storage as &mut OutOfMemoryStorage<F>;

//         if out_of_mem_storage.precomputed_fft.is_none() {
//             self.init_lde_manager();
//             out_of_mem_storage.precomputed_fft = Some(
//                 self.lde_manager
//                     .as_ref()
//                     .unwrap()
//                     .fft_precompute(&self.coset_offsets[0]),
//             );
//         }

//         if chunk_index > 0 {
//             out_of_mem_storage
//                 .precomputed_fft
//                 .as_mut()
//                 .unwrap()
//                 .shift_twiddle_factors(
//                     &self.coset_offsets[chunk_index],
//                     &self.coset_offsets[chunk_index - 1],
//                 );
//         }

//         out_of_mem_storage.precomputed_fft.as_ref().unwrap()
//     }
// }

// pub struct FriLayerProxy<F: Field> {
//     folder: Arc<dyn FriFolderBase>,
//     prev_layer: Arc<dyn FriLayer<Field = F>>,
//     eval_point: F,
//     fri_prover_config: Arc<FriProverConfig>,
//     coset_bases: Arc<dyn FftBases>,
//     coset_offsets: Vec<F>,
//     chunk_size: u64,
// }

// impl<F: Field> FriLayer for FriLayerProxy<F> {
//     type Field = F;

//     fn layer_size(&self) -> u64 {
//         self.coset_bases.size()
//     }

//     fn chunk_size(&self) -> u64 {
//         self.chunk_size
//     }

//     fn make_storage(&self) -> Box<dyn Storage> {
//         Box::new(ProxyStorage::new(self.chunk_size as usize))
//     }

//     fn get_chunk(
//         &self,
//         storage: &mut dyn Storage,
//         requested_size: usize,
//         chunk_index: usize,
//     ) -> Vec<Self::Field> {
//         let proxy_storage = storage.downcast_mut::<ProxyStorage<F>>().unwrap();
//         let mut output = vec![F::zero(); requested_size];
//         self.get_chunk_into(proxy_storage, &mut output, requested_size, chunk_index);
//         output
//     }

//     fn eval_at_points(&self, required_indices: &[u64]) -> Vec<Self::Field> {
//         panic!("Should never be called");
//     }
// }

// impl<F: Field> FriLayerProxy<F> {
//     pub fn new(
//         folder: Arc<dyn FriFolderBase>,
//         prev_layer: Arc<dyn FriLayer<Field = F>>,
//         eval_point: F,
//         fri_prover_config: Arc<FriProverConfig>,
//     ) -> Self {
//         let coset_bases = Self::fold_domain(prev_layer.domain());
//         let chunk_size = Self::calculate_chunk_size(&fri_prover_config);
//         let (coset_bases, coset_offsets) = split_to_cosets(&coset_bases, chunk_size);

//         Self {
//             folder,
//             prev_layer,
//             eval_point,
//             fri_prover_config,
//             coset_bases,
//             coset_offsets,
//             chunk_size,
//         }
//     }

//     fn fold_domain(domain: &Arc<dyn FftBases>) -> Arc<dyn FftBases> {
//         domain.from_layer_as_arc(1)
//     }

//     fn calculate_chunk_size(fri_prover_config: &FriProverConfig) -> u64 {
//         let not_split = prev_layer_chunk_size == prev_layer_size;
//         if not_split && prev_layer_size > fri_prover_config.max_non_chunked_layer_size {
//             std::cmp::max(
//                 fri_prover_config.max_non_chunked_layer_size,
//                 prev_layer_size / fri_prover_config.n_chunks_between_layers,
//             )
//         } else {
//             prev_layer_chunk_size / 2
//         }
//     }

//     fn get_chunk_into(
//         &self,
//         storage: &mut ProxyStorage<F>,
//         output: &mut [F],
//         requested_size: usize,
//         chunk_index: usize,
//     ) {
//         let chunk_domain = self
//             .coset_bases
//             .get_shifted_bases_as_unique_ptr(&self.coset_offsets[chunk_index]);
//         assert_eq!(
//             requested_size as u64, self.chunk_size,
//             "requested_size is different than chunk_size"
//         );

//         let mut prev_storage = self.prev_layer.make_storage();
//         let prev_chunk =
//             self.prev_layer
//                 .get_chunk(&mut *prev_storage, requested_size * 2, chunk_index);

//         self.folder.compute_next_fri_layer(
//             chunk_domain.at(0),
//             &prev_chunk,
//             &self.eval_point,
//             output,
//         );
//     }
// }

// struct ProxyStorage<F: Field> {
//     accumulation: Vec<F>,
// }

// impl<F: Field> ProxyStorage<F> {
//     fn new(size: usize) -> Self {
//         Self {
//             accumulation: vec![F::zero(); size],
//         }
//     }
// }

// struct OutOfMemoryStorage<F: Field> {
//     accumulation: Option<Vec<F>>,
//     precomputed_fft: Option<FftWithPrecomputeBase>,
// }

// impl<F: Field> OutOfMemoryStorage<F> {
//     fn new() -> Self {
//         Self {
//             accumulation: None,
//             precomputed_fft: None,
//         }
//     }
// }

// // 추가로 필요한 구조체와 트레이트
// struct LdeManager;
// struct FftWithPrecomputeBase;
// struct InMemoryStorage;
// pub trait FriFolderBase {
//     fn compute_next_fri_layer<F: Field>(
//         &self,
//         domain_element: F,
//         prev_layer_chunk: &[F],
//         eval_point: &F,
//         output: &mut [F],
//     );
// }

// impl Storage for InMemoryStorage {}
// impl<F: Field> Storage for OutOfMemoryStorage<F> {}
// impl<F: Field> Storage for ProxyStorage<F> {}
