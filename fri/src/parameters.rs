use ark_ff::{FftField, Field};
use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::FftBases;

//#[derive(Deserialize)]
pub struct FriParameters<F: FftField> {
    /*
      A list of fri_step_i (one per FRI layer). FRI reduction in the i-th layer will be 2^fri_step_i
      and the total reduction factor will be $2^{\sum_i \fri_step_i}$. The size of fri_step_list is
      the number of FRI layers.

      For example, if fri_step_0 = 3, the second layer will be of size N/8 (where N is the size of the
      first layer). It means that the two merkle trees for layers of sizes N/2 and N/4 will be
      skipped. On the other hand, it means that each coset in the first layer is of size 8 instead
      of 2. Also note that in the fri_step_0=1 case we send 2 additional field elements per query (one
      for each of the two layers that we skipped). So, while we send more field elements in the
      fri_step_0=3 case (8 rather than 4), we refrain from sending the authentication paths for the
      two skipped layers.

      For a simple FRI usage, take fri_step_list = {1, 1, ..., 1}.
    */
    pub fri_step_list: Vec<usize>,

    /*
      In the original FRI protocol, one has to reduce the degree from N to 1 by using a total of
      log2(N) fri steps (sum of fri_step_list = log2(N)). This has two disadvantages:
        1. The last layers are small but still require Merkle authentication paths which are
           non-negligible.
        2. It requires N to be of the form 2^n.

      In our implementation, we reduce the degree from N to R (last_layer_degree_bound) for a
      relatively small R using log2(N/R) fri steps. To do it we send the R coefficients of the last
      FRI layer instead of continuing with additional FRI layers.

      To reduce proof-length, it is always better to pick last_layer_degree_bound > 1.
    */
    pub last_layer_degree_bound: u64,
    pub n_queries: usize,
    pub fft_bases: Option<FftBases<F>>,
    pub field: F,

    /*
      If greater than 0, used to apply proof of work right before randomizing the FRI queries. Since
      the probability to draw bad queries is relatively high (~rho for each query), while the
      probability to draw bad x^(0) values is ~1/|F|, the queries are more vulnerable to enumeration.
    */
    pub proof_of_work_bits: usize,
}

impl<F: FftField> FriParameters<F> {
    pub fn from_json(json: &JsonValue, fft_bases: Option<FftBases<F>>, field: F) -> Self {
        FriParameters {
            fri_step_list: json["fri_step_list"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect(),
            last_layer_degree_bound: json["last_layer_degree_bound"].as_u64().unwrap(),
            n_queries: json["n_queries"].as_u64().unwrap() as usize,
            fft_bases,
            field,
            proof_of_work_bits: json["proof_of_work_bits"].as_u64().unwrap() as usize,
        }
    }
}

pub struct FriProverConfig {
    pub max_non_chunked_layer_size: u64,
    pub n_chunks_between_layers: usize,
    pub log_n_max_in_memory_fri_layer_elements: usize,
}

impl FriProverConfig {
    pub const DEFAULT_MAX_NON_CHUNKED_LAYER_SIZE: u64 = 32768;
    pub const DEFAULT_NUMBER_OF_CHUNKS_BETWEEN_LAYERS: usize = 32;
    pub const ALL_IN_MEMORY_LAYERS: usize = 63;
}
