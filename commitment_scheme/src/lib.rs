pub mod merkle;
use std::vec::Vec;

// Define the CommitmentSchemeProver trait
pub trait CommitmentSchemeProver {
    // Return the number of segments
    fn num_segments(&self) -> usize;

    // Return the segment length, measured in elements
    fn segment_length_in_elements(&self) -> usize;

    // Return the size of an element, measured in bytes
    fn element_length_in_bytes(&self) -> usize;

    // Add a segment for commitment
    fn add_segment_for_commitment(&mut self, segment_data: &[u8], segment_index: usize);

    // Commit to the data
    fn commit(&mut self);

    // Start the decommitment phase
    fn start_decommitment_phase(&mut self, queries: Vec<usize>);

    // Decommit to data stored in queried locations
    fn decommit(&mut self, elements_data: &[u8]);
}

// Define the CommitmentSchemeVerifier trait
pub trait CommitmentSchemeVerifier {
    // Read the commitment
    fn read_commitment(&mut self) -> Result<(), anyhow::Error>;

    // Verify the integrity of the data
    fn verify_integrity(&mut self, elements_to_verify: &[(usize, Vec<u8>)]) -> Option<bool>;

    // Return the total number of elements in the current layer
    fn num_of_elements(&self) -> usize;
}
