use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct ChannelStates {
    pub is_query_phase: bool,
    pub byte_count: usize,
    pub hash_count: usize,
    pub commitment_count: usize,
    pub field_element_count: usize,
    pub data_count: usize,
}

impl ChannelStates {
    pub fn increment_byte_count(&mut self, n: usize) {
        self.byte_count += n;
    }

    pub fn increment_commitment_count(&mut self) {
        self.commitment_count += 1;
    }

    pub fn is_query_phase(&self) -> bool {
        self.is_query_phase
    }

    pub fn begin_query_phase(&mut self) {
        self.is_query_phase = true;
    }

    pub fn increment_hash_count(&mut self) {
        self.hash_count += 1;
    }

    pub fn increment_field_element_count(&mut self, n: usize) {
        self.field_element_count += n;
    }

    pub fn increment_data_count(&mut self) {
        self.data_count += 1;
    }
}

impl fmt::Display for ChannelStates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Byte count: {}\nHash count: {}\nCommitment count: {}\nField element count: {}\nData count: {}\n",
            self.byte_count, self.hash_count, self.commitment_count, self.field_element_count, self.data_count
        )
    }
}
