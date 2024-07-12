use std::fmt;

#[derive(Default)]
pub struct ChannelStatistics {
    pub byte_count: usize,
    pub hash_count: usize,
    pub commitment_count: usize,
    pub field_element_count: usize,
    pub data_count: usize,
}

impl fmt::Display for ChannelStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Byte count: {}\nHash count: {}\nCommitment count: {}\nField element count: {}\nData count: {}\n",
            self.byte_count, self.hash_count, self.commitment_count, self.field_element_count, self.data_count
        )
    }
}
