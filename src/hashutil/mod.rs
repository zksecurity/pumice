// TODO : Find proper hash libaray
// Digest? hashes
#[allow(dead_code)]
pub trait TempHashContainer {
    fn init_empty() -> Self;

    fn init_digest(data: &Vec<u8>) -> Self;

    fn update(&mut self, data: &Vec<u8>);

    fn hash(&self) -> Vec<u8>;

    fn size() -> usize;
}
