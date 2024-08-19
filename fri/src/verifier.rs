use std::error::Error;

#[allow(dead_code)]
pub trait FriVerifier {
    type Field;
    type VerifierChannel;
    type TableVerifierFactory;
    type FriParameters;
    type FirstLayerCallback;

    fn new(
        channel: Box<Self::VerifierChannel>,
        table_verifier_factory: Box<Self::TableVerifierFactory>,
        params: Box<Self::FriParameters>,
        first_layer_queries_callback: Box<Self::FirstLayerCallback>,
    ) -> Self;

    fn verify_fri(&self) -> Result<(), Box<dyn Error>>;

    fn init(&self);

    fn commitment_phase(&self);

    fn read_last_layer_coefficients(&self);

    fn verify_first_layer(&self);

    fn verify_inner_layers(&self);

    fn verify_last_layer(&self);
}
