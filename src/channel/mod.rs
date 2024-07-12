use ark_ff::Field;

#[derive(Default)]
struct Annotation {
    scope: Vec<String>,
    annotations: Vec<String>,
    annotations_enabled: bool,
    extra_annotations_enabled: bool,
    prover_to_verifier_bytes: usize,
    expected_annotations: Option<Vec<String>>,
    annotation_prefix: String,
}

impl Annotation {
    /// Call this function every time that the annotation scope is updated to recalculate the prefix to
    /// be added to annotations. It takes all annotation scopes in the annotation_scope_ vector and
    /// concatenates them with "/" delimiters.
    fn update_annotation_prefix(&mut self) {
        self.annotation_prefix = self
            .scope
            .iter()
            .fold(String::new(), |acc, s| acc + "/" + s)
            + ": ";
    }

    fn add_annotation(&mut self, annotation: String) {
        if self.annotations_enabled {
            self.annotations.push(annotation);
        }
    }

    fn annotate_prover_to_verifier(&mut self, annotation: String, n_bytes: usize) {
        let start = self.prover_to_verifier_bytes;
        self.prover_to_verifier_bytes += n_bytes;
        let end = self.prover_to_verifier_bytes;

        self.add_annotation(format!(
            "P->V[{}:{}]: {}{}\n",
            start, end, self.annotation_prefix, annotation
        ));
    }

    fn annotate_verifier_to_prover(&mut self, annotation: String) {
        self.add_annotation(format!("V->P: {}{}\n", self.annotation_prefix, annotation));
    }
}

#[allow(dead_code)]
trait Channel {
    type Field: Field;

    fn recv_felts(&mut self, n: usize) -> Result<Vec<Self::Field>, anyhow::Error>;

    fn recv_bytes(&mut self, n: usize) -> Result<Vec<u8>, anyhow::Error>;

    fn random_number(&mut self, bound: u64) -> u64;

    fn random_field(&mut self) -> Self::Field;

    fn apply_proof_of_work(&mut self, security_bits: usize);

    fn begin_query_phase(&mut self);

    fn enter_annotation_scope(&mut self, scope: String);
    fn exit_annotation_scope(&mut self);
    fn disable_annotations(&mut self);
    fn disable_extra_annotations(&mut self);
    fn extra_annotations_disabled(&self) -> bool;
    fn set_expected_annotations(&mut self, expected_annotations: Vec<String>);

    fn get_annotations(&self) -> &Vec<String>;
    fn get_annotations_mut(&mut self) -> &mut Annotation;

    fn annotate_prover_to_verifier(&mut self, annotation: String, n_bytes: usize) {
        self.get_annotations_mut().annotate_prover_to_verifier(annotation, n_bytes);
    }

    fn annotate_verifier_to_prover(&mut self, annotation: String) {
        self.get_annotations_mut().annotate_verifier_to_prover(annotation)
    }
}
