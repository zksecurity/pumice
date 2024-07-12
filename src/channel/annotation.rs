use std::fmt;

#[derive(Default)]
pub struct Annotation {
    pub scope: Vec<String>,
    pub annotations: Vec<String>,
    pub annotations_enabled: bool,
    pub extra_annotations_enabled: bool,
    pub prover_to_verifier_bytes: usize,
    pub expected_annotations: Option<Vec<String>>,
    pub annotation_prefix: String,
}

impl Annotation {
    pub fn update_annotation_prefix(&mut self) {
        self.annotation_prefix = self
            .scope
            .iter()
            .fold(String::new(), |acc, s| acc + "/" + s)
            + ": ";
    }

    pub fn add_annotation(&mut self, annotation: String) {
        assert!(
            self.annotations_enabled(),
            "Cannot add annotation when annotations are disabled."
        );
        if let Some(expected_annotations) = &self.expected_annotations {
            let idx = self.annotations.len();
            assert!(
                idx < expected_annotations.len(),
                "Expected annotations is too short."
            );
            let expected_annotation = &expected_annotations[idx];
            assert!(
                expected_annotation == &annotation,
                "Annotation mismatch. Expected annotation: '{}'. Found: '{}'",
                expected_annotation,
                annotation
            );
        }
        self.annotations.push(annotation);
    }

    pub fn annotate_prover_to_verifier(&mut self, annotation: String, n_bytes: usize) {
        let start = self.prover_to_verifier_bytes;
        self.prover_to_verifier_bytes += n_bytes;
        let end = self.prover_to_verifier_bytes;

        self.add_annotation(format!(
            "P->V[{}:{}]: {}{}\n",
            start, end, self.annotation_prefix, annotation
        ));
    }

    pub fn annotate_verifier_to_prover(&mut self, annotation: String) {
        self.add_annotation(format!("V->P: {}{}\n", self.annotation_prefix, annotation));
    }

    pub fn annotations_enabled(&self) -> bool {
        self.annotations_enabled
    }

    pub fn extra_annotations_disabled(&self) -> bool {
        !self.extra_annotations_enabled
    }

    pub fn set_expected_annotations(&mut self, expected_annotations: Vec<String>) {
        self.expected_annotations = Some(expected_annotations);
    }
}

impl fmt::Display for Annotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// XXX : why omitting few bytes??
        let title = &self.annotation_prefix[1..self.annotation_prefix.len() - 2];
        writeln!(f, "title {} Proof Protocol\n", title)?;

        for annotation in &self.annotations {
            writeln!(f, "{}", annotation)?;
        }

        Ok(())
    }
}
