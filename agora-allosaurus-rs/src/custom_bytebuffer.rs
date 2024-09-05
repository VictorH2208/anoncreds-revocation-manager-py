use blsful::inner_types::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomStructForServerUpdate {
    pub ds: Vec<Scalar>,
    pub vs: Vec<G1Projective>,
}

impl CustomStructForServerUpdate {
    pub fn new() -> Self {
        CustomStructForServerUpdate {
            ds: Vec::new(),
            vs: Vec::new(),
        }
    }

    pub fn add_multiple(&mut self, ds: Vec<Scalar>, vs: Vec<G1Projective>) {
        self.ds.extend(ds);
        self.vs.extend(vs);
    }
}
