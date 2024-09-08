use blsful::inner_types::*;
use serde::{Deserialize, Serialize};

use crate::{MembershipProof, SECURITY_BYTES};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomStructForMembershipProof {
    pub proof: MembershipProof,
    pub challenge: [u8; 2*SECURITY_BYTES],
}

impl CustomStructForMembershipProof {
    pub fn new(proof: MembershipProof, challenge: [u8; 2*SECURITY_BYTES]) -> Self {
        CustomStructForMembershipProof {
            proof: proof,
            challenge: challenge,
        }
    }
}
