use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ExistingVotes {
    pub el_gamal_pks: Vec<BigUint>,
    pub alphas: Vec<BigUint>,
    pub nonce_vec: Vec<BigUint>,
    pub casted_votes: Vec<BigUint>,
}