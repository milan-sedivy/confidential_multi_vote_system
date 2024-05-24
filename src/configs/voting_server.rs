use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use crate::crypto_schemes::el_gamal::ElGamalComponents;

#[derive(Serialize, Deserialize)]
pub struct VotingServerConfig {
    pub el_gamal_components: ElGamalComponents,
    pub paillier_sk_shares: Vec<BigUint>,
    pub delta: u128
}
//Maybe add series of accepted encrypted votes and signatures?