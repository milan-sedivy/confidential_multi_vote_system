use serde::{Deserialize, Serialize};
use crate::crypto_schemes::el_gamal::ElGamalComponents;

#[derive(Serialize, Deserialize)]
pub struct PemConfig {
    pub el_gamal_components: ElGamalComponents,

}