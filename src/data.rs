use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use crate::crypto_schemes::paillier::PublicKey;

#[derive(Debug,Serialize, Deserialize)]
pub struct Data {
    pub(crate) public_key: PublicKey,
    pub(crate) secret_share: BigUint,
    pub(crate) delta: u128
}
#[derive(Debug, Serialize, Deserialize)]
pub struct KeysData {
    pub el_gamal_pks: Vec<BigUint>,
}