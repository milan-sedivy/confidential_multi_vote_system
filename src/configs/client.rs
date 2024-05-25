use rsa::{RsaPublicKey};
use serde::{Deserialize, Serialize};
use crate::crypto_schemes::el_gamal::ElGamalComponents;

#[derive(Serialize, Deserialize)]
pub struct ClientConfig {
    pub paillier_pk: crate::crypto_schemes::paillier::PublicKey,
    pub el_gamal_kp: crate::crypto_schemes::el_gamal::KeyPair,
    pub el_gamal_components: ElGamalComponents,
    // not needed as certificate will be generated along with configs (for simplicity because it needs to be signed by a CA anyway)
    // stored only for debugging
    pub pem_rsa_pk: RsaPublicKey,
    pub nonce: Vec<u8>,
    pub client_aes_key: Vec<u8>
}