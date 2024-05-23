use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use crate::certificate::ElGamalComponents;

#[derive(Serialize, Deserialize)]
pub struct ClientConfig {
    pub paillier_pk: crate::crypto_schemes::paillier::PublicKey,
    pub el_gamal_kp: crate::crypto_schemes::el_gamal::KeyPair,
    pub el_gamal_components: ElGamalComponents,
    pub pem_rsa_pk: RsaPublicKey,
    pub client_rsa_pk: RsaPublicKey,
    pub client_rsa_sk: RsaPrivateKey, //k
}