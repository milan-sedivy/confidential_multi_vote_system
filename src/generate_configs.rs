//Goal of this bin is to create the necessary files for the application:
// - ElGamalComponents ------------- (client_cfg.json, certificate.json)
// - ElGamalKeyPair ---------------- (client_cfg.json, pk in certificate.json)
// - Signing/Verifying key --------- (certificate.json, only verifying key)
// - Certificate ------------------- (certificate.json)
// - PEM encryption key ------------ (pem_cfg.json)
// - Client encrypt/decrypt keys --- (client_cfg.json)

mod certificate;
mod crypto_schemes;
mod configs;
use std::fmt::Debug;
use std::fs;
use rsa::pss::BlindedSigningKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use crate::crypto_schemes::el_gamal::ElGamalGenerator;
use crate::certificate::*;
use crate::configs::client::ClientConfig;
use crate::crypto_schemes::paillier::{Generator, PaillierGenerator};

fn main() {
    let pailier_generator = PaillierGenerator::new(3u8);
    let el_gamal_generator = ElGamalGenerator::new();
    let mut rng = rand::thread_rng();

    // client config
    let paillier_pk = pailier_generator.key_pair.public_key.clone();
    let el_gamal_kp = el_gamal_generator.key_pair;
    let el_gamal_components = el_gamal_generator.components.clone();


    let bits = 2048;
    let client_rsa_sk = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let client_rsa_pk = RsaPublicKey::from(&client_rsa_sk);
    let pem_rsa_sk = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pem_rsa_pk = RsaPublicKey::from(&pem_rsa_sk);


    let client_config: ClientConfig = ClientConfig {
        paillier_pk,
        el_gamal_kp,
        el_gamal_components,,
        pem_rsa_pk,
        client_rsa_pk,
        client_rsa_sk,
    };
    let client_config = serde_json::to_string(&client_config).unwrap();

    fs::write("client_config.json", client_config).expect("Failed to write to client_config.json");

    // pem config
}