//Goal of this bin is to create the necessary files for the application:
// - ElGamalComponents ------------- (client_cfg.json, certificate.json)
// - ElGamalKeyPair ---------------- (client_cfg.json, pk in certificate.json)
// - Signing/Verifying key --------- (certificate.json, only verifying key)
// - Certificate ------------------- (certificate.json)
// - PEM encryption key ------------ (pem_cfg.json)
// - Client encrypt/decrypt keys --- (client_cfg.json)

mod crypto_schemes;
mod configs;
use std::fs;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPublicKey};
use rsa::pss::BlindedSigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding};
use crate::crypto_schemes::el_gamal::ElGamalGenerator;
use crate::configs::client::ClientConfig;
use crate::configs::pem::PemConfig;
use crate::configs::voting_server::VotingServerConfig;
use crate::configs::certificate::*;
use crate::crypto_schemes::paillier::{Generator, PaillierGenerator};

fn main() {
    println!("-------------");
    println!("STEP1: Initializing paillier and elgamal generators.");

    let mut paillier_generator = PaillierGenerator::new(3u8);
    let el_gamal_generator = ElGamalGenerator::new();
    let mut rng = rand::thread_rng();
    paillier_generator.create_shares();


    println!("-------------");
    println!("STEP1 - DONE.");
    println!("-------------");


    println!("STEP2: Building configs for applications.");
    // client config
    print!("= Creating client_config.json");
    let paillier_pk = paillier_generator.key_pair.public_key.clone();
    let el_gamal_kp = el_gamal_generator.key_pair;
    let el_gamal_components = el_gamal_generator.components.clone();


    let bits = 2048;

    let pem_rsa_sk = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate PEM private key");
    let pem_rsa_pk = RsaPublicKey::from(&pem_rsa_sk);
    let ca_rsa_private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate CA private key");
    let ca_rsa_sk = BlindedSigningKey::<Sha256>::new(ca_rsa_private_key);
    let ca_rsa_pk = ca_rsa_sk.verifying_key();
    let client_aes_key = Aes256Gcm::generate_key(&mut rng).as_slice().to_owned();
    let nonce = Aes256Gcm::generate_nonce(&mut rng).as_slice().to_owned();

    let client_config: ClientConfig = ClientConfig {
        paillier_pk: paillier_pk.clone(),
        el_gamal_kp: el_gamal_kp.clone(),
        el_gamal_components,
        pem_rsa_pk: pem_rsa_pk.clone(),
        nonce: nonce.clone(),
        client_aes_key: client_aes_key.clone()
    };
    let client_config = serde_json::to_string(&client_config).unwrap();

    fs::write("client_config.json", client_config).expect("Failed to write to client_config.json");
    println!("   ---- DONE");

    // pem config
    print!("= Creating pem_config.json");
    let el_gamal_components = el_gamal_generator.components.clone();
    let pem_config: PemConfig = PemConfig {
        el_gamal_components: el_gamal_components.clone(),
        pem_rsa_sk: pem_rsa_sk.clone(),
    };
    let pem_config = serde_json::to_string(&pem_config).unwrap();

    fs::write("pem_config.json", pem_config).expect("Failed to write to pem_config.json");
    println!("   ---- DONE");
    //voting_server config
    print!("= Creating voting_server_config.json");
    let paillier_sk_shares = paillier_generator.key_pair.get_shares().clone();
    let delta = paillier_generator.delta;
    let voting_server_config = VotingServerConfig {
        el_gamal_components: el_gamal_generator.components,
        paillier_pk,
        paillier_sk_shares,
        delta,
    };
    let voting_server_config = serde_json::to_string(&voting_server_config).unwrap();

    fs::write("voting_server_config.json", voting_server_config).expect("Failed to write to voting_server_config.json");
    println!("   ---- DONE");


    println!("-------------");
    println!("STEP2 - DONE.");
    println!("-------------");



    println!("STEP3 - Building certificate.");
    let subj_data = SubjData { //needs to be encrypted
        share_count: 10,
        el_gamal_public_key: el_gamal_kp.y.clone(),
    };
    let serialized_subj_data = serde_json::to_string(&subj_data).unwrap();
    let aes_cipher = Aes256Gcm::new_from_slice(client_aes_key.clone().as_slice()).unwrap();
    let binding = nonce.clone();
    let aes_nonce = Nonce::from_slice(binding.as_slice());
    let encrypted_subj_data = aes_cipher.encrypt(&aes_nonce, serialized_subj_data.as_bytes()).unwrap();

    //test:
    let decrypted = aes_cipher.decrypt(&aes_nonce, encrypted_subj_data.as_slice()).unwrap();
    let deserialized_decrypted_subj_data : SubjData = serde_json::from_slice(&decrypted[..]).unwrap();

    assert_eq!(subj_data, deserialized_decrypted_subj_data, "Testing if original SubjData is equivalent to decrypted/deserialized SubjData");
    let padding = Oaep::new::<Sha256>();
    let encrypted_nonce = pem_rsa_pk.encrypt(&mut rng, padding, nonce.as_slice()).unwrap();
    let padding = Oaep::new::<Sha256>();
    let encrypted_client_sk = pem_rsa_pk.encrypt(&mut rng, padding, client_aes_key.as_slice()).unwrap();

    let public_key = ca_rsa_pk.to_pkcs1_der().unwrap().as_bytes().to_vec();
    let certificate_data = CertificateData {
        data: Data {
            name: "Robert Aliceman".to_string(),
            el_gamal_components,
            encrypted_nonce,
            encrypted_client_sk,
            encrypted_subj_data,
        },
        public_key // CA PK
    };
    let binding = serde_json::to_string(&certificate_data).unwrap();
    let certificate_to_sign = binding.as_bytes();
    let signature = ca_rsa_sk.sign_with_rng(&mut rng, certificate_to_sign).to_vec();

    let certificate = MockCertificate {
        certificate_data,
        signature, // CA signature
    };
    let certificate = serde_json::to_string(&certificate).unwrap();
    fs::write("certificate.json", certificate).unwrap();

    println!("-------------");
    println!("STEP3 - DONE.");
    println!("-------------");

    println!();
    println!("All configs and the certificate have been successfully generated");
    println!();
    println!("-------------");
}