//Goal of this bin is to create the necessary files for the application:
// - ElGamalComponents ------------- (client_cfg.json, certificate.json)
// - ElGamalKeyPair ---------------- (client_cfg.json, pk in certificate.json)
// - Signing/Verifying key --------- (certificate.json, only verifying key)
// - Certificate ------------------- (certificate.json)
// - PEM encryption key ------------ (pem_cfg.json)
// - Client encrypt/decrypt keys --- (client_cfg.json)

mod crypto_schemes;
mod configs;
use std::fmt::Debug;
use std::fs;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
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
    let client_rsa_sk = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let client_rsa_pk = RsaPublicKey::from(&client_rsa_sk);
    let pem_rsa_sk = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pem_rsa_pk = RsaPublicKey::from(&pem_rsa_sk);


    let client_config: ClientConfig = ClientConfig {
        paillier_pk,
        el_gamal_kp: el_gamal_kp.clone(),
        el_gamal_components,
        pem_rsa_pk: pem_rsa_pk.clone(),
        client_rsa_pk: client_rsa_pk.clone(),
        client_rsa_sk: client_rsa_sk.clone(),
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
    let encrypted_subj_data = client_rsa_pk.encrypt(&mut rng, Pkcs1v15Encrypt, serialized_subj_data.as_bytes()).unwrap();

    //test:
    let decrypted = client_rsa_sk.decrypt(Pkcs1v15Encrypt, &encrypted_subj_data).unwrap();
    let deserialized_decrypted_subj_data : SubjData = serde_json::from_slice(&decrypted[..]).unwrap();
    assert_eq!(subj_data, deserialized_decrypted_subj_data, "Testing if original SubjData is equivalent to decrypted/deserialized SubjData");

    let encrypted_der_client_sk = pem_rsa_pk.encrypt(&mut rng, Pkcs1v15Encrypt, client_rsa_sk.to_pkcs1_der().unwrap().as_bytes()).unwrap();
    //let serialized_der_client_sk = serde_json::to_vec(&encrypted_der_client_sk).unwrap();
    // let serialized_client_sk = serde_json::to_string(&client_rsa_sk).unwrap();
    // let encrypted_client_sk = pem_rsa_pk.encrypt(&mut rng, Pkcs1v15Encrypt, serialized_client_sk.as_bytes()).unwrap();
    //test:
    //let deserialized_der_client_sk = serde_json::from_slice(&serialized_der_client_sk[..]).unwrap();//pem_rsa_sk.decrypt(Pkcs1v15Encrypt, &encrypted_client_sk).unwrap();
    let decrypted = pem_rsa_sk.decrypt(Pkcs1v15Encrypt, &encrypted_der_client_sk).unwrap();
    let decrypted_rsa_sk = RsaPrivateKey::from_pkcs1_der(&decrypted).unwrap();
    assert_eq!(client_rsa_sk, decrypted_rsa_sk, "Testing if original ClientSK is equivalent to decrypted/deserialized ClientSK");



    let certificate = MockCertificate {
        certificate: CertificateData {
            data: Data {
                name: "Robert Aliceman".to_string(),
                el_gamal_components,
                encrypted_client_sk: Vec::<u8>::new(), //TODO
                encrypted_subj_data, //TODO
            },
            public_key: Default::default() }, //CA PK
        signature: "".to_string(), // CA signature
    };

}