use std::fs;
use std::ops::DerefMut;
use num_bigint::{BigUint, ToBigInt};
use rand::thread_rng;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::Pkcs1v15Encrypt;
use crate::crypto_schemes::el_gamal::{ElGamalComponents, ElGamalGenerator, ElGamalSigner, Encryption, Signature};
use crate::crypto_schemes::paillier::{Cipher, Combiner, Generator, KeyPair, PaillierCipher, PaillierGenerator, PublicKey};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::client;
use crate::configs::client::ClientConfig;
use crate::data::{Data, MessageType};
use crate::crypto_schemes::bigint::UsefulConstants;

mod crypto_schemes;
mod utils;
mod data;
mod configs;
type ElGamalKeyPair = crate::crypto_schemes::el_gamal::KeyPair;
fn main() {
    let mut rng = thread_rng();
    let client_config: ClientConfig = serde_json::from_slice(fs::read("client_config.json").expect("Failed to open client_config.json").as_slice()).unwrap();
    // To encrypt we don't need a share or delta
    let paillier_cipher = PaillierCipher::init_from(&client_config.paillier_pk, &BigUint::zero(), 0);
    let elgamal_signer = ElGamalSigner::from(client_config.el_gamal_components, client_config.el_gamal_kp.clone());

    let encrypted_elgamal_pk = client_config.pem_rsa_pk.encrypt(&mut rng,Pkcs1v15Encrypt,&client_config.client_rsa_sk.to_pkcs1_der().unwrap().as_bytes());


    use ws::{connect, CloseCode};


    let components: ElGamalComponents = serde_json::from_slice(fs::read("components.json").expect("Failed to open components.json").as_slice()).unwrap();
    let key_pair: ElGamalKeyPair = serde_json::from_slice(fs::read("key_pair.json").expect("Failed to open key_pair.json").as_slice()).unwrap();

    let el_gamal_signer = ElGamalSigner::from(components.clone(),key_pair.clone());

    let el_gamal_data = serde_json::to_string(&MessageType::ElGamalData(components, key_pair.y)).unwrap();


    connect("ws://127.0.0.1:8001", |out| {
        //data_vec.iter().for_each(|e| out.send(serde_json::to_string(e).unwrap()).unwrap());

        let _ = out.send(el_gamal_data.clone());
        move |msg| {
            println!("Got message: {}", msg);
            out.close(CloseCode::Normal)
        }
    }).unwrap();
}