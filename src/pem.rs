use std::{env, fs};
use std::io::Error;
use std::sync::{Arc, Mutex};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use env_logger::{Builder, Target};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use num_bigint::BigUint;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pss::{Signature,VerifyingKey};
use rsa::{Oaep, RsaPublicKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;
use crate::configs::certificate::{MockCertificate, SubjData};
use crate::configs::pem::PemConfig;
use crate::crypto_schemes::el_gamal::{ElGamalComponents, ElGamalGenerator, ElGamalVerifier};
mod data;
mod configs;
mod crypto_schemes;
use crate::data::*;
unsafe impl Send for KeyStore {}
#[derive(Clone)]
pub struct KeyStore {
    pub voters_pk: BigUint,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // let mut builder = Builder::from_default_env();
    // builder.target(Target::Stdout);
    //
    // builder.init();

    // Configure the application from pem_config.json
    let pem_config: PemConfig = serde_json::from_slice(fs::read("pem_config.json").expect("Failed to read pem_config.json").as_slice()).unwrap();

    let ws_server_addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8001".to_string());
    let voting_app_addr = env::args().nth(2).unwrap_or_else(|| "ws://127.0.0.1:8002".to_string());
    // Create the event loop and TCP listener we'll accept connections on.
    let voting_app_url = url::Url::parse(&voting_app_addr).unwrap();

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();


    tokio::spawn(communicate_with_voting_app(voting_app_url, stdin_rx));
    let try_socket = TcpListener::bind(&ws_server_addr).await;
    let listener = try_socket.expect("Failed to bind");
    println!("Listening on: {}", ws_server_addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream, stdin_tx.clone(), pem_config.clone()));
    }

    Ok(())
}

async fn communicate_with_voting_app(voting_app_url: Url, mut rx: futures_channel::mpsc::UnboundedReceiver<Message>) {
    let (voting_app_stream, _) = connect_async(voting_app_url).await.expect("Failed to connect to voting app server");
    let (mut voting_app_write, _) = voting_app_stream.split();

    while let Some(message) = rx.next().await {
        // rx.map(Ok).forward(voting_app_write).await?;
        println!("msg to be sent: {}", message);
        voting_app_write.send(message).await;
    }
}

async fn accept_connection(stream: TcpStream, tx: futures_channel::mpsc::UnboundedSender<Message>, pem_config: PemConfig) {
    let addr = stream.peer_addr().expect("connected streams should have a peer address");
    println!("Peer address: {}", addr);

    let mut ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    println!("New WebSocket connection: {}", addr);
    let msg = Message::from("Hello world");
    let (mut write, mut read) = ws_stream.split();

    while let Some(result) = read.next().await {
        match result {
            Ok(msg) => {
                //println!("Received a message: {}", msg);
                if msg.is_empty() { break }
                match serde_json::from_str(msg.to_text().unwrap()).unwrap() {
                    MessageType::Certificate(certificate) => {
                        let certificate_data = certificate.certificate_data.clone();
                        if !certificate_is_valid(certificate) {
                            println!("Invalid certificate. Denying request.");
                            let msg = MessageType::GenericMessage(String::from("Request denied"));
                            let _ = write.send(Message::from(serde_json::to_string(&msg).unwrap())).await;
                            continue;
                        }
                        println!("Certificate is valid. Decrypting.");
                        let padding = Oaep::new::<Sha256>();
                        let pem_sk = pem_config.pem_rsa_sk.clone();
                        let decrypted_nonce = pem_sk.decrypt(
                            padding, certificate_data.data.encrypted_nonce.as_slice()
                        ).unwrap();
                        let nonce = Nonce::from_slice(decrypted_nonce.as_slice());
                        let padding = Oaep::new::<Sha256>();
                        let decrypted_aes_key = pem_sk.decrypt(
                            padding, certificate_data.data.encrypted_client_sk.as_slice()
                        ).unwrap();
                        let aes_cipher = Aes256Gcm::new_from_slice(decrypted_aes_key.as_slice()).unwrap();
                        let serialized_subj_data = aes_cipher.decrypt(nonce, certificate_data.data.encrypted_subj_data.as_slice()).unwrap();
                        let subj_data: SubjData = serde_json::from_slice(serialized_subj_data.as_slice()).unwrap();

                        println!("{:?}", subj_data);
                    },
                    MessageType::ElGamalData(components, pk) => {
                        //temporary for debugging purposes

                        // let (keys_data, alphas_data) = create_el_gamal_keys(components, generator.lock().unwrap().key_pair.y.clone());
                        // let msg = MessageType::KeysData(keys_data);
                        // tx.unbounded_send(Message::from(serde_json::to_string(&msg).unwrap())).unwrap();
                        // let msg = MessageType::KeysData(alphas_data);
                        // let _ = write.send(Message::from(serde_json::to_string(&msg).unwrap())).await;
                    },
                    _ => println!("Something else")
                }
            }
            Err(e) => {
                println!("Error receiving message: {}", e);
                break;
            }
        }
    }

    tx.unbounded_send(msg);

}


// Steps the TPM/PEM will do:


// Verify signature on ceritficate
fn certificate_is_valid(certificate: MockCertificate) -> bool {
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(RsaPublicKey::from_pkcs1_der(&certificate.certificate_data.public_key).unwrap());
    let msg = serde_json::to_string(&certificate.certificate_data).unwrap();
    let signature = Signature::try_from(certificate.signature.as_slice()).unwrap();

    verifying_key.verify(msg.as_bytes(), &signature).is_ok()
}

//Decipher the incoming SubjData using your own key
//Result should be:
// - Obtaining encrypted SK
// - Deciphering SubjData with SK
// - Obtaining ElGamal key (for encryption later on)
fn decipher_subj_data() {
    todo!()
}

// Create alphas and chameleon keys
fn create_el_gamal_keys(components: ElGamalComponents, y: BigUint) -> (KeysData, KeysData) {
    let mut el_gamal_verifier = ElGamalVerifier::from(components);
    let (el_gamal_pks, alphas) = el_gamal_verifier.generate_multiple_chameleon_pks(y, 10);
    (KeysData {
        el_gamal_pks_or_alphas: el_gamal_pks,
    }, KeysData {
        el_gamal_pks_or_alphas: alphas
    })
}

// Encrypt Alphas
fn encrypt_alphas() {
    todo!()
}
