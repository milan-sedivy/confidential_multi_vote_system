use std::{env, fs};
use std::io::Error;
use std::sync::{Arc, Mutex};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use env_logger::{Builder, Target};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use log::LevelFilter::Info;
use num_bigint::BigUint;
use rand::rngs::{StdRng};
use rand::SeedableRng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pss::{Signature,VerifyingKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;
use crate::configs::certificate::{CertificateData, MockCertificate, SubjData};
use crate::configs::pem::PemConfig;
use crate::crypto_schemes::bigint::{BetterFormattingVec, UsefulConstants};
use crate::crypto_schemes::el_gamal::{ElGamalCipher, ElGamalComponents, ElGamalVerifier, KeyPair, Encryption, EncryptedMessage};
mod data;
mod configs;
mod crypto_schemes;
use crate::data::*;
unsafe impl Send for KeyStore {}
#[derive(Clone)]
pub struct KeyStore {
    pub voters_pk: Vec<BigUint>,
}
impl KeyStore {
    fn new() -> Self { Self {voters_pk: Vec::<BigUint>::new()} }
}
type KS = Arc<Mutex<KeyStore>>;
#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut builder = Builder::new();
    builder.filter(None,Info);
    builder.target(Target::Stdout);

    builder.init();


    // Configure the application from pem_config.json
    let pem_config: PemConfig = serde_json::from_slice(fs::read("pem_config.json").expect("Failed to read pem_config.json").as_slice()).unwrap();
    let key_store: KS = Arc::new(Mutex::new(KeyStore::new()));

    let ws_server_addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8001".to_string());
    let voting_app_addr = env::args().nth(2).unwrap_or_else(|| "ws://127.0.0.1:8002".to_string());
    // Create the event loop and TCP listener we'll accept connections on.
    let voting_app_url = url::Url::parse(&voting_app_addr).unwrap();

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();


    tokio::spawn(communicate_with_voting_app(voting_app_url, stdin_rx));
    let try_socket = TcpListener::bind(&ws_server_addr).await;
    let listener = try_socket.expect("Failed to bind");
    info!("Listening on: {}", ws_server_addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream, stdin_tx.clone(), pem_config.clone(), key_store.clone()));
    }

    Ok(())
}

async fn communicate_with_voting_app(voting_app_url: Url, mut rx: futures_channel::mpsc::UnboundedReceiver<Message>) {
    let (voting_app_stream, _) = connect_async(voting_app_url).await.expect("Failed to connect to voting app server");
    let (mut voting_app_write, _) = voting_app_stream.split();

    while let Some(message) = rx.next().await {
        // rx.map(Ok).forward(voting_app_write).await?;
        info!("Sending data to voting server.");
        let _ = voting_app_write.send(message).await;
    }
}

async fn accept_connection(stream: TcpStream, tx: futures_channel::mpsc::UnboundedSender<Message>, pem_config: PemConfig, key_store: KS) {
    let addr = stream.peer_addr().expect("connected streams should have a peer address");
    info!("Peer address: {}", addr);

    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    info!("New WebSocket connection: {}", addr);
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
                            warn!("Invalid certificate. Denying request.");
                            let msg = MessageType::GenericMessage(String::from("Request denied"));
                            let _ = write.send(Message::from(serde_json::to_string(&msg).unwrap())).await;
                            continue;
                        }
                        let el_gamal_components = certificate_data.data.el_gamal_components.clone();
                        info!("Certificate is valid. Decrypting.");
                        let pem_sk = pem_config.pem_rsa_sk.clone();
                        let subj_data = decipher_subj_data(certificate_data.clone(), pem_sk);

                        debug!("{:?}", subj_data);

                        let mut el_gamal_cipher: ElGamalCipher = ElGamalCipher::from(el_gamal_components.clone(), KeyPair {x: BigUint::zero(), y: subj_data.el_gamal_public_key.clone()});
                        let (mut el_gamal_pks, alphas_data) = create_el_gamal_keys_and_alphas(el_gamal_components, subj_data.el_gamal_public_key.clone(), subj_data.share_count);
                        let nonce_vec: Vec<BigUint> = (0..el_gamal_pks.len()).map(|_| el_gamal_cipher.generate_nonce()).collect();
                        let keys_data = KeysData { el_gamal_pks: el_gamal_pks.clone(), nonce_vec: nonce_vec.clone() };
                        let msg = MessageType::KeysData(keys_data.clone());
                        tx.unbounded_send(Message::from(serde_json::to_string(&msg).unwrap())).unwrap();
                        key_store.lock().unwrap().voters_pk.append(&mut el_gamal_pks);
                        info!("Encrypting alphas using users ElGamal PK: {:?}", BetterFormattingVec(&alphas_data));
                        let encrypted_alphas: Vec<EncryptedMessage> = alphas_data.into_iter().map(|alpha| el_gamal_cipher.encrypt(alpha).unwrap_or_else(|e| {error!("Failed to encrypt alphas."); panic!("{:?}", e)})).collect();

                        let mut rng = StdRng::from_entropy();
                        let encrypted_nonce_vec: Vec<Vec<u8>> = nonce_vec.iter().map(|nonce| {
                            let padding = Oaep::new::<Sha256>();
                            certificate_data.data.client_pk.encrypt(&mut rng, padding, &nonce.to_bytes_be()[..]).expect("failed to encrypt")
                        }).collect();
                        let msg = MessageType::EncryptedAlphas(EncryptedAlphas {encrypted_alphas, encrypted_nonce_vec});
                        info!("Encryption done, sending the following: {:?}", msg);

                        let _ = write.send(Message::from(serde_json::to_string(&msg).unwrap())).await;
                    },
                    _other => info!("MessageType: {:?} received.", _other)
                }
            }
            Err(e) => {
                error!("Error receiving message: {}", e);
                break;
            }
        }
    }
}


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
fn decipher_subj_data(certificate_data: CertificateData, pem_sk: RsaPrivateKey) -> SubjData {
    let padding = Oaep::new::<Sha256>();
    let decrypted_nonce= pem_sk.decrypt(
        padding, certificate_data.data.encrypted_nonce.as_slice()
    ).unwrap();
    let nonce = Nonce::from_slice(decrypted_nonce.as_slice());
    let padding = Oaep::new::<Sha256>();
    let decrypted_aes_key= pem_sk.decrypt(
        padding, certificate_data.data.encrypted_client_sk.as_slice()
    ).unwrap();
    let aes_cipher = Aes256Gcm::new_from_slice(decrypted_aes_key.as_slice()).unwrap();
    let serialized_subj_data = aes_cipher.decrypt(nonce, certificate_data.data.encrypted_subj_data.as_slice()).unwrap();

    serde_json::from_slice::<SubjData>(serialized_subj_data.as_slice()).unwrap()
}

// Create alphas and chameleon keys
fn create_el_gamal_keys_and_alphas(components: ElGamalComponents, y: BigUint, key_count: usize) -> (Vec<BigUint>, Vec<BigUint>) {
    let mut el_gamal_verifier = ElGamalVerifier::from(components);
    let (el_gamal_pks, alphas) = el_gamal_verifier.generate_multiple_chameleon_pks(y, key_count);
    (el_gamal_pks, alphas)
}
