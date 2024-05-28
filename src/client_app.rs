#![allow(dead_code)]
use std::fs;
use num_bigint::{BigUint};
use crate::crypto_schemes::el_gamal::{ElGamalCipher, ElGamalSigner, Encryption, Signature};
use crate::crypto_schemes::paillier::{Cipher, PaillierCipher};

use crate::configs::client::ClientConfig;
use crate::data::{MessageType, VoteData};
use crate::crypto_schemes::bigint::{BetterFormattingVec, UsefulConstants};
use env_logger::{Builder, Target};
use futures_util::{future, pin_mut, SinkExt, StreamExt};
use log::{error, info, warn};
use log::LevelFilter::Info;
use rsa::Oaep;
use rsa::sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use crate::data::MessageType::{EncryptedVote};
use crate::utils::base_three::{BaseTen};

mod crypto_schemes;
mod utils;
mod data;
mod configs;
type ElGamalKeyPair = crate::crypto_schemes::el_gamal::KeyPair;

const M: u64 = 10;
#[tokio::main]
async fn main() {
    let mut builder = Builder::new();
    builder.filter(None,Info);
    builder.target(Target::Stdout);

    builder.init();

    let client_config: ClientConfig = serde_json::from_slice(fs::read("client_config.json").unwrap_or_else(|e| { error!("Failed to open client_config.json"); panic!("{}", e) } ).as_slice()).unwrap();
    // To encrypt we don't need a share or delta
    let paillier_cipher = PaillierCipher::init_from(&client_config.paillier_pk, &BigUint::zero(), 0);
    let elgamal_signer = ElGamalSigner::from(client_config.el_gamal_components.clone(), client_config.el_gamal_kp.clone());
    let mut elgamal_cipher: ElGamalCipher = ElGamalCipher::from(client_config.el_gamal_components, client_config.el_gamal_kp.clone());
    let url = url::Url::parse("ws://127.0.0.1:8001").unwrap();

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();


    let (ws_stream, _) = connect_async(url).await.unwrap_or_else(|e| { error!("Failed to connect"); panic!("{}", e) });
    info!("WebSocket handshake has been successfully completed");
    let (mut write, mut read) = ws_stream.split();
    let cert = serde_json::from_slice(
        fs::read("certificate.json").unwrap_or_else(|e| { error!("Failed to open certificate.json"); panic!("{}", e) })
            .as_slice())
        .unwrap_or_else(|e| { error!("Malformed certificate file."); panic!("{}", e) });
    let msg = MessageType::Certificate(cert);

    let _ = write.send(Message::from(serde_json::to_string(&msg).unwrap_or_else(|e| { error!("Failed to send certificate"); panic!("{}", e) }))).await;
    info!("Certificate sent.");
    let message = read.next().await.unwrap()
        .unwrap_or_else(|e| { error!("Message was malformed"); panic!("{}", e) } );

    let data: MessageType = serde_json::from_str(&message.to_text()
        .unwrap_or_else(|e| {error!("Message was malformed"); panic!("{}", e) }))
        .unwrap_or_else(|e| {error!("Failed to deserialize object"); panic!("{}", e) });
    match data {
        MessageType::EncryptedAlphas(keys_data) => {
            info!("Received encrypted alphas from PEM server: {:?}", keys_data);
            let alphas: Vec<BigUint> = keys_data.encrypted_alphas.into_iter().map(
                |e| elgamal_cipher.decrypt(e).unwrap_or_else(|e| {error!("Failed to decrypt encrypted alphas."); panic!("{:?}", e)})
            ).collect();
            let nonce_vec: Vec<BigUint> = keys_data.encrypted_nonce_vec.into_iter().map(|nonce| {
                let padding = Oaep::new::<Sha256>();
                let dec_data = client_config.client_sk.decrypt(padding, &nonce[..]).expect("failed to decrypt");
                BigUint::from_bytes_be(dec_data.as_slice())
            }).collect();
            info!("Decrypted and obtained original alphas: {:?}", BetterFormattingVec(&alphas));
            info!("Nonces: {:?}", BetterFormattingVec(&nonce_vec));
            info!("Client application is fully setup, you can proceed with voting.");
            print_divider();
            tokio::spawn(read_stdin(stdin_tx,paillier_cipher,elgamal_signer, alphas, nonce_vec));
            let _= write.close().await;
        },
        _ => {warn!("Received unexpected MessageType, program might fail.")}
    }
    let url = url::Url::parse("ws://127.0.0.1:8002").unwrap();
    let (ws_stream, _) = connect_async(url).await.unwrap_or_else(|e| { error!("Failed to connect"); panic!("{}", e) });
    let (write, read) = ws_stream.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = {
        read.for_each(|message| async {
            let data = message.unwrap().into_data();
            tokio::io::stdout().write_all(&data).await.unwrap();
        })
    };

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;

}

async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>, mut paillier_cipher: PaillierCipher, mut el_gamal_signer: ElGamalSigner, alphas: Vec<BigUint>, nonce_vec: Vec<BigUint>) {
    let mut stdin = tokio::io::stdin();
    // Create the candidate pool locally, because we are only demonstrating the principles,
    // normally this would be received from the voting server.
    let mut candidate_pool = utils::candidate::CandidatePool::new();
    candidate_pool.add_candidate("Do you approve the re-election of the following candidate: Marie Novotna to the board of directors?");
    candidate_pool.add_candidate("Do you approve the proposed executive compensation packages for the CEO Jan Cerny - 300k CZK salary plus 1mil CZK in stock options?");
    candidate_pool.add_candidate("Do you approve the proposed dividend payment of 230CZK per share to shareholders for the fiscal year 2023?");
    candidate_pool.add_candidate("Do you approve the proposed merger with StestiAuto a.s., involving a stock exchange of 1.5 shares of our company for each share of StestiAuto a.s.?");

    for i in 0..4 {
        let prompt = candidate_pool.get_candidate(&i).unwrap().statement.clone();
        println!("{}", prompt);
        loop {
            let mut buf = vec![0; 1024];
            let n = match stdin.read(&mut buf).await {
                Err(_) => {
                    error!("Reading stdin failed.");
                    panic!();
                },
                Ok(n) => n,
            };
            buf.truncate(n);
            let mut cmd = String::from_utf8(buf).unwrap();
            cmd.pop();

            match cmd.as_str() {
                "N" | "n" => {
                    candidate_pool.get_candidate(&i).unwrap().vote_no();
                    break;
                },
                "Y" | "y" => {
                    candidate_pool.get_candidate(&i).unwrap().vote_yes();
                    break;
                },
                "A" | "a" => {
                    candidate_pool.get_candidate(&i).unwrap().vote_none();
                    break;
                },
                _ => warn!("Invalid input, valid inputs: (N/n)ot accepting, (Y/y)es, (A/a)bstain."),
            }
            cmd.pop();
        }
    }
    let votes_base_ten = BaseTen::from(candidate_pool.get_base_three_votes()).0;
    // not safe
    let vote = BigUint::from(M).pow(votes_base_ten as u32);

    let vote_messages: Vec<MessageType> = alphas.into_iter().zip(nonce_vec.into_iter()).map(|(alpha, nonce)| {
        let encrypted_vote = paillier_cipher.encrypt(vote.clone());
        let el_gamal_signature = el_gamal_signer.sign_using_alpha(&alpha, nonce.to_string());
        EncryptedVote(VoteData {
            encrypted_vote,
            el_gamal_signature
        })
    }).collect();
    vote_messages.iter().for_each(|vote_message|{tx.unbounded_send(Message::from(serde_json::to_string(&vote_message).unwrap())).unwrap();});
    print_divider();

    let mut buf = vec![0; 1024];
    match stdin.read(&mut buf).await {
        Err(_) => {error!("Reading stdin failed."); panic!();},
        Ok(n) => n,
    };
    tx.unbounded_send(Message::from(serde_json::to_string(&MessageType::DecryptionRequest).unwrap())).unwrap();
}

fn print_divider() {
    let divider = "-".repeat(50);
    println!("{}", divider);
}