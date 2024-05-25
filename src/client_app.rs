#![allow(dead_code)]
use std::fs;
use num_bigint::{BigUint};
use rand::thread_rng;
use crate::crypto_schemes::el_gamal::{ElGamalCipher, ElGamalComponents, ElGamalSigner, Encryption};
use crate::crypto_schemes::paillier::{PaillierCipher,};

use crate::configs::client::ClientConfig;
use crate::data::{MessageType,KeysData};
use crate::crypto_schemes::bigint::{BetterFormattingVec, UsefulConstants};
use std::env;
use std::future::Future;
use env_logger::{Builder, Target};
use futures_util::{future, pin_mut, SinkExt, StreamExt};
use log::{error, info, LevelFilter, warn};
use log::LevelFilter::Info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use crate::data::MessageType::GenericMessage;
use crate::utils::base_three::{BaseTen, BaseThree};

mod crypto_schemes;
mod utils;
mod data;
mod configs;
type ElGamalKeyPair = crate::crypto_schemes::el_gamal::KeyPair;
#[tokio::main]
async fn main() {
    let mut builder = Builder::new();//from_default_env();
    builder.filter(None,Info);
    builder.target(Target::Stdout);

    builder.init();

    let mut rng = thread_rng();
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
            info!("Decrypted and obtained original alphas: {:?}", BetterFormattingVec(&alphas));
            info!("Client application is fully setup, you can proceed with voting.");
            let divider = "-".repeat(50);
            println!("{}", divider);
            tokio::spawn(read_stdin(stdin_tx));
        },
        _ => {warn!("Received unexpected MessageType, program might fail.")}
    }

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

async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>) {
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

        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
            Err(_) => {error!("Reading stdin failed."); panic!();},
            Ok(n) => n,
        };
        buf.truncate(n);
        let mut cmd = String::from_utf8(buf).unwrap();
        cmd.pop();
            match cmd.as_str() {
                "N" => { candidate_pool.get_candidate(&i).unwrap().vote_no(); },
                "Y" => { candidate_pool.get_candidate(&i).unwrap().vote_yes(); },
                "0" => { candidate_pool.get_candidate(&i).unwrap().vote_none(); },
                _ => (),
            }

    }
    println!("VoteCount: {:?}", candidate_pool.get_candidate(&1).unwrap().vote_count);
    println!("BaseThree: {}", candidate_pool.get_base_three_votes().get());
    let test = BaseTen::from(candidate_pool.get_base_three_votes());

    println!("TotalVoteCount (base ten): {:?}", test);

    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);
        tx.unbounded_send(Message::from(serde_json::to_string(&GenericMessage(String::from("This is some user input"))).unwrap())).unwrap();
        //tx.unbounded_send(Message::binary(buf)).unwrap();
    }
}
