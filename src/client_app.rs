#![allow(dead_code)]
use std::fs;
use num_bigint::{BigUint};
use rand::thread_rng;
use crate::crypto_schemes::el_gamal::{ElGamalComponents, ElGamalSigner};
use crate::crypto_schemes::paillier::{PaillierCipher,};

use crate::configs::client::ClientConfig;
use crate::data::{MessageType,KeysData};
use crate::crypto_schemes::bigint::UsefulConstants;
use std::env;
use env_logger::{Builder, Target};
use futures_util::{future, pin_mut, SinkExt, StreamExt};
use log::{error, info, LevelFilter, warn};
use log::LevelFilter::Info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

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
    let elgamal_signer = ElGamalSigner::from(client_config.el_gamal_components, client_config.el_gamal_kp.clone());

    let url = url::Url::parse("ws://127.0.0.1:8001").unwrap();

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx));

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
        MessageType::KeysData(keys_data) => {
            info!("Received alphas from PEM server: {:?}", keys_data.el_gamal_pks_or_alphas);
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

    // connect("ws://127.0.0.1:8001", |out| {
    //     //data_vec.iter().for_each(|e| out.send(serde_json::to_string(e).unwrap()).unwrap());
    //     let cert = serde_json::from_slice(fs::read("certificate.json").unwrap().as_slice()).unwrap();
    //     let msg = MessageType::Certificate(cert);
    //     out.send(serde_json::to_string(&msg).unwrap()).unwrap();
    //     move |msg| {
    //         println!("Got message: {}", msg);
    //         out.close(CloseCode::Normal)
    //     }
    // }).unwrap();
}

async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>) {
    let mut stdin = tokio::io::stdin();
    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);
        tx.unbounded_send(Message::binary(buf)).unwrap();
    }
}