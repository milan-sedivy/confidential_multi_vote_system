use std::{env, fs};
use std::io::Error;
use env_logger::{Builder, Target};
use futures_util::{SinkExt, StreamExt};
use log::{error, info};
use log::LevelFilter::Info;
use num_bigint::BigUint;
use tokio::io::AsyncReadExt;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use cryptographic_system::configs::voting_server::VotingServerConfig;
use cryptographic_system::crypto_schemes::paillier::{Cipher, PaillierCipher};
use cryptographic_system::data::{DecryptedShares, MessageType};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut builder = Builder::new();
    builder.filter(None,Info);
    builder.target(Target::Stdout);

    builder.init();


    // Shares are already within the voting_server_config so we'll use that
    let voting_server_config: VotingServerConfig = serde_json::from_slice(fs::read("voting_server_config.json").expect("Failed to read voting_server_config.json").as_slice()).unwrap();
    let mut paillier_share_holders: Vec<PaillierCipher> = Vec::<PaillierCipher>::new();
    voting_server_config.paillier_sk_shares.iter().for_each( |share| {
        paillier_share_holders.push(PaillierCipher::init_from(&voting_server_config.paillier_pk, share, voting_server_config.delta.clone()));
    });

    let voting_app_url = env::args().nth(2).unwrap_or_else(|| "ws://127.0.0.1:8002".to_string());

    let mut stdin = tokio::io::stdin();


    let (ws_stream, _) = connect_async(voting_app_url).await.unwrap_or_else(|e| { error!("Failed to connect"); panic!("{}", e) });
    info!("WebSocket handshake has been successfully completed");
    let (mut write, mut read) = ws_stream.split();

    println!("---------------------------------------------------------------");
    println!("To begin the process and request the encrypted tally hit enter.");
    println!("---------------------------------------------------------------");

    let mut buf = vec![0; 1024];
    let _n = match stdin.read(&mut buf).await {
        Err(_) => {
            error!("Reading stdin failed.");
            panic!();
        },
        Ok(n) => n,
    };
    info!("Waiting for encrypted tally.");
    let request = MessageType::RequestEncryptedTally;
    let msg = Message::from(serde_json::to_string(&request).unwrap());
    let _ = write.send(msg).await;

    let Some(Ok(response)) = read.next().await else {panic!("Failed to read incoming message.")};

    if let MessageType::DecryptionRequest(encrypted_tally) = serde_json::from_str(response.to_text().unwrap()).unwrap() {
        info!("Encrypted tally received");
        let mut decrypted_shares = Vec::<BigUint>::new();
        paillier_share_holders.iter_mut().for_each(|cipher_engine| {
            decrypted_shares.push(cipher_engine.decrypt_share(encrypted_tally.0.clone()));
            info!("Share decrypted");
        });
        info!("Sending shares back to voting server for combining.");
        let response = MessageType::DecryptionResponse(DecryptedShares(decrypted_shares));
        let msg = Message::from(serde_json::to_string(&response).unwrap());
        let _ = write.send(msg).await;
    }
    let _ = write.close().await;
    Ok(())
}

