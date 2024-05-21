use std::env;
use std::io::Error;
use env_logger::{Builder, Target};
use log::info;
use futures_util::{future, SinkExt, StreamExt, TryStreamExt};
use tokio::fs::write;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;
pub mod data;
pub mod crypto_schemes;
use crate::data::*;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);

    builder.init();

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
        tokio::spawn(accept_connection(stream, stdin_tx.clone()));
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

async fn accept_connection(stream: TcpStream, tx: futures_channel::mpsc::UnboundedSender<Message>) {
    let addr = stream.peer_addr().expect("connected streams should have a peer address");
    println!("Peer address: {}", addr);

    let mut ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    println!("New WebSocket connection: {}", addr);
    let msg = Message::from("Hello world");
    let (write, mut read) = ws_stream.split();

    while let Some(result) = read.next().await {
        match result {
            Ok(msg) => {
                println!("Received a message: {}", msg);
                match serde_json::from_str(msg.to_text().unwrap()).unwrap() {
                    MessageType::ElGamalData(e) => {println!("{}", e.g)},
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
