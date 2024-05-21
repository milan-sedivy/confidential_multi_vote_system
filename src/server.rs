// use ws::{listen, Message};
pub mod crypto_schemes;
pub mod data;
use crate::data::{Data, KeysData};
use crate::crypto_schemes::el_gamal::*;

use std::{
    collections::HashSet,
    env,
    io::Error as IoError,
    net::SocketAddr,
};

use futures_channel::mpsc::{unbounded, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};
use num_bigint::BigUint;

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;

type Tx = UnboundedSender<Message>;

pub struct Votes {
    accepted_keys: HashSet<BigUint>,
    encrypted_tally: BigUint,
}
/*
Goals:
Client ---> Encrypted Vote
Encrypted Vote --> Add to tally (check_and_remove_key)
Server ---> add key

*/
impl Votes {
    fn add_vote_to_tally() {}

    pub fn add_key(&mut self, chameleon_key: &BigUint) {
        self.accepted_keys.insert(chameleon_key.clone());
    }

    pub fn add_keys(&mut self, keys_data: &mut KeysData) {
        keys_data.el_gamal_pks.iter().for_each(|key|{
            self.add_key(key);
        });
    }
//Needs to find it based on hash and message
    fn check_and_remove_key(&mut self, message: BigUint, signature: (BigUint, BigUint),) -> bool {
        self.accepted_keys.iter().for_each(|pk| {
            // let el_gamal = ElGamal::from_pk()
        });
        return false;
    }
}

async fn handle_connection(raw_stream: TcpStream, addr: SocketAddr) {
    println!("Incoming TCP connection from: {}", addr);

    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .expect("Error during the websocket handshake occurred");
    println!("WebSocket connection established: {}", addr);

    // Insert the write part of this peer to the peer map.
    let (tx, rx) = unbounded();

    let (outgoing, incoming) = ws_stream.split();

    let broadcast_incoming = incoming.try_for_each(|msg| {
        //println!("Received a message from {}: {}", addr, msg.to_text().unwrap());
        match serde_json::from_str::<Data>(&msg.to_text().unwrap()) {
                    Ok(data) => println!("Received data:\n{:?}\n", data),
                    Err(e) => println!("Could not parse status: {}\n", e)
        }
        future::ok(())
    });

    let receive_from_others = rx.map(Ok).forward(outgoing);

    pin_mut!(broadcast_incoming, receive_from_others);
    future::select(broadcast_incoming, receive_from_others).await;

    println!("{} disconnected", &addr);
}

#[tokio::main]
async fn main() -> Result<(), IoError> {
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:3012".to_string());


    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    println!("Listening on: {}", addr);






    // Let's spawn the handling of each connection in a separate task.
    while let Ok((stream, addr)) = listener.accept().await {
        tokio::spawn(handle_connection(stream, addr));
    }

    Ok(())
}
// fn main() {
//     listen("127.0.0.1:3012", |out| {
//         move |msg: Message| {
//             if let Ok(text) = msg.into_text() {
//                 match serde_json::from_str::<Data>(&text) {
//                     Ok(data) => println!("Received status:\n{:?}\n", data),
//                     Err(e) => println!("Could not parse status: {}\n", e)
//                 }
//             }
//             Ok(())
//         }
//     }).unwrap()
// }