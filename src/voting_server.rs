#![allow(dead_code)]
pub mod crypto_schemes;
mod data;
mod configs;
use crate::data::{KeysData, MessageType};
use crate::crypto_schemes::el_gamal::*;
use crate::crypto_schemes::bigint::*;
use std::{
    collections::HashSet,
    env,
};
use std::io::Error;
use std::sync::{Arc, Mutex};
use env_logger::{Builder, Target};
use futures_channel::mpsc::{UnboundedSender};
use futures_util::{StreamExt};
use num_bigint::BigUint;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;

type Tx = UnboundedSender<Message>;
#[derive(Clone)]
pub struct SharedVotes {
    el_gamal_verifier: Option<ElGamalVerifier>,
    accepted_keys: HashSet<BigUint>,
    encrypted_tally: BigUint,
}
/*
Goals:
Client ---> Encrypted Vote
Encrypted Vote --> Add to tally (check_and_remove_key)
Server ---> add key

*/
unsafe impl Send for SharedVotes {}
impl SharedVotes {
    pub fn new() -> Self {
        let el_gamal_verifier = None;
        let accepted_keys = HashSet::<BigUint>::new();
        let encrypted_tally = BigUint::zero();
        Self {
            el_gamal_verifier,
            accepted_keys,
            encrypted_tally
        }
    }
    fn add_vote_to_tally() {todo!()}
    pub fn init_verifier(&mut self, components: ElGamalComponents) {
        self.el_gamal_verifier = Some(ElGamalVerifier::from(components));
    }
    pub fn add_key(&mut self, chameleon_key: &BigUint) {
        self.accepted_keys.insert(chameleon_key.clone());
    }

    pub fn add_keys(&mut self, keys_data: &mut KeysData) {
        keys_data.el_gamal_pks_or_alphas.iter().for_each(|key|{
            self.add_key(key);
        });
    }
    //Needs to find it based on hash and message performs an exhaustive search.
    fn check_and_remove_key(&mut self, message: String, signature: (BigUint, BigUint),) -> bool {
        let mut accepted_key: (bool, BigUint) = (false, BigUint::zero());
        self.accepted_keys.iter().for_each(|pk| {
            if self.el_gamal_verifier.as_mut().unwrap().verify(message.clone(), pk, signature.clone()) {
                accepted_key = (true, pk.clone());
            }
        });
        if accepted_key.0 {
            self.accepted_keys.remove(&accepted_key.1);
            return true;
        }
        return false;
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);

    builder.init();
    let voting_ballot = Arc::new(Mutex::new(SharedVotes::new()));
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8002".to_string());

    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    println!("Listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream, voting_ballot.clone()));
    }

    Ok(())
}

async fn accept_connection(stream: TcpStream, voting_ballot: Arc<Mutex<SharedVotes>>) {
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
                match serde_json::from_str(msg.to_text().unwrap()).unwrap_or(MessageType::Nothing) {
                    MessageType::KeysData(mut e) => {
                        //println!("KeysData: {:?}", e)
                        voting_ballot.lock().unwrap().add_keys(&mut e);
                        println!("{:?}", voting_ballot.lock().unwrap().accepted_keys);
                    },
                    MessageType::ElGamalData(components, pk) => {
                        voting_ballot.lock().unwrap().el_gamal_verifier = Some(ElGamalVerifier::from(components));
                    },
                    MessageType::EncryptedVote(e) => {
                        if voting_ballot.lock().unwrap().check_and_remove_key(e.encrypted_vote.to_string(), e.el_gamal_signature.clone()) {
                            println!("{}", voting_ballot.lock().unwrap().encrypted_tally);
                            if voting_ballot.lock().unwrap().encrypted_tally == BigUint::zero() {
                                voting_ballot.lock().unwrap().encrypted_tally = e.encrypted_vote;
                            } else {
                                voting_ballot.lock().unwrap().encrypted_tally *= e.encrypted_vote;
                            }
                        }
                        println!("{}", voting_ballot.lock().unwrap().encrypted_tally);
                    }
                    _ => {}
                }
            }
            Err(e) => {
                println!("Error receiving message: {}", e);
                break;
            }
        }
    }
}