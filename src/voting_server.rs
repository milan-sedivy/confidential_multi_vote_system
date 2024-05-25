#![allow(dead_code)]
pub mod crypto_schemes;
mod data;
mod configs;
use crate::data::{KeysData, MessageType};
use crate::crypto_schemes::el_gamal::*;
use crate::crypto_schemes::bigint::*;
use std::{collections::HashSet, env, fs};
use std::io::Error;
use std::sync::{Arc, Mutex};
use env_logger::{Builder, Target};
use futures_channel::mpsc::{UnboundedSender};
use futures_util::{StreamExt};
use log::{error, info};
use log::LevelFilter::Info;
use num_bigint::BigUint;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use crate::configs::voting_server::VotingServerConfig;
use crate::crypto_schemes::paillier::{PaillierCipher, PaillierCombiner, Cipher};

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
        keys_data.el_gamal_pks.iter().for_each(|key|{
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
    let mut builder = Builder::new();
    builder.filter_level(Info);
    builder.target(Target::Stdout);

    builder.init();
    let voting_server_config = fs::read("voting_server_config.json").unwrap_or_else(|e| { error!("Failed to read voting_server_config.json"); panic!("{}", e)});
    let voting_server_config: VotingServerConfig = serde_json::from_slice(&voting_server_config[..]).unwrap_or_else(|e| { error!("Failed to deserialize voting server config"); panic!("{}", e)});
    let voting_ballot = Arc::new(Mutex::new(SharedVotes::new()));
    voting_ballot.lock().unwrap().init_verifier(voting_server_config.el_gamal_components.clone());

    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8002".to_string());

    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    info!("Listening on: {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(accept_connection(stream, voting_ballot.clone(), voting_server_config.clone()));
    }

    Ok(())
}

async fn accept_connection(stream: TcpStream, voting_ballot: Arc<Mutex<SharedVotes>>, voting_server_config: VotingServerConfig) {
    let addr = stream.peer_addr().expect("connected streams should have a peer address");
    info!("Peer address: {}", addr);

    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    info!("New WebSocket connection: {}", addr);
    let (_write, mut read) = ws_stream.split();

    while let Some(result) = read.next().await {
        match result {
            Ok(msg) => {
                //println!("Received a message: {}", msg);
                match serde_json::from_str(msg.to_text().unwrap()).unwrap_or(MessageType::Nothing) {
                    MessageType::KeysData(mut e) => {
                        //println!("KeysData: {:?}", e)
                        voting_ballot.lock().unwrap().add_keys(&mut e);
                        info!("{:?}", voting_ballot.lock().unwrap().accepted_keys);
                    },
                    MessageType::EncryptedVote(e) => {
                        if voting_ballot.lock().unwrap().check_and_remove_key(e.encrypted_vote.to_string(), e.el_gamal_signature.clone()) {
                            info!("Signature was verified, encrypted vote is accepted.");
                            if voting_ballot.lock().unwrap().encrypted_tally == BigUint::zero() {
                                voting_ballot.lock().unwrap().encrypted_tally = e.encrypted_vote;
                            } else {
                                voting_ballot.lock().unwrap().encrypted_tally *= e.encrypted_vote;
                            }
                        } else {
                            info!("Signature was not accepted!")
                        }
                    },
                    MessageType::DecryptionRequest => {
                        let mut paillier_combiner = PaillierCombiner::init_from(&voting_server_config.paillier_pk.clone(), voting_server_config.delta.clone());

                        let encrypted_tally_copy = voting_ballot.lock().unwrap().encrypted_tally.clone();
                        let shares = voting_server_config.paillier_sk_shares.clone();
                        let decrypted_shares: Vec<BigUint> = shares.iter().map(|share| {
                            let mut paillier_cipher = PaillierCipher::init_from(&voting_server_config.paillier_pk.clone(), share, voting_server_config.delta.clone());
                            paillier_cipher.decrypt_share(encrypted_tally_copy.clone())
                        }).collect();
                        paillier_combiner.add_all_shares(decrypted_shares);
                        info!("Combined decrypted shares: {:?}",paillier_combiner.combine_shares());
                    }
                    _ => {}
                }
            }
            Err(e) => {
                error!("Error receiving message: {}", e);
                break;
            }
        }
    }
}