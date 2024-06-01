#![allow(dead_code)]
pub mod crypto_schemes;
mod data;
mod configs;
mod utils;
use crate::data::{EncryptedTally, KeysData, MessageType};
use crate::crypto_schemes::el_gamal::*;
use crate::crypto_schemes::bigint::*;
use std::{env, fs};
use std::collections::HashMap;
use std::io::{Error};
use std::ops::{Div, Rem};
use std::sync::{Arc, Mutex};
use env_logger::{Builder, Target};
use futures_channel::mpsc::{UnboundedSender};
use futures_util::{SinkExt, StreamExt};
use log::{error, info};
use log::LevelFilter::Info;
use num_bigint::BigUint;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use crate::configs::existing_votes::ExistingVotes;
use crate::configs::voting_server::VotingServerConfig;
use crate::crypto_schemes::paillier::{PaillierCombiner};
use crate::utils::base_three::{BaseTen};
use crate::utils::candidate::CandidatePool;

const M: u64 = 10;
type Tx = UnboundedSender<Message>;
#[derive(Clone)]
pub struct SharedVotes {
    el_gamal_verifier: Option<ElGamalVerifier>,
    accepted_keys_with_nonce: HashMap<BigUint,BigUint>,
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
        let accepted_keys_with_nonce = HashMap::<BigUint, BigUint>::new();
        let encrypted_tally = BigUint::zero();
        Self {
            el_gamal_verifier,
            accepted_keys_with_nonce,
            encrypted_tally
        }
    }
    fn add_vote_to_tally() {todo!()}
    pub fn init_verifier(&mut self, components: ElGamalComponents) {
        self.el_gamal_verifier = Some(ElGamalVerifier::from(components));
    }
    pub fn add_key(&mut self, chameleon_key: &BigUint, nonce: &BigUint) {
        self.accepted_keys_with_nonce.insert(chameleon_key.clone(), nonce.clone());
    }

    pub fn add_keys(&mut self, keys_data: &mut KeysData) {
        keys_data.el_gamal_pks.iter().zip(keys_data.nonce_vec.iter()).for_each(|(key, nonce)|{
            self.add_key(key, nonce);
        });
    }
    //Needs to find it based on hash and message performs an exhaustive search.
    fn check_and_remove_key(&mut self, signature: (BigUint, BigUint),) -> bool {
        let mut accepted_key: (bool, BigUint) = (false, BigUint::zero());
        self.accepted_keys_with_nonce.iter().for_each(|(pk, nonce)| {
            if self.el_gamal_verifier.as_mut().unwrap().verify(nonce.clone().to_string(), pk, signature.clone()) {
                accepted_key = (true, pk.clone());
            }
        });
        if accepted_key.0 {
            self.accepted_keys_with_nonce.remove(&accepted_key.1);
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
    let existing_votes: ExistingVotes = serde_json::from_slice(fs::read("existing_votes.json").unwrap_or_else(|e| panic!("{}", e)).as_slice()).unwrap();

    let voting_server_config: VotingServerConfig = serde_json::from_slice(&voting_server_config[..]).unwrap_or_else(|e| { error!("Failed to deserialize voting server config"); panic!("{}", e)});
    let voting_ballot = Arc::new(Mutex::new(SharedVotes::new()));

    // This is here to fake existing votes
    voting_ballot.lock().unwrap().encrypted_tally = existing_votes.casted_votes.iter().product();

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
    let (mut write, mut read) = ws_stream.split();

    while let Some(result) = read.next().await {
        match result {
            Ok(msg) => {
                //println!("Received a message: {}", msg);
                match serde_json::from_str(msg.to_text().unwrap()).unwrap_or(MessageType::Nothing) {
                    MessageType::KeysData(mut e) => {
                        //println!("KeysData: {:?}", e)
                        voting_ballot.lock().unwrap().add_keys(&mut e);
                        //info!("Accepted keys: {:?}", BetterFormattingVec(&voting_ballot.lock().unwrap().accepted_keys_with_nonce.clone().into_iter().collect()));
                        let _ = &voting_ballot.lock().unwrap().accepted_keys_with_nonce.iter().for_each(|(pk, nonce)| {
                           info!("Accepted Key: {:?}, with nonce: {:?}", pk, nonce);
                        });
                    },
                    MessageType::EncryptedVote(e) => {
                        if voting_ballot.lock().unwrap().check_and_remove_key(e.el_gamal_signature.clone()) {
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
                    MessageType::RequestEncryptedTally => {
                        let request = MessageType::DecryptionRequest(EncryptedTally(voting_ballot.lock().unwrap().encrypted_tally.clone()));
                        let message = Message::from(serde_json::to_string(&request).unwrap());
                        info!("Sending tally to key share holders.");
                        let _ = write.send(message).await;
                    }
                    MessageType::DecryptionResponse(decrypted_shares) => {
                        info!("Received decrypted shares, combining.");
                        let mut paillier_combiner = PaillierCombiner::init_from(&voting_server_config.paillier_pk.clone(), voting_server_config.delta.clone());

                        paillier_combiner.add_all_shares(decrypted_shares.0);
                        let mut combined_decryption = paillier_combiner.combine_shares();
                        info!("Combined decrypted shares: {:?}",combined_decryption);
                        calculate_votes(&mut combined_decryption);

                        info!("Voting has successfully finished.");
                        let _= write.close().await;
                        std::process::exit(0);
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
//this function is hardcoded for 4 candidates where each candidate has 3 possible types of votes (Y/N/A)
fn calculate_votes(combined: &mut BigUint) {
    let mut candidate_pool = CandidatePool::new();
    candidate_pool.add_candidate("Do you approve the re-election of the following candidate: Marie Novotna to the board of directors?");
    candidate_pool.add_candidate("Do you approve the proposed executive compensation packages for the CEO Jan Cerny - 300k CZK salary plus 1mil CZK in stock options?");
    candidate_pool.add_candidate("Do you approve the proposed dividend payment of 230CZK per share to shareholders for the fiscal year 2023?");
    candidate_pool.add_candidate("Do you approve the proposed merger with StestiAuto a.s., involving a stock exchange of 1.5 shares of our company for each share of StestiAuto a.s.?");
    for current_exponent in (0..=80).rev() {
        let div = BigUint::from(M).pow(current_exponent as u32);
        let times = combined.clone().div(&div).to_bytes_be().as_slice().try_into().unwrap();
        let replace = combined.clone().rem(&div);
        *combined = replace;
        (0..u8::from_be_bytes(times)).for_each(|_|{  candidate_pool.cast_encoded_votes(BaseTen(current_exponent as u64)); });
    }
    println!("===================RESULTS===================");
    println!("{:?}", candidate_pool.get_candidate(&0u8).unwrap());
    println!("{:?}", candidate_pool.get_candidate(&1u8).unwrap());
    println!("{:?}", candidate_pool.get_candidate(&2u8).unwrap());
    println!("{:?}", candidate_pool.get_candidate(&3u8).unwrap());
    println!("=============================================");
}