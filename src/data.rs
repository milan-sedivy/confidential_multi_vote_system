use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use crate::crypto_schemes::el_gamal::ElGamalComponents;
use crate::crypto_schemes::paillier::PublicKey;
use super::configs::certificate::MockCertificate;
//Not used currently, maybe later ... currently we will assume that everyone has already shared their
//secret with the voting server
#[derive(Debug,Serialize, Deserialize)]
pub struct Data {
    pub(crate) public_key: PublicKey,
    pub(crate) secret_share: BigUint,
    pub(crate) delta: u128
}
//To be sent from PEM to the voting_server
#[derive(Debug, Serialize, Deserialize)]
pub struct KeysData {
    pub el_gamal_pks_or_alphas: Vec<BigUint>,
}
//To be sent from the client to the voting_server
#[derive(Debug, Serialize, Deserialize)]
pub struct VoteData {
    pub encrypted_vote: BigUint,
    pub el_gamal_signature: (BigUint, BigUint)
}
#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    EncryptedVote(VoteData), //Sent by client to voting_server
 //   PailierData(Data),
    KeysData(KeysData), //Used by pem_server to communicate with client and voting_server
 //   ElGamalData(ElGamalComponents, BigUint),
    Certificate(MockCertificate), //Sent by client to pem server
    KeyRequest, //Sent by voting_server to pem_server
    GenericMessage(String),
    Nothing 
}

