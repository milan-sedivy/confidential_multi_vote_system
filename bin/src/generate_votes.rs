use std::fs;
use num_bigint::BigUint;
use cryptographic_system::configs::client::ClientConfig;
use cryptographic_system::configs::existing_votes::ExistingVotes;
use cryptographic_system::crypto_schemes::el_gamal::{ElGamalCipher, ElGamalGenerator, ElGamalVerifier};
use cryptographic_system::crypto_schemes::paillier::{PaillierCipher, Cipher};
use cryptographic_system::crypto_schemes::bigint::UsefulConstants;
use cryptographic_system::utils::base_three::BaseTen;

const M: u64 = 10;

fn main() {
    //We will use client's config to generate the signatures using the existing components from the other voters
    let client_config: ClientConfig = serde_json::from_slice(fs::read("../../client_config.json").unwrap().as_slice()).unwrap();
    let mut paillier_cipher = PaillierCipher::init_from(&client_config.paillier_pk, &BigUint::zero(), 0);
    let el_gamal = ElGamalGenerator::from(client_config.el_gamal_components.clone());
    let mut el_gamal_cipher = ElGamalCipher::from(client_config.el_gamal_components, el_gamal.key_pair.clone());
    let el_gamal_kp = el_gamal.key_pair.clone();
    let mut el_gamal_verifier = ElGamalVerifier::from(el_gamal.components.clone());

    let (el_gamal_pks, alphas) = el_gamal_verifier.generate_multiple_chameleon_pks(el_gamal_kp.y, 5);
    let mut nonce_vec = Vec::<BigUint>::new();
    (0..5).for_each(|_| nonce_vec.push(el_gamal_cipher.generate_nonce()));
    //let key_data = KeysData { el_gamal_pks, nonce_vec: nonce_vec.clone() };
    let mut candidate_pool = cryptographic_system::utils::candidate::CandidatePool::new();
    (0..4).for_each(|_| candidate_pool.add_candidate(""));

    (0..2).for_each(|i| {
        candidate_pool.get_candidate(&i).as_mut().unwrap().vote_yes();
    });
    (2..4).for_each(|i| {
        candidate_pool.get_candidate(&i).as_mut().unwrap().vote_no();
    });
    let votes_base_ten = BaseTen::from(candidate_pool.get_base_three_votes()).0;
    let vote = BigUint::from(M).pow(votes_base_ten as u32);

    let mut casted_votes: Vec<BigUint> = (0..3).map(|_| {
        let encrypted_vote = paillier_cipher.encrypt(vote.clone());
            encrypted_vote
    }).collect();

    candidate_pool.reset();
    (0..2).for_each(|i| {
        candidate_pool.get_candidate(&i).as_mut().unwrap().vote_no();
    });
    (2..4).for_each(|i| {
        candidate_pool.get_candidate(&i).as_mut().unwrap().vote_yes();
    });
    let votes_base_ten = BaseTen::from(candidate_pool.get_base_three_votes()).0;
    let vote = BigUint::from(M).pow(votes_base_ten as u32);

    let mut additional_casted_votes: Vec<BigUint> = (3..5).map(|_| {
            let encrypted_vote = paillier_cipher.encrypt(vote.clone());
            encrypted_vote
    }).collect();

    casted_votes.append(&mut additional_casted_votes);

    let existing_votes = ExistingVotes {
        el_gamal_pks,
        alphas,
        nonce_vec,
        casted_votes,
    };

    let _= fs::write("../../existing_votes.json", serde_json::to_string(&existing_votes).unwrap());
    println!("Done generating existing_votes.json")
}