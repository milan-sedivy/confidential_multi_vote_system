use std::ops::DerefMut;
use num_bigint::{BigInt, BigUint, ToBigInt};
use sha256::digest;
use crate::crypto_schemes::el_gamal::{Encryption, Signature};
use crate::crypto_schemes::paillier::{Cipher, Combiner, Generator, KeyPair, PaillierCipher, PaillierGenerator, PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Result;
use ws::listen;
use crate::data::Data;

mod crypto_schemes;
mod utils;
pub mod data;


fn main() {
    // let mut el_gamal = crate::crypto_schemes::el_gamal::ElGamal::new();
    // el_gamal.init();
    // let alpha = el_gamal.generate_random();
    // let mut  chameleon = el_gamal.chameleon_from(alpha);
    // let encrypted = chameleon.encrypt(BigUint::from(10u8)).unwrap();
    // let decrypted = chameleon.decrypt(encrypted).unwrap();
    // println!("10 : {decrypted}");
    //
    // let input = String::from("hello world asdasdadsasdasdasdsasdasdasdasdasd");
    // let val = digest(input);
    // let test = val.as_str().as_bytes();
    // let hex = BigUint::parse_bytes(test, 16);
    // println!("{}", val);
    // println!("{}", hex.unwrap());
    // let signature = el_gamal.sign(String::from("Hello"));
    // println!("{}", el_gamal.verify(String::from("Hello"), signature));

    let mut paillier = PaillierGenerator::init(4);
    println!("{:?}", paillier);
    paillier.create_shares();
    let mut paillier_combiner = Combiner::init_from(&paillier.key_pair.public_key, paillier.delta.clone());
    //paillier.key_pair.shares.iter().for_each(|e|)

    let mut cipher_engines: Vec<PaillierCipher> = vec![];
    paillier.key_pair.shares.iter().for_each(|e| cipher_engines.push(PaillierCipher::init_from(&paillier.key_pair.public_key, e, paillier.delta.clone())));
    println!("{:?}", cipher_engines);
    println!("{}", cipher_engines.len());
    let t = BigUint::from(5u8);
    let encrypted = cipher_engines[1].encrypt(t);
    println!("{}", encrypted);
    cipher_engines.iter_mut().for_each(|e| paillier_combiner.add_decrypted_message_share(e.decrypt_share(encrypted.clone())));

    println!("{}", paillier_combiner.combine_shares());
    let mut data_vec: Vec<Data> = vec![];
    paillier.key_pair.shares.iter().for_each(|e| {
        data_vec.push(Data {public_key: paillier.key_pair.public_key.clone(), secret_share: e.clone(), delta: 24});
        //println!("{}", serde_json::to_string(&data).unwrap());
    });
    use ws::{connect, CloseCode};

    connect("ws://127.0.0.1:3012", |out| {
        data_vec.iter().for_each(|e| out.send(serde_json::to_string(e).unwrap()).unwrap());

        move |msg| {
            println!("Got message: {}", msg);
            out.close(CloseCode::Normal)
        }
    }).unwrap()
    // paillier.create_shares(4u8);
    // //let mut shares: Vec<BigUint> = paillier.key_pair.get_shares().clone().iter_mut().map(|e| paillier.decrypt_share(encrypted.clone(),e.clone())).collect();
    // println!("c (encrypted): {}", encrypted);
    // println!("Individual shares: {:?}", paillier.key_pair.get_shares());
    // println!("Decrypted share of message: {:?}", shares);
    // // println!("{}", BigUint::from(4160u32).modpow(&BigUint::from(36u8),&BigUint::from(5929u32)));
    // // println!("{}", BigUint::from(449u32).modinv(&BigUint::from(5929u32)).unwrap());
    // let shares_again = paillier.key_pair.get_shares().clone()
    //     .iter_mut()
    //     .enumerate()
    //     .map(|(i, e)| &paillier.calculate_micro(i+1)*&e.clone().to_bigint().unwrap()).sum::<BigInt>();
    // println!("shares_again: {}", shares_again);
    // let result = paillier.combine_shares(shares);
    // //let result = paillier.decrypt(encrypted);
    // println!("{}", result);
}