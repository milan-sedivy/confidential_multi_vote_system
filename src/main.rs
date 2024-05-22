use std::fs;
use std::ops::DerefMut;
use num_bigint::{BigUint, ToBigInt};
use crate::crypto_schemes::el_gamal::{ElGamalComponents, ElGamalGenerator, ElGamalSigner, Encryption, Signature};
use crate::crypto_schemes::paillier::{Cipher, Combiner, Generator, KeyPair, PaillierCipher, PaillierGenerator, PublicKey};
use serde::{Deserialize, Serialize};
use crate::data::{Data, MessageType};

mod crypto_schemes;
mod utils;
pub mod data;
mod certificate;

type ElGamalKeyPair = crate::crypto_schemes::el_gamal::KeyPair;
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
   // println!("{:?}", paillier);
    paillier.create_shares();
    let mut paillier_combiner = Combiner::init_from(&paillier.key_pair.public_key, paillier.delta.clone());
    //paillier.key_pair.shares.iter().for_each(|e|)

    let mut cipher_engines: Vec<PaillierCipher> = vec![];
    paillier.key_pair.shares.iter().for_each(|e| cipher_engines.push(PaillierCipher::init_from(&paillier.key_pair.public_key, e, paillier.delta.clone())));
  //  println!("{:?}", cipher_engines);
  //  println!("{}", cipher_engines.len());
    let t = BigUint::from(5u8);
    let encrypted = cipher_engines[1].encrypt(t);
   // println!("{}", encrypted);
    cipher_engines.iter_mut().for_each(|e| paillier_combiner.add_decrypted_message_share(e.decrypt_share(encrypted.clone())));

   // println!("{}", paillier_combiner.combine_shares());
    let mut data_vec: Vec<Data> = vec![];
    paillier.key_pair.shares.iter().for_each(|e| {
        data_vec.push(Data {public_key: paillier.key_pair.public_key.clone(), secret_share: e.clone(), delta: 24});
        //println!("{}", serde_json::to_string(&data).unwrap());
    });
    use ws::{connect, CloseCode};

    // let mut el_gamal = ElGamalGenerator::new();
    // let serialized_key_pair = serde_json::to_string(&el_gamal.key_pair);
    // let serialized_components = serde_json::to_string(&el_gamal.components);
    //
    // fs::write("key_pair.json", serialized_key_pair.unwrap());
    // fs::write("components.json", serialized_components.unwrap());
    let components: ElGamalComponents = serde_json::from_slice(fs::read("components.json").expect("Failed to open components.json").as_slice()).unwrap();
    let key_pair: ElGamalKeyPair = serde_json::from_slice(fs::read("key_pair.json").expect("Failed to open key_pair.json").as_slice()).unwrap();

    let el_gamal_signer = ElGamalSigner::from(components.clone(),key_pair.clone());

    let el_gamal_data = serde_json::to_string(&MessageType::ElGamalData(components, key_pair.y)).unwrap();


    connect("ws://127.0.0.1:8001", |out| {
        //data_vec.iter().for_each(|e| out.send(serde_json::to_string(e).unwrap()).unwrap());

        let _ = out.send(el_gamal_data.clone());
        move |msg| {
            println!("Got message: {}", msg);
            out.close(CloseCode::Normal)
        }
    }).unwrap();



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