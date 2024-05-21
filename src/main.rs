use std::ops::DerefMut;
use num_bigint::{BigInt, BigUint, ToBigInt};
use sha256::digest;
use crate::crypto_schemes::el_gamal::{Encryption, Signature};
use crate::crypto_schemes::paillier::{KeyPair, Paillier, PublicKey};

mod crypto_schemes;
mod utils;

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

    let mut paillier : Paillier = Paillier::init(3);
    println!("{:?}", paillier);
    // let components = crypto_schemes::paillier::Components {p: BigUint::from(11u8), q: BigUint::from(7u8), p_sub: BigUint::from(5u8), q_sub: BigUint::from(3u8)};
    // let key_pair = KeyPair { public_key: PublicKey { N: BigUint::from(77u32), g: BigUint::from(3974u32), sigma: BigUint::from(74u32) }, private_key: BigUint::from(345u32), shares: vec![BigUint::from(574u32), BigUint::from(989u32), BigUint::from(198u32), BigUint::from(274u32)] };
    // let mut paillier: Paillier = Paillier::from_data(components, key_pair, 4, 24);
    let t = BigUint::from(5u8);
    let encrypted = paillier.encrypt(t);

    paillier.create_shares();
    // paillier.create_shares(4u8);
    let mut shares: Vec<BigUint> = paillier.key_pair.get_shares().clone().iter_mut().map(|e| paillier.decrypt_share(encrypted.clone(),e.clone())).collect();
    println!("c (encrypted): {}", encrypted);
    println!("Individual shares: {:?}", paillier.key_pair.get_shares());
    println!("Decrypted share of message: {:?}", shares);
    // println!("{}", BigUint::from(4160u32).modpow(&BigUint::from(36u8),&BigUint::from(5929u32)));
    // println!("{}", BigUint::from(449u32).modinv(&BigUint::from(5929u32)).unwrap());
    let shares_again = paillier.key_pair.get_shares().clone()
        .iter_mut()
        .enumerate()
        .map(|(i, e)| &paillier.calculate_micro(i+1)*&e.clone().to_bigint().unwrap()).sum::<BigInt>();
    println!("shares_again: {}", shares_again);
    let result = paillier.combine_shares(shares);
    //let result = paillier.decrypt(encrypted);
    println!("{}", result);
}