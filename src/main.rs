use num_bigint::BigUint;
use sha256::digest;
use crate::crypto_schemes::el_gamal::{Encryption, Signature};
use crate::crypto_schemes::paillier::Paillier;

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

    let mut paillier : Paillier = Paillier::init();



    let t = BigUint::from(5u8);
    let encrypted = paillier.encrypt(t);
    let result = paillier.decrypt(encrypted);
    println!("{}", result);
}