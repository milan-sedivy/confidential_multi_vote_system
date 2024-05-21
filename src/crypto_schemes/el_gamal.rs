use num_prime::RandPrime;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use super::error::CryptoError::{self, MessageOutOfBounds, MissingComponents, MissingPrivateKey, MissingPublicKey};
use super::bigint::*;
use sha256::digest;

pub struct ElGamal {
    components: Option<Components>,
    key_pair: KeyPair,
    rng: ThreadRng,
}
impl ElGamal {
    pub fn new() -> Self {
       ElGamal {
           components: None,
           key_pair: KeyPair {x: None, y: None},
           rng: thread_rng()
       }
    }
    pub fn chameleon_from(&mut self, alpha: BigUint) -> Self {
        let mut modified_key_pair = self.key_pair.clone();
        modified_key_pair.x = Some((modified_key_pair.x.unwrap() + alpha) % &self.components.as_ref().unwrap().q);
        modified_key_pair.y = Some(self.components.as_ref().unwrap().g.clone().modpow(&modified_key_pair.x.as_ref().unwrap(), &self.components.as_ref().unwrap().p));
        ElGamal {
            components: self.components.clone(),
            key_pair: modified_key_pair,
            rng: thread_rng()
        }
    }
    pub fn from(components: Components) -> Self {
        let mut el_gamal = ElGamal {
            components: Some(components),
            key_pair: KeyPair {x: None, y: None},
            rng: thread_rng()
        };
        el_gamal.generate_keypair();
        el_gamal
    }
    pub fn from_pk(components: Components, public_key: BigUint) -> Self {
        ElGamal {
            components: Some(components),
            key_pair: KeyPair {x: None, y: Some(public_key)},
            rng: thread_rng()
        }
    }
    pub fn init(&mut self) {
        self.generate_components();
        self.generate_keypair();
    }
    pub fn generate_random(&mut self) -> BigUint {
        let mut components = match &self.components {
            Some(x) => x,
            None => {
                println!("No components available");
                return BigUint::zero();
            }
        };
        let upper_bound = components.q.clone() - BigUint::from(2u8);
        let lower_bound = BigUint::from(2u8);
        self.rng.gen_biguint_range(&lower_bound, &upper_bound)
    }
    fn generate_components(&mut self) {
        let p: BigUint = self.rng.gen_safe_prime(256);
        let q: BigUint = (p.clone() - BigUint::one())/BigUint::from(2u8);
        let mut g: BigUint = BigUint::from(2u8);

        // let condition = q.clone() - BigUint::one();
        // let exponent = (q.clone() - BigUint::one())/BigUint::from(2u8);
        println!("It gets stuck here");
        while g.modpow(&q, &p) != BigUint::one() {
            g = g + BigUint::one();
        }
        println!("{q} {p} {g}");
        self.components = Some(Components {g, p, q});
    }
    fn generate_keypair(&mut self) {
        let x = self.generate_random();
        if (x == BigUint::zero()) { return };
        let components = match &self.components {
            Some(x) => x,
            None => {
                println!("No components available");
                return;
            }
        };
        let y = components.g.clone().modpow(&x, &components.p);
        println!("{x} {y}");
        self.key_pair = KeyPair {x: Some(x), y: Some(y)};
    }
}

pub struct EncryptedMessage(BigUint, BigUint);

impl Encryption for ElGamal {
    fn encrypt(&mut self, message: BigUint) -> Result<EncryptedMessage,CryptoError> {
        let h = self.generate_random();
        if (h == BigUint::zero()) {return Err(MissingComponents)};
        let Some(components) = &self.components else { return Err(MissingComponents)};
        if message == BigUint::zero() || message.ge(&components.p) { return Err(MessageOutOfBounds)}
        let Some(y) = &self.key_pair.y else { return Err(MissingPublicKey)};


        let s = y.modpow(&h,&components.p);
        let c1: BigUint = components.g.modpow(&h, &components.p);
        let c2: BigUint = (message * s) % &components.p;
        println!("Encryption done");
        Ok(EncryptedMessage(c1, c2))
    }
    fn decrypt(&mut self, encrypted_message: EncryptedMessage) -> Result<BigUint,CryptoError> {
        let Some(components) = &self.components else { return Err(MissingComponents)};
        let Some(x) = &self.key_pair.x else { return Err(MissingPrivateKey)};
        //let s = encrypted_message.0.modpow(x, &components.q);
        let q_minus_x = components.q.clone() - x.clone();
        let s_inverse = encrypted_message.0.modpow(&q_minus_x, &components.p);

        Ok((encrypted_message.1 * s_inverse) % &components.p)
    }
}

impl Signature for ElGamal {
    fn hash(message: String) -> BigUint {
        let val = digest(message);
        let hash_bytes = val.as_str().as_bytes();
        BigUint::parse_bytes(hash_bytes, 16).unwrap()
    }
    fn sign(&mut self, message: String) -> (BigUint,BigUint) {
        let k: BigUint = self.generate_random();
        let r = self.components.as_ref().unwrap().g.clone().modpow(&k, &self.components.as_ref().unwrap().p);


        let hash_dec = ElGamal::hash(message);
        let modulo = &self.components.as_ref().unwrap().p - BigUint::one();
        (r.clone(), (hash_dec.modsub(&(self.key_pair.x.clone().unwrap()*r % &modulo),&modulo) * k.modinv(&self.components.as_ref().unwrap().q).unwrap()) % &modulo)
    }

    fn verify(&mut self, message: String,  signature: (BigUint, BigUint)) -> bool {
        if (signature.0 == BigUint::zero() || signature.0 > self.components.as_ref().unwrap().p) { return false }
        if (signature.1 == BigUint::zero() || signature.1 > (&self.components.as_ref().unwrap().p - BigUint::one())) { return false }
        let hash_dec = ElGamal::hash(message);
        let modulo = self.components.as_ref().unwrap().p.clone();

        let lhs = self.components.as_ref().unwrap().g.modpow(&hash_dec, &modulo);
        let rhs = self.key_pair.y.as_ref().unwrap().modpow(&signature.0, &modulo)*signature.0.modpow(&signature.1, &modulo);
        return lhs == (rhs % &modulo)
    }
}

#[derive(Clone)]
pub struct Components {
    g: BigUint,
    p: BigUint,
    q: BigUint,
}
#[derive(Clone)]
pub struct KeyPair {
    x: Option<BigUint>, // sk Option!
    y: Option<BigUint>, // pk
}


pub trait ElGamalProperties {
    fn generate_components(&mut self);
    fn create_keypair(&mut self);
}

pub trait Encryption {
    fn encrypt(&mut self, message: BigUint) -> Result<EncryptedMessage, CryptoError>;
    fn decrypt(&mut self, encrypted_message: EncryptedMessage) -> Result<BigUint, CryptoError>;
}

pub trait Signature {
    fn hash(message: String) -> BigUint;
    fn sign(&mut self, message: String) -> (BigUint, BigUint);
    fn verify(&mut self, message: String,  signature: (BigUint, BigUint)) -> bool;
}

