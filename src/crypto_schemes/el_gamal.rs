use std::collections::HashSet;
use num_prime::RandPrime;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use super::error::CryptoError::{self, MessageOutOfBounds};
use super::bigint::*;
use sha256::digest;

pub struct ElGamalSigner {
    components: ElGamalComponents,
    key_pair: KeyPair,
    rng: ThreadRng,
}
pub struct ElGamalVerifier {
    components: ElGamalComponents,
    rng: ThreadRng,
}
pub struct ElGamalGenerator {
    components: ElGamalComponents,
    key_pair: KeyPair,
    rng: ThreadRng,
}
pub struct ElGamalCipher {
    components: ElGamalComponents,
    key_pair: KeyPair,
    rng: ThreadRng,
}
#[derive(Clone,Debug, Serialize, Deserialize)]
pub struct ElGamalComponents {
    pub(crate) g: BigUint,
    pub(crate) p: BigUint,
    pub(crate) q: BigUint,
}

impl ElGamalComponents {
    pub fn generate_random(&mut self, rng: &mut ThreadRng) -> BigUint {
        let upper_bound = self.q.clone() - BigUint::from(2u8);
        let lower_bound = BigUint::from(2u8);
        rng.gen_biguint_range(&lower_bound, &upper_bound)
    }
}
#[derive(Clone)]
pub struct KeyPair {
    x: BigUint, // sk Option!
    y: BigUint, // pk
}


impl ElGamalGenerator {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let mut components = ElGamalGenerator::generate_components(&mut rng);
        let key_pair = ElGamalGenerator::generate_keypair(&mut components, &mut rng);
        ElGamalGenerator {
            components,
            key_pair,
            rng
        }
    }
    fn generate_components(rng: &mut ThreadRng) -> ElGamalComponents {
        let p: BigUint = rng.gen_safe_prime(256);
        let q: BigUint = (p.clone() - BigUint::one())/BigUint::from(2u8);
        let mut g: BigUint = BigUint::from(2u8);

        while g.modpow(&q, &p) != BigUint::one() {
            g = g + BigUint::one();
        }
        ElGamalComponents {g, p, q}
    }
    fn generate_keypair(components: &mut ElGamalComponents, rng: &mut ThreadRng) -> KeyPair {
        let x = components.generate_random(rng);
        let y = components.g.clone().modpow(&x, &components.p);
        KeyPair {x, y}
    }
    pub fn chameleon_from(&mut self, alpha: BigUint) -> Self {
        let mut modified_key_pair = self.key_pair.clone();
        modified_key_pair.x = (modified_key_pair.x + alpha) % &self.components.q;
        modified_key_pair.y = self.components.g.clone().modpow(&modified_key_pair.x, &self.components.p);
        ElGamalGenerator {
            components: self.components.clone(),
            key_pair: modified_key_pair,
            rng: thread_rng()
        }
    }

}
impl ElGamalSigner {

    pub fn from(components: ElGamalComponents, key_pair: KeyPair) -> Self {
        ElGamalSigner {
            components,
            key_pair,
            rng: thread_rng()
        }
    }
}

pub struct EncryptedMessage(BigUint, BigUint);
impl ElGamalCipher {
    pub fn from(components: ElGamalComponents, key_pair: KeyPair) -> Self {
        ElGamalCipher {
            components,
            key_pair,
            rng: thread_rng()
        }
    }
}
impl ElGamalVerifier {
    pub fn from(components: ElGamalComponents) -> Self {
        ElGamalVerifier {
            components,
            rng: thread_rng()
        }
    }
    pub fn generate_alpha(&mut self) -> BigUint {
        self.components.generate_random(&mut self.rng)
    }
    pub fn generate_multiple_chameleon_pks(&mut self, y: BigUint, count: usize) -> Vec<BigUint> {
        let mut result = HashSet::<BigUint>::new();

        while result.iter().count() < count {
            let alpha = self.generate_alpha();
            result.insert(self.create_chameleon_pk(y.clone(), alpha));
        }

        result.into_iter().collect()
    }
    pub fn create_chameleon_pk(&mut self, y: BigUint, alpha: BigUint) -> BigUint {
        (self.components.g.modpow(&alpha, &self.components.p) * y) % &self.components.p
    }
}
impl Encryption for ElGamalCipher {
    fn encrypt(&mut self, message: BigUint) -> Result<EncryptedMessage,CryptoError> {
        let h = self.components.generate_random(&mut self.rng);
        if message == BigUint::zero() || message.ge(&self.components.p) { return Err(MessageOutOfBounds)}

        let s = self.key_pair.y.modpow(&h,&self.components.p);
        let c1: BigUint = self.components.g.modpow(&h, &self.components.p);
        let c2: BigUint = (message * s) % &self.components.p;
        println!("Encryption done");
        Ok(EncryptedMessage(c1, c2))
    }
    fn decrypt(&mut self, encrypted_message: EncryptedMessage) -> Result<BigUint,CryptoError> {
        let q_minus_x = self.components.q.clone() - self.key_pair.x.clone();
        let s_inverse = encrypted_message.0.modpow(&q_minus_x, &self.components.p);

        Ok((encrypted_message.1 * s_inverse) % &self.components.p)
    }
}
pub fn hash(message: String) -> BigUint {
    let val = digest(message);
    let hash_bytes = val.as_str().as_bytes();
    BigUint::parse_bytes(hash_bytes, 16).unwrap()
}
impl Signature for ElGamalSigner {
    fn sign(&mut self, message: String) -> (BigUint,BigUint) {
        let k: BigUint = self.components.generate_random(&mut self.rng);
        let r = self.components.g.clone().modpow(&k, &self.components.p);


        let hash_dec = hash(message);
        let modulo = &self.components.p - BigUint::one();
        (r.clone(), (hash_dec.modsub(&(self.key_pair.x.clone()*r % &modulo),&modulo) * k.modinv(&self.components.q).unwrap()) % &modulo)
    }

}
impl Verify for ElGamalVerifier {
    fn verify(&mut self, message: String, y: &BigUint,  signature: (BigUint, BigUint)) -> bool {
        if (signature.0 == BigUint::zero() || signature.0 > self.components.p) { return false }
        if (signature.1 == BigUint::zero() || signature.1 > (&self.components.p - BigUint::one())) { return false }
        let hash_dec = hash(message);
        let modulo = self.components.p.clone();

        let lhs = self.components.g.modpow(&hash_dec, &modulo);
        let rhs = y.modpow(&signature.0, &modulo)*signature.0.modpow(&signature.1, &modulo);
        return lhs == (rhs % &modulo)
    }
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
    fn sign(&mut self, message: String) -> (BigUint, BigUint);

}
pub trait Verify {
    fn verify(&mut self, message: String, y: &BigUint,  signature: (BigUint, BigUint)) -> bool;
}

