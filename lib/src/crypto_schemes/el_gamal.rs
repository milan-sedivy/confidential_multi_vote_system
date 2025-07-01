use num_prime::RandPrime;
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::ThreadRng;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use super::error::CryptoError::{self, MessageOutOfBounds};
use super::bigint::*;
use sha256::digest;
unsafe impl Send for ElGamalSigner {}

pub struct ElGamalSigner {
    components: ElGamalComponents,
    key_pair: KeyPair,
    rng: ThreadRng,
}
#[derive(Clone)]
pub struct ElGamalVerifier {
    components: ElGamalComponents,
    rng: ThreadRng,
}
#[allow(dead_code)]
pub struct ElGamalGenerator {
    pub components: ElGamalComponents,
    pub key_pair: KeyPair,
    rng: ThreadRng,
}
unsafe impl Send for ElGamalCipher {}
pub struct ElGamalCipher {
    pub components: ElGamalComponents,
    key_pair: KeyPair,
    rng: ThreadRng,
}
#[derive(Clone,Debug, Serialize, Deserialize)]
pub struct ElGamalComponents {
    pub g: BigUint,
    pub p: BigUint,
    pub q: BigUint,
}

impl ElGamalComponents {
    pub fn generate_random(&mut self, rng: &mut ThreadRng) -> BigUint {
        let upper_bound = self.q.clone() - BigUint::from(2u8);
        let lower_bound = BigUint::from(2u8);
        rng.gen_biguint_range(&lower_bound, &upper_bound)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub x: BigUint, // sk Option!
    pub y: BigUint, // pk
}

#[allow(dead_code)]
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
    pub fn from(mut components: ElGamalComponents) -> Self {
        let mut rng = thread_rng();
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
#[allow(dead_code)]
impl ElGamalSigner {

    pub fn from(components: ElGamalComponents, key_pair: KeyPair) -> Self {
        ElGamalSigner {
            components,
            key_pair,
            rng: thread_rng()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage(BigUint, BigUint);
#[allow(dead_code)]
impl ElGamalCipher {
    pub fn from(components: ElGamalComponents, key_pair: KeyPair) -> Self {
        ElGamalCipher {
            components,
            key_pair,
            rng: thread_rng()
        }
    }
    pub fn generate_nonce(&mut self) -> BigUint {
        self.rng.gen_biguint_range(&BigUint::one(), &self.components.q)
    }
}
#[allow(dead_code)]
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
    pub fn generate_multiple_chameleon_pks(&mut self, y: BigUint, count: usize) -> (Vec<BigUint>, Vec<BigUint>) {
        let mut result = Vec::<BigUint>::new();
        let mut alphas = Vec::<BigUint>::new();
        while result.iter().count() < count {
            let alpha = self.generate_alpha();
            // If order wouldn't be important we would just use a hashset here.
            if alphas.iter().find(|e| **e == alpha).is_some() {
                continue;
            }
            alphas.push(alpha.clone());
            result.push(self.create_chameleon_pk(y.clone(), alpha));
        }
        (result, alphas)
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
        self.sign_with_key(&self.key_pair.x.clone(), message)
    }

    fn sign_with_key(&mut self, private_key: &BigUint, message: String) -> (BigUint, BigUint) {
        let k: BigUint = self.components.generate_random(&mut self.rng);
        let r = self.components.g.clone().modpow(&k, &self.components.p);

        let hash_dec = hash(message);
        let modulo = &self.components.p - BigUint::one();
        (r.clone(), (hash_dec.modsub(&(private_key*r % &modulo),&modulo) * k.modinv(&self.components.q).unwrap()) % &modulo)
    }
    fn sign_using_alpha(&mut self, alpha: &BigUint, message: String) -> (BigUint, BigUint) {
        let chameleon = &self.key_pair.x + alpha;
        self.sign_with_key(&chameleon, message)
    }
}
impl Verify for ElGamalVerifier {
    fn verify(&mut self, message: String, y: &BigUint,  signature: (BigUint, BigUint)) -> bool {
        if signature.0 == BigUint::zero() || signature.0 > self.components.p { return false }
        if signature.1 == BigUint::zero() || signature.1 > (&self.components.p - BigUint::one()) { return false }
        let hash_dec = hash(message);
        let modulo = self.components.p.clone();

        let lhs = self.components.g.modpow(&hash_dec, &modulo);
        let rhs = y.modpow(&signature.0, &modulo)*signature.0.modpow(&signature.1, &modulo);
        return lhs == (rhs % &modulo)
    }
}
unsafe impl Send for ElGamalGenerator {}


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
    fn sign_with_key(&mut self, private_key: &BigUint, message: String) -> (BigUint, BigUint);
    fn sign_using_alpha(&mut self, alpha: &BigUint, message: String) -> (BigUint, BigUint);

}
pub trait Verify {
    fn verify(&mut self, message: String, y: &BigUint,  signature: (BigUint, BigUint)) -> bool;
}

