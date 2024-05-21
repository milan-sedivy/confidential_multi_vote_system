use num_bigint::{BigInt, BigUint, RandBigInt};
use num_prime::RandPrime;
use rand::prelude::ThreadRng;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use crate::crypto_schemes::bigint::{UsefulOperations, UsefulConstants, ModSub};
#[derive(Debug)]
pub struct Components {
    pub p: BigUint,
    pub q: BigUint,
    pub p_sub: BigUint,
    pub q_sub: BigUint,
}
#[derive(Clone,Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub N: BigUint,
    pub g: BigUint,
    pub sigma: BigUint
}
#[derive(Debug)]
pub struct KeyPair {
    pub(crate) public_key: PublicKey,
    pub(crate) private_key: BigUint,
    pub(crate) shares: Vec<BigUint>,
}
#[derive(Debug)]
pub struct PaillierGenerator {
    pub components: Components,
    pub key_pair: KeyPair,
    rng: ThreadRng,
    number_of_shares: u8,
    pub delta: u128
}
#[derive(Debug)]
pub struct PaillierCipher {
    rng: ThreadRng,
    pub public_key: PublicKey,
    secret_share: BigUint,
    delta: u128
}

pub struct Combiner {
    public_key: PublicKey,
    decrypted_message_shares: Vec<BigUint>,
    delta: u128
}
impl KeyPair {
    pub fn borrow_pk(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn get_shares(&self) -> &Vec<BigUint> {&self.shares}
}

pub trait Generator {
    type Output;
    type Generator;
    fn init(number_of_shares: u8) -> Self::Generator;
    //For testing purposes only
    fn from_data(components: Components, key_pair: KeyPair, number_of_shares: u8, delta: u128) -> Self::Generator;
    fn create_shares(&mut self);
    fn f(&self, x: Self::Output, coefficients: &Vec<Self::Output>) -> Self::Output;
}
pub trait Group {
    type Output;
    fn get_element_of_group(rng: &mut ThreadRng, modulo: &Self::Output) -> Self::Output;
}
impl Group for PaillierGenerator {
    type Output = BigUint;
    fn get_element_of_group(rng: &mut ThreadRng, modulo: &BigUint) -> BigUint {
        let mut x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        while x.gcd(&modulo) != BigUint::one() {
            x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        }
        x
    }
}
impl Group for PaillierCipher {
    type Output = BigUint;
    fn get_element_of_group(rng: &mut ThreadRng, modulo: &BigUint) -> BigUint {
        let mut x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        while x.gcd(&modulo) != BigUint::one() {
            x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        }
        x
    }
}
impl Generator for PaillierGenerator {
    type Output = BigUint;
    type Generator = Self;
    fn init(number_of_shares: u8) -> Self {
        let mut rng = thread_rng();
        let one = BigUint::one();
        let two = BigUint::two();

        let p: BigUint = rng.gen_safe_prime(256);
        let mut q: BigUint = rng.gen_safe_prime(256);
        while p.eq(&q)
        {
            q = rng.gen_safe_prime(256);
        }
        let p_sub = (&p - &one) / &two;
        let q_sub = (&q - &one) / &two;

        let N= &p * &q;
        let N_squared = N.pow(2);
        let m= &p_sub * &q_sub;
        let a = PaillierGenerator::get_element_of_group(&mut rng,&N);
        let b = PaillierGenerator::get_element_of_group(&mut rng,&N);
        let beta = PaillierGenerator::get_element_of_group(&mut rng,&N);

        let mut g: BigUint = ((&N+&one).modpow(&a, &N_squared)*(&b.modpow(&N,&N_squared))) % &N_squared;

        let sigma =&a*&m*&beta % &N;
        let public_key = PublicKey {N: N.clone(), g, sigma};

        let components = Components {p,q,p_sub,q_sub};

        let private_key = (&beta*&m) % &(&N*&m);
        let delta = Self::factorial(number_of_shares.clone() as u128);
        PaillierGenerator {components, key_pair: KeyPair {public_key, private_key, shares: Vec::<BigUint>::new()}, rng, number_of_shares, delta}
    }
    fn from_data(components: Components, key_pair: KeyPair, number_of_shares: u8, delta: u128) -> Self {
        let mut rng = thread_rng();

        PaillierGenerator { components, key_pair, rng, number_of_shares, delta}
    }
    fn create_shares(&mut self) {
        let mut shares = Vec::<BigUint>::new();
        let mut coefficients = Vec::<BigUint>::new();
        let m = &self.components.p_sub*&self.components.q_sub;
        let upper_bound = &self.key_pair.public_key.N*(&m - &BigUint::one());
        for _i in 1u8..self.number_of_shares {
            coefficients.push(self.rng.gen_biguint_range(&BigUint::one(), &upper_bound));
        }
        println!("Number of coefficients: {}", coefficients.len());
        for i in 0..=coefficients.len() {
            shares.push(self.f(BigUint::from(i+1), &coefficients));
        }
        println!("Number of total shares: {}", shares.len());
        self.key_pair.shares = shares;
    }
    fn f(&self, x: BigUint, coefficients: &Vec<BigUint>) -> BigUint {
        let m = &self.components.p_sub*&self.components.q_sub;
        let result = (coefficients.iter().enumerate()
            .map(|(i, a_i)| a_i*x.pow((i+1) as u32))
            .map(|e| e % (&self.key_pair.public_key.N*&m))
            .sum::<BigUint>() + &self.key_pair.private_key) % (&self.key_pair.public_key.N*&m);
        result

    }
}
pub trait Cipher {
    type Output;
    fn encrypt(&mut self, message: Self::Output) -> Self::Output;
    fn decrypt_share(&mut self, message: Self::Output) -> Self::Output;
}

impl Cipher for PaillierCipher {
    type Output = BigUint;
    fn encrypt(&mut self, message: BigUint) -> BigUint {
        let modulo = &self.public_key.N;
        let mut x = PaillierCipher::get_element_of_group(&mut self.rng, &modulo);
        let modulo = modulo.pow(2);
        (&self.public_key.g.modpow(&message,&modulo) * x.modpow(&self.public_key.N, &modulo)) % modulo
    }
    #[inline]
    fn decrypt_share(&mut self, message: BigUint) -> BigUint {
        message.modpow(&(BigUint::from(2*self.delta)*&self.secret_share), &self.public_key.N.pow(2))
    }
}

impl PaillierCipher {
    pub fn init_from(public_key: &PublicKey, secret_share: &BigUint, delta: u128) -> Self {
        let rng = thread_rng();
        Self {rng, public_key: public_key.clone(), secret_share: secret_share.clone(), delta }
    }
}
impl Combiner {
    pub fn init_from(public_key: &PublicKey, delta: u128) -> Self {
        let decrypted_message_shares = Vec::<BigUint>::new();
        Self {public_key: public_key.clone(), decrypted_message_shares, delta }
    }
    pub fn add_decrypted_message_share(&mut self, decrypted_share: BigUint) {
        self.decrypted_message_shares.push(decrypted_share);
    }
    pub fn combine_shares(&mut self) -> BigUint {
        println!("{:?}", self.decrypted_message_shares);
        let inner_element: BigUint = self.decrypted_message_shares.clone().iter().enumerate().map(|(k, c_k)| {
            let micro = &self.calculate_micro(k.clone()+1);
            match micro >= &BigInt::from(0) {
                true => {
                    let result = c_k.modpow(&(&BigUint::two() * micro.to_biguint().unwrap()), &(&self.public_key.N.pow(2)));
                    return result;
                },
                false => {
                    let pos_micro = (BigInt::from(-1) * micro).to_biguint().unwrap() * &BigUint::two();
                    let result = c_k.modpow(&pos_micro, &self.public_key.N.pow(2)).modinv(&self.public_key.N.pow(2)).unwrap();
                    return result;
                }
            }
        }).product::<BigUint>();

        let inv = (4*self.delta.pow(2)*&self.public_key.sigma % &self.public_key.N).modinv(&self.public_key.N).unwrap();
        (self.L(&(&inner_element % &self.public_key.N.pow(2))) * inv) % &self.public_key.N
    }
    fn calculate_micro(&mut self, k: usize) -> BigInt {
        let mut micro = (self.delta as i128);

        for l in 1..=self.decrypted_message_shares.len() {
            if l == k { continue }
            micro /= l as i128 - k as i128;
            micro *= l as i128 ;
        }
        BigInt::from(micro)
    }

    #[allow(non_snake_case)]
    #[inline]
    fn L(&self, u: &BigUint) -> BigUint {
        (u - BigUint::one()) / &self.public_key.N
    }
}
impl PaillierGenerator {
    #[inline]
    fn factorial(num: u128) -> u128 {
        (1..=num).product()
    }

}