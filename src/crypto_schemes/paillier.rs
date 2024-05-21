use std::thread::Thread;
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_prime::RandPrime;
use rand::prelude::ThreadRng;
use rand::thread_rng;
use crate::crypto_schemes::bigint::{UsefulOperations, UsefulConstants, ModSub};
use crate::crypto_schemes::el_gamal::EncryptedMessage;
#[derive(Debug)]
pub struct Components {
    pub p: BigUint,
    pub q: BigUint,
    pub p_sub: BigUint,
    pub q_sub: BigUint,
}
#[derive(Clone,Debug)]
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
pub struct Paillier {
    pub components: Components,
    pub key_pair: KeyPair,
    rng: ThreadRng,
    number_of_shares: u8,
    delta: u128
}
impl KeyPair {
    pub fn borrow_pk(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn get_shares(&self) -> &Vec<BigUint> {&self.shares}
}
impl Paillier {
    pub fn init(number_of_shares: u8) -> Self {
        let mut rng = thread_rng();
        let one = BigUint::one();
        let two = BigUint::two();

        let p: BigUint = BigUint::from(11u8);//rng.gen_safe_prime(256);
        let mut q: BigUint = BigUint::from(7u8);//rng.gen_safe_prime(256);
        while p.eq(&q)
        {
            q = rng.gen_safe_prime(256);
        }
        let p_sub = (&p - &one) / &two;
        let q_sub = (&q - &one) / &two;

        let N= &p * &q;
        let N_squared = N.pow(2);
        let m= &p_sub * &q_sub;
        let a = Paillier::get_element_of_group(&mut rng,&N);
        let b = Paillier::get_element_of_group(&mut rng,&N);
        let beta = Paillier::get_element_of_group(&mut rng,&N);

        println!("a: {} b: {} beta: {}", a,b,beta);
        let mut g: BigUint = ((&N+&one).modpow(&a, &N_squared)*(&b.modpow(&N,&N_squared))) % &N_squared;

        //let private_key = (&p-&one).lcm(&(&q-&one));
        let sigma =&a*&m*&beta % &N;
        let public_key = PublicKey {N: N.clone(), g, sigma};

        let components = Components {p,q,p_sub,q_sub};

        let private_key = (&beta*&m) % &(&N*&m);
        let delta = Self::factorial(number_of_shares.clone() as u128);
        Paillier {components, key_pair: KeyPair {public_key, private_key, shares: Vec::<BigUint>::new()}, rng, number_of_shares, delta}
    }
    pub fn from_data(components: Components, key_pair: KeyPair, number_of_shares: u8, delta: u128) -> Self {
        let mut rng = thread_rng();

        Paillier { components, key_pair, rng, number_of_shares, delta}
    }
    pub fn encrypt(&mut self, message: BigUint) -> BigUint {
        let m = &self.components.p_sub*&self.components.q_sub;

        let modulo = &self.key_pair.public_key.N;
        let mut x = Paillier::get_element_of_group(&mut self.rng, &modulo);
        println!("{}", x);
        let modulo = modulo.pow(2);
        (&self.key_pair.public_key.g.modpow(&message,&modulo) * x.modpow(&self.key_pair.public_key.N, &modulo)) % modulo
    }
    // pub fn decrypt(&mut self, message: BigUint) -> BigUint {
    //     let pk = self.key_pair.borrow_pk();
    //     let modulo = &pk.N.pow(2);
    //     let rhs = self.L(&message.modpow(&self.key_pair.private_key, &modulo));
    //     let lhs = self.L(&pk.g.modpow(&self.key_pair.private_key, &modulo));
    //     let lhs_inv = lhs.modinv(&pk.N).unwrap();
    //
    //     (rhs * lhs_inv) % &pk.N
    // }

    pub fn get_element_of_group(rng: &mut ThreadRng, modulo: &BigUint) -> BigUint {
        let mut x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        while x.gcd(&modulo) != BigUint::one() {
            x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        }
        x
    }
    pub fn create_shares(&mut self) {
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
        //coefficients.iter().enumerate().for_each(|(i,e)| println!("{i+1}th coef: {}", e));
        //coefficients.iter().enumerate().map(|(i, a_i)| a_i*x.pow((i+1) as u32)).enumerate().for_each(|(i,e)| println!("{i+1}th a_i * x^i: {}", e));
        let result = (coefficients.iter().enumerate()
            .map(|(i, a_i)| a_i*x.pow((i+1) as u32))
            .map(|e| e % (&self.key_pair.public_key.N*&m))
            .sum::<BigUint>() + &self.key_pair.private_key) % (&self.key_pair.public_key.N*&m);
        println!("x:{x} - f(x):{result}");
        result

        // for i in 1..coefficients.len() {
        //     point += &coefficients[i] * x.pow(i as u32);
        //     point %= &self.key_pair.public_key.N*&m
        // }
        // point
    }
    #[inline]
    pub fn decrypt_share(&mut self, message: BigUint, sk_share: BigUint) -> BigUint { //This is OK
        let decrypted_share = message.modpow(&(BigUint::from(2*self.delta)*sk_share), &self.key_pair.public_key.N.pow(2));
        decrypted_share
    }

    pub fn combine_shares(&mut self, decrypted_shares: Vec<BigUint>) -> BigUint {
        let m = &self.components.p_sub*&self.components.q_sub;
        let inner_element: BigUint = decrypted_shares.iter().enumerate().map(|(k, c_k)| {
            println!("{}", k);
            let micro = &self.calculate_micro(k+1);
            match micro >= &BigInt::from(0) {
                true => {
                    let result = c_k.modpow(&(&BigUint::two() * micro.to_biguint().unwrap()), &(&self.key_pair.public_key.N.pow(2)));
                    println!("micro.to_biguint().unwrap(): {}", &(&BigUint::two() * micro.to_biguint().unwrap()));
                    println!("c_k^micro*2: {}", result);
                    return result;
                },
                false => {
                    //let result = c_k.signed_modpow(&(&BigInt::from(2u8) * micro), &(&self.key_pair.public_key.N*&m), &(&self.key_pair.public_key.N.pow(2)));
                    let pos_micro = (BigInt::from(-1) * micro).to_biguint().unwrap() * &BigUint::two();
                    let result = c_k.modpow(&pos_micro, &self.key_pair.public_key.N.pow(2)).modinv(&self.key_pair.public_key.N.pow(2)).unwrap();
                    println!("&(&BigInt::from(2u8) * micro: {}", &(&BigInt::from(2u8) * micro));
                    println!("c_k^micro*2: {}", result);
                    return result;
                }
            }
            //c_k.modpow(&(&BigUint::two() * &self.calculate_micro(k)), &self.key_pair.public_key.N.pow(2))
        }
        ).product::<BigUint>();
        println!("inner_element: {}", inner_element);
        // M
        println!("{}", 4*self.delta.pow(2)*&self.key_pair.public_key.sigma % &self.key_pair.public_key.N);
        let inv = (4*self.delta.pow(2)*&self.key_pair.public_key.sigma % &self.key_pair.public_key.N).modinv(&self.key_pair.public_key.N).unwrap();
        println!("AHA!");
        (self.L(&(&inner_element % &self.key_pair.public_key.N.pow(2))) * inv) % &self.key_pair.public_key.N
    }

    pub fn calculate_micro(&mut self, k: usize) -> BigInt {
        let mut micro = (self.delta as i128);

        //let m = &self.components.p_sub*&self.components.q_sub;
        for l in 1..=self.key_pair.shares.len() {
            if l == k { continue }
            micro /= l as i128 - k as i128;
            micro *= l as i128 ;
        }
        let result: BigInt = BigInt::from(micro);
        println!("micro: {}, k: {}", result, k);
        result
    }
    #[inline]
    fn factorial(num: u128) -> u128 {
        (1..=num).product()
    }
    #[allow(non_snake_case)]
    #[inline]
    fn L(&self, u: &BigUint) -> BigUint {
        //println!("L: {}", (u - BigUint::one()) / &self.key_pair.public_key.N);
        println!("{}", u);
        (u - BigUint::one()) / &self.key_pair.public_key.N
    }
}