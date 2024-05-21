use std::thread::Thread;
use num_bigint::{BigUint, RandBigInt};
use num_prime::RandPrime;
use rand::prelude::ThreadRng;
use rand::thread_rng;
use crate::crypto_schemes::bigint::{UsefulOperations, UsefulConstants};

pub struct Components {
    pub p: BigUint,
    pub q: BigUint,
    pub p_sub: BigUint,
    pub q_sub: BigUint,
}
#[derive(Clone)]
pub struct PublicKey {
    pub N: BigUint,
    pub g: BigUint,
    pub sigma: BigUint
}
pub struct KeyPair {
    public_key: PublicKey,
    private_key: BigUint,
}
pub struct Paillier {
    pub components: Components,
    pub key_pair: KeyPair,
    rng: ThreadRng,
}
impl KeyPair {
    pub fn borrow_pk(&self) -> &PublicKey {
        &self.public_key
    }
    pub fn create_shares(&self) -> Vec<BigUint> {
        todo!()
    }
    pub fn from_shares(&self) {
        todo!()
    }
}
impl Paillier {
    pub fn init() -> Self {
        let mut rng = thread_rng();
        let one = BigUint::one();
        let two = BigUint::two();

        let p: BigUint = rng.gen_safe_prime(256);
        let mut q: BigUint = rng.gen_safe_prime(256);
        while (p.eq(&q))
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
        let mut g: BigUint = ((&N+&one).modpow(&a, &N_squared)*(&b.modpow(&N,&N_squared))) % &N_squared;

        let private_key = (&p-&one).lcm(&(&q-&one));
        let sigma =&a*&m*&beta % &N;
        let public_key = PublicKey {N, g, sigma};

        let components = Components {p,q,p_sub,q_sub};

        //let private_key = (&beta*&m) % &N_squared; TODO: Prevest na sdilenou verzi

        Paillier {components, key_pair: KeyPair {public_key, private_key}, rng}
    }

    pub fn encrypt(&mut self, message: BigUint) -> BigUint {
        let modulo = &self.key_pair.public_key.N;
        let mut x = Paillier::get_element_of_group(&mut self.rng, &modulo);
        let modulo = modulo.pow(2);
        (&self.key_pair.public_key.g.modpow(&message,&modulo) * x.modpow(&self.key_pair.public_key.N, &modulo)) % modulo
    }
    pub fn decrypt(&mut self, message: BigUint) -> BigUint {
        let pk = self.key_pair.borrow_pk();
        let modulo = &pk.N.pow(2);
        let rhs = (message.modpow(&self.key_pair.private_key, &modulo) - BigUint::one()) / &pk.N;
        let lhs = (&pk.g.modpow(&self.key_pair.private_key, &modulo) - BigUint::one())/ &pk.N;
        let lhs_inv = lhs.modinv(&pk.N).unwrap();

        (rhs * lhs_inv) % &pk.N
    }

    pub fn get_element_of_group(rng: &mut ThreadRng, modulo: &BigUint) -> BigUint {
        let mut x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        while x.gcd(&modulo) != BigUint::one() {
            x = rng.gen_biguint_range(&BigUint::one(), &(modulo));
        }
        x
    }
}