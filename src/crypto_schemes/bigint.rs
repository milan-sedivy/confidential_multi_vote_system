use std::{cmp, mem};
use num_bigint::{BigInt, BigUint};

pub trait UsefulConstants {
    type Output;
    fn one() -> Self::Output;
    fn zero() -> Self::Output;
    fn two() -> Self::Output;
}
pub trait ModSub {
    fn modsub(&self, b: &BigUint, modulo: &BigUint) -> BigUint;
    fn signed_modpow(&self, b: &BigInt, modulo: &BigUint, outer_modulo: &BigUint) -> BigUint;
}

pub trait UsefulOperations {
    type Output;
    fn is_zero(&self) -> bool;
    fn gcd(&self, other: &Self::Output) -> Self::Output;
    fn lcm(&self, other: &Self::Output) -> Self::Output;
}

impl UsefulOperations for BigUint {
    type Output = BigUint;
    fn is_zero(&self) -> bool {
        self.eq(&BigUint::zero())
    }
    fn gcd(&self, other: &Self::Output) -> Self::Output {
    fn twos(x: &BigUint) -> u64 {
        x.trailing_zeros().unwrap_or(0)
    }

    // Stein's algorithm
    if self.is_zero() {
    return other.clone();
    }
    if other.is_zero() {
    return self.clone();
    }
    let mut m = self.clone();
    let mut n = other.clone();

    // find common factors of 2
    let shift = cmp::min(twos(&n), twos(&m));

    // divide m and n by 2 until odd
    // m inside loop
    n >>= twos(&n);

    while !m.is_zero() {
    m >>= twos(&m);
    if n > m {
    mem::swap(&mut n, &mut m)
    }
    m -= &n;
    }

    n << shift
}
    fn lcm(&self, other: &BigUint) -> BigUint {
        if self.is_zero() && other.is_zero() {
            BigUint::zero()
        } else {
            self / self.gcd(other) * other
        }
    }

}

impl UsefulConstants for BigUint {
    type Output = BigUint;
    fn one() -> Self::Output {
        BigUint::from(1u8)
    }
    fn zero() -> Self::Output {
        BigUint::from(0u8)
    }
    fn two() -> Self::Output { BigUint::from(2u8) }
}
impl ModSub for BigUint {
    fn modsub(&self, b: &BigUint, modulo: &BigUint) -> BigUint {
        let mut a: BigUint = self.clone();
        if self < b {
            a = a + modulo;
        }
        return a - b;
    }

    fn signed_modpow(&self, b: &BigInt, modulo: &BigUint, outer_modulo: &BigUint) -> BigUint {
        //println!("Modulo: {}, SignedModPow: {}",modulo, &(BigUint::zero().modsub(&(b * &BigInt::from(-1)).to_biguint().unwrap(), modulo)));
        self.modpow(&(BigUint::zero().modsub(&(b * &BigInt::from(-1)).to_biguint().unwrap(), modulo)), outer_modulo)
    }

}

