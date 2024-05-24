//pub struct Number(u64);

pub struct BaseThree {
    value: u64
}
pub struct BaseTen(u64);

impl BaseThree {
    pub fn from_base_three(num: u64) -> Option<BaseThree> {
        let mut temp = num;
        while temp > 0 {
            if temp % 10 > 2 {
                println!("Input number not in base 3");
                return None;
            }
            temp /= 10;
        }
        Some(Self {value: num})
    }

    pub fn new(num: BaseTen) -> BaseThree {
        let mut x: u64 = num.0;
        let mut multiplier = 1;
        let mut result = 0;
        while x > 0 {
            let remainder = x % 10;
            result += remainder * multiplier;
            multiplier *= 3;
            x /= 10;
        }
        BaseThree {
            value: result
        }
    }

    pub fn get(&self) -> u64 {
        return self.value;
    }
}
impl BaseTen {
    pub fn new(num: u64) -> BaseTen {
        BaseTen(num)
    }
}
impl From<BaseTen> for BaseThree {
    fn from(value: BaseTen) -> Self {
        BaseThree::new(value)
    }
}
impl From<BaseThree> for BaseTen {
    fn from(num: BaseThree) -> Self {
        let mut base: u64 = 1;
        let mut result = 0;
        let mut number = num.value;
        while number / base > 0 {
            base *= 3;
        }
        base /= 3;
        while number > 0  {
            result *= 10;
            let div = number / base;
            result += div;
            number %= base;
            base /= 3;
        }
        BaseTen(result)
    }
}