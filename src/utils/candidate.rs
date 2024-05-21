use std::collections::HashMap;
use std::ops::Index;
use super::base_three::{BaseThree, BaseTen};

#[derive(Debug)]
pub struct VoteCount {
    pub yes: u64,
    pub no: u64,
    pub none: u64,
}
pub struct Candidate {
    pub statement: String,
    pub vote_count: VoteCount,
}

pub struct CandidatePool {
    pool: HashMap<u8, Candidate>,
    last_candidate_num: u8,
}

impl CandidatePool {
    pub fn new() -> CandidatePool {
        CandidatePool {
            pool: HashMap::new(),
            last_candidate_num: 0,
        }
    }

    pub fn add_candidate(&mut self, statement: &str) {
        let new_candidate = Candidate::new(statement);
        self.pool.entry(self.last_candidate_num).or_insert(new_candidate);
        self.last_candidate_num += 1;
    }
    // for now we keep but later on it will be read only
    pub fn get_candidate<'a>(&'a self, key: u8) -> Option<&'a Candidate> {
        self.pool.get(&key)
    }
    /*    pub fn base_ten_to_three(number: u64) -> u64 {
            let mut base: u64 = 1;
            let mut result = 0;
            let mut number = number;
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
            result
        }*/
    pub fn cast_encoded_votes(&mut self, encoded_vote: BaseTen) {
        let mut candidate_votes = BaseThree::from(encoded_vote).get();//Self::base_ten_to_three(encoded_vote);
        let mut current_candidate = 0;
        while candidate_votes > 0 {
            let current_vote: u8 = (candidate_votes % 10) as u8;
            self.cast_base_three_vote(&current_candidate, &current_vote);
            current_candidate += 1;
            candidate_votes /= 10;
        }
    }
    pub fn cast_votes(&mut self, base_three_vote: BaseThree) {
        let mut candidate_votes = base_three_vote.get();
        let mut current_candidate = 0;
        while candidate_votes > 0 {
            let current_vote: u8 = (candidate_votes % 10) as u8;
            self.cast_base_three_vote(&current_candidate, &current_vote);
            current_candidate += 1;
            candidate_votes /= 10;
        }
    }
    fn cast_base_three_vote(&mut self, candidate_num: &u8, vote: &u8) {
        if let Some(mut candidate) = self.pool.get_mut(candidate_num) {
            match vote {
                2 => candidate.vote_no(),
                1 => candidate.vote_yes(),
                0 => candidate.vote_none(),
                _ => println!("Incorrect vote")
            }
        } else {
            println!("Incorrect candidate number");
        }
    }
}

impl Candidate {
    pub fn new(statement: &str) -> Candidate {
        let candidate: Candidate = Candidate {
            statement: String::from(statement),
            vote_count: VoteCount {
                yes: 0,
                no: 0,
                none: 0,
            },
        };
        candidate
    }
    pub fn vote_yes(&mut self) {
        self.vote_count.yes += 1;
    }
    pub fn vote_no(&mut self) {
        self.vote_count.no += 1;
    }
    pub fn vote_none(&mut self) {
        self.vote_count.none += 1;
    }
}
