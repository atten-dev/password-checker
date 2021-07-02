use std::io::{self, BufReader};
use std::convert::TryFrom;
use std::io::prelude::*;
use std::fs::File;
use std::env;
use std::collections::HashMap;
use sha1::{Sha1, Digest};

struct TrieNode {
    // children: [Option<Box<TrieNode>>; 16]
    children: HashMap<u8, Box<TrieNode>>
}

impl TrieNode {
    fn new() -> TrieNode {
        TrieNode { children: Default::default() } //[None; 16] } 
    }
}

// impl Default for TrieNode {
//     fn default() -> TrieNode {
//         TrieNode::new()
//     }
// }

struct Trie
{
    root: TrieNode 
}

impl Trie
{
    fn new() -> Trie {
        Trie { root: TrieNode::new() }
    }

    fn store_hash_recursive(node: &mut TrieNode, pw_remainder: &str) {
        if let Some(first_char) = pw_remainder.chars().next() {
            let child_idx = u8::try_from(first_char.to_digit(16).unwrap()).unwrap();

            match node.children.contains_key(&child_idx) { 
                false => {
                    node.children.insert(child_idx, Box::new(TrieNode::new()));
                }
                true => {
                    
                }
            }
            Trie::store_hash_recursive(node.children.get_mut(&child_idx).unwrap().as_mut(), &pw_remainder[1..])
        }
    }

    fn store_hash(&mut self, pw: &str) {
        let pw = pw.to_uppercase();
        Trie::store_hash_recursive(&mut self.root, &pw);
    }

    fn load_hashes(&mut self, path: &str) -> io::Result<()> {
        let f = File::open(path)?;
        let f = BufReader::new(f);

        let mut counter : u64 = 0;
        for line in f.lines() {
            self.store_hash(line.unwrap().split(":").next().unwrap());
            counter+=1;
            if counter % 1000 == 0 {
                println!("Loaded {} hashes so far", counter);
            }
        }
        println!("Done loading hashes");
        Ok(())
    }

    fn check_hash_recursive(node: &TrieNode, pw_hash_remainder: &str) -> bool{
        if let Some(first_char) = pw_hash_remainder.chars().next() {
            let child_idx = u8::try_from(first_char.to_digit(16).unwrap()).unwrap();

            match node.children.contains_key(&child_idx) { 
                false => {
                    return false
                }
                true => {
                    return Trie::check_hash_recursive(node.children.get(&child_idx).unwrap(), &pw_hash_remainder[1..])
                }
            }
        }
        else {
            true
        }
    }

    fn check_hash_exists(&self, pw_hash: &str) -> bool {
        Trie::check_hash_recursive(&self.root, &pw_hash)
    }

    fn check_password_exists(&self, pw: &str) -> bool {
        let mut hasher = Sha1::new();
        hasher.update(pw);
        let result = hasher.finalize();
        println!("Hash is {:X}", result);
        println!("Searching for your hash.");
        return self.check_hash_exists(&format!("{:X}", result));
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() > 1);

    println!("Loading hashes from {}.", args[1]);
    let mut hash_trie = Trie::new();
    hash_trie.load_hashes(&args[1]).expect("Failed to open hash file");
    loop {
        println!("Please enter the password you would like to check:");
        let mut pw = String::new();
        io::stdin().read_line(&mut pw).expect("Failed to read line");
        let pw = pw.trim();
        println!("You entered: {}", pw);
        let pw_exists = hash_trie.check_password_exists(pw);
        match pw_exists {
            true => println!("Password is in database"),
            false => println!("Password is not in database")
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_hash() {
        let mut trie = Trie::new();
        trie.store_hash("0");
        assert!(trie.root.children.get(&0u8).is_some());
    }

    #[test]
    fn store_hash_two_char() {
        let mut trie = Trie::new();
        trie.store_hash("21");
        assert!(trie.root.children.get(&2u8).as_ref().unwrap().children.get(&1u8).is_some());
    }

    #[test]
    fn store_hash_two_hashes() {
        let mut trie = Trie::new();
        trie.store_hash("21");
        trie.store_hash("12");
        assert!(trie.root.children.get(&1u8).as_ref().unwrap().children.get(&2u8).is_some());
        assert!(trie.root.children.get(&2u8).as_ref().unwrap().children.get(&1u8).is_some());
    }

    #[test]
    fn store_hash_full_hash() {
        let mut trie = Trie::new();
        trie.store_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert!(trie.root.children.get(&5u8).as_ref().unwrap().
                          children.get(&11u8).as_ref().unwrap(). // B
                          children.get(&10u8).as_ref().unwrap(). // A
                          children.get(&10u8).as_ref().unwrap(). // A
                          children.get(&6u8).as_ref().unwrap().
                          children.get(&1u8).as_ref().unwrap().
                          children.get(&14u8).as_ref().unwrap(). // E
                          children.get(&4u8).as_ref().unwrap().
                          children.get(&12u8).as_ref().unwrap(). // C
                          children.get(&9u8).as_ref().unwrap().
                          children.get(&11u8).as_ref().unwrap(). // B
                          children.get(&9u8).as_ref().unwrap().
                          children.get(&3u8).as_ref().unwrap().
                          children.get(&15u8).as_ref().unwrap(). // F
                          children.get(&3u8).as_ref().unwrap().
                          children.get(&15u8).as_ref().unwrap(). // F
                          children.get(&0u8).as_ref().unwrap().
                          children.get(&6u8).as_ref().unwrap().
                          children.get(&8u8).as_ref().unwrap().
                          children.get(&2u8).as_ref().unwrap().
                          children.get(&2u8).as_ref().unwrap().
                          children.get(&5u8).as_ref().unwrap().
                          children.get(&0u8).as_ref().unwrap().
                          children.get(&11u8).as_ref().unwrap(). // B
                          children.get(&6u8).as_ref().unwrap().
                          children.get(&12u8).as_ref().unwrap(). // C
                          children.get(&15u8).as_ref().unwrap(). // F
                          children.get(&8u8).as_ref().unwrap().
                          children.get(&3u8).as_ref().unwrap().
                          children.get(&3u8).as_ref().unwrap().
                          children.get(&1u8).as_ref().unwrap().
                          children.get(&11u8).as_ref().unwrap(). // B
                          children.get(&7u8).as_ref().unwrap().
                          children.get(&14u8).as_ref().unwrap(). // E
                          children.get(&14u8).as_ref().unwrap(). // E
                          children.get(&6u8).as_ref().unwrap().
                          children.get(&8u8).as_ref().unwrap().
                          children.get(&15u8).as_ref().unwrap(). // F
                          children.get(&13u8).as_ref().unwrap(). // D
                          children.get(&8u8).is_some());
    }   

    #[test]
    fn check_hash_exists() {
        let mut trie = Trie::new();
        trie.store_hash("21");
        assert!(trie.check_hash_exists("21"));
        assert!(!trie.check_hash_exists("12"));
    }

    #[test]
    fn check_password_exists() {
        let mut trie = Trie::new();
        trie.store_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert!(trie.check_password_exists("password"));
        assert!(!trie.check_password_exists("Password"));
    }

    #[test]
    fn load_hashes() {
        let mut trie = Trie::new();
        trie.load_hashes("test_pws.txt").expect("Failed to load test vector");
        assert!(trie.check_password_exists("password"));
        assert!(!trie.check_password_exists("Password"));
    }

}