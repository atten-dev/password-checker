use std::io::{self, BufReader};
use std::convert::TryFrom;
use std::io::prelude::*;
use std::fs::File;
use std::env;
use std::collections::HashMap;
use sha1::{Sha1, Digest};
use generic_array::{ArrayLength, GenericArray};
use hex::FromHex;

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
    root: TrieNode,
    // hashes: Vec<GenericArray<u8,generic_array::typenum::U18>>
    // hashes: Vec<[u8; 20]>
}

impl Trie
{
    fn new() -> Trie {
        Trie { root: TrieNode::new() }
    }

    fn store_hash_recursive(node: &mut TrieNode, hash_remainder: &[u8]) {
        if let Some(first_byte) = hash_remainder.first() {
            if !node.children.contains_key(&first_byte) { 
                node.children.insert(*first_byte, Box::new(TrieNode::new()));
            }
            Trie::store_hash_recursive(node.children.get_mut(&first_byte).unwrap().as_mut(), &hash_remainder[1..])
        }
    }

    fn store_hash_bin(&mut self, hash: [u8; 20]) { //GenericArray<u8, generic_array::typenum::U18>) {
        Trie::store_hash_recursive(&mut self.root, &hash)
    }

    fn store_hash(&mut self, hash: &str) {
        if hash.len() < 2 { return; }
        let bin_hash = <[u8; 20] as FromHex>::from_hex(hash).expect("Hex to binary conversion failed");
        self.store_hash_bin(bin_hash);
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

    fn check_hash_recursive(node: &TrieNode, hash_remainder: &[u8]) -> bool{
        if let Some(first_byte) = hash_remainder.first() {
            if node.children.contains_key(&first_byte) { 
                Trie::check_hash_recursive(node.children.get(&first_byte).unwrap(), &hash_remainder[1..])
            }
            else {
                false 
            }
        }
        else {
            true
        }
    }

    fn check_hash_exists(&self, pw_hash: &str) -> bool {
        let bin_hash = <[u8; 20] as FromHex>::from_hex(pw_hash).expect("Hex to binary conversion failed");
        Trie::check_hash_recursive(&self.root, &bin_hash)
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