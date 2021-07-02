use std::io::{self, BufReader};
use std::convert::TryFrom;
use std::io::prelude::*;
use std::fs::File;
use std::env;
use sha1::{Sha1, Digest};

struct TrieNode {
    // children: [Option<Box<TrieNode>>; 16]
    children: Vec<Option<Box<TrieNode>>>
}

impl TrieNode {
    fn new() -> TrieNode {
        TrieNode { children: Vec::with_capacity(16usize) } //[None; 16] } 
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
            let child_idx = usize::try_from(first_char.to_digit(16).unwrap()).unwrap();
            if node.children.len() == 0 {
                node.children.resize_with(16, Default::default);  
            }
            match node.children[child_idx] { 
                None => {
                    node.children[child_idx] = Some(Box::new(TrieNode::new()))
                }
                Some(ref child) => {
                    
                }
            }
            Trie::store_hash_recursive(node.children[child_idx].as_mut().unwrap(), &pw_remainder[1..])
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
            let child_idx = usize::try_from(first_char.to_digit(16).unwrap()).unwrap();
            if node.children.len() == 0 {
                return false;
            }
            match node.children[child_idx] { 
                None => {
                    return false
                }
                Some(ref child) => {
                    return Trie::check_hash_recursive(child, &pw_hash_remainder[1..])
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
        assert!(trie.root.children[0].is_some());
    }

    #[test]
    fn store_hash_two_char() {
        let mut trie = Trie::new();
        trie.store_hash("21");
        assert!(trie.root.children[2].as_ref().unwrap().children[1].is_some());
    }

    #[test]
    fn store_hash_two_hashes() {
        let mut trie = Trie::new();
        trie.store_hash("21");
        trie.store_hash("12");
        assert!(trie.root.children[1].as_ref().unwrap().children[2].is_some());
        assert!(trie.root.children[2].as_ref().unwrap().children[1].is_some());
    }

    #[test]
    fn store_hash_full_hash() {
        let mut trie = Trie::new();
        trie.store_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert!(trie.root.children[5].as_ref().unwrap().
                          children[11].as_ref().unwrap(). // B
                          children[10].as_ref().unwrap(). // A
                          children[10].as_ref().unwrap(). // A
                          children[6].as_ref().unwrap().
                          children[1].as_ref().unwrap().
                          children[14].as_ref().unwrap(). // E
                          children[4].as_ref().unwrap().
                          children[12].as_ref().unwrap(). // C
                          children[9].as_ref().unwrap().
                          children[11].as_ref().unwrap(). // B
                          children[9].as_ref().unwrap().
                          children[3].as_ref().unwrap().
                          children[15].as_ref().unwrap(). // F
                          children[3].as_ref().unwrap().
                          children[15].as_ref().unwrap(). // F
                          children[0].as_ref().unwrap().
                          children[6].as_ref().unwrap().
                          children[8].as_ref().unwrap().
                          children[2].as_ref().unwrap().
                          children[2].as_ref().unwrap().
                          children[5].as_ref().unwrap().
                          children[0].as_ref().unwrap().
                          children[11].as_ref().unwrap(). // B
                          children[6].as_ref().unwrap().
                          children[12].as_ref().unwrap(). // C
                          children[15].as_ref().unwrap(). // F
                          children[8].as_ref().unwrap().
                          children[3].as_ref().unwrap().
                          children[3].as_ref().unwrap().
                          children[1].as_ref().unwrap().
                          children[11].as_ref().unwrap(). // B
                          children[7].as_ref().unwrap().
                          children[14].as_ref().unwrap(). // E
                          children[14].as_ref().unwrap(). // E
                          children[6].as_ref().unwrap().
                          children[8].as_ref().unwrap().
                          children[15].as_ref().unwrap(). // F
                          children[13].as_ref().unwrap(). // D
                          children[8].is_some());
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
        trie.load_hashes("test_pws.txt");
        assert!(trie.check_password_exists("password"));
        assert!(!trie.check_password_exists("Password"));
    }

}