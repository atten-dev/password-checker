use std::io::{self, BufRead, BufReader, Write, BufWriter, Seek, SeekFrom};
use std::convert::TryFrom;
use std::fs::File;
use std::collections::BTreeMap;
use sha1::{Sha1, Digest};
use hex::FromHex;
use clap::{Arg, App};

struct PasswordChecker
{
    hash_pos_map: BTreeMap<String, u64>,
    hash_path: String
}

impl PasswordChecker
{
    fn new(hash_path: &str) -> PasswordChecker {
        PasswordChecker { hash_pos_map: Default::default(), hash_path: hash_path.to_string() }
    }

    fn store_hash(&mut self, hash: &str, pos: u64) {
        self.hash_pos_map.insert(hash.to_string(), pos);
    }

    fn load_index(&mut self, path: &str) -> io::Result<()> {
        let f = File::open(path)?;
        let f = BufReader::new(f);

        let mut counter : u64 = 0;
        for line in f.lines() {
            let line = line.unwrap();
            let vec = line.trim().split(":").take(2).collect::<Vec<&str>>();
            let hash = vec[0];
            let pos = vec[1].parse::<u64>().unwrap();
            self.store_hash(hash, pos);
            counter+=1;
            if counter % 1000 == 0 {
                println!("Loaded {} hashes so far", counter);
            }
        }
        println!("Done loading hashes");
        Ok(())
    }

    fn get_file_pos(&self, pw_hash: &str) -> u64 {
        match self.hash_pos_map.range(pw_hash.to_string()..).next() {
            Some(kv) => *kv.1,
            None => 0
        }
    }

    fn check_hash_exists(&self, pw_hash: &str) -> u64 {
        let pos = self.get_file_pos(pw_hash);
        let f = File::open(&self.hash_path).expect("Failed to open hash file");
        let mut f = BufReader::new(f);
        f.seek(SeekFrom::Start(pos)).expect("Failed to seek");
        for _ in 0..100 {
            let mut line = String::new(); 
            let res = f.read_line(&mut line);
            match res
            {
                Ok(0) => { break; }
                Ok(_) => {
                    let vec = line.trim().split(":").take(2).collect::<Vec<&str>>();
                    let hash = vec[0];
                    let count = vec[1].parse::<u64>().unwrap();
                    if hash == pw_hash {
                        return count;
                    }
                }
                Err(e) => { panic!("Failed to read line of hash file: {}", e); }
            }

        }
        0
    }

    fn check_password_exists(&self, pw: &str) -> u64 {
        let mut hasher = Sha1::new();
        hasher.update(pw);
        let result = hasher.finalize();
        println!("Hash is {:X}", result);
        println!("Searching for your hash.");
        return self.check_hash_exists(&format!("{:X}", result));
    }
}

fn create_index(hash_path: &str, index_path: &str) -> io::Result<()> {
    let mut f = BufReader::new(File::open(hash_path)?);
    let mut out_f = BufWriter::new(File::create(index_path)?);

    let mut line = String::new();
    let mut counter : u64 = 0;
    loop {
        let before_pos = f.stream_position()?;
        match f.read_line(&mut line) {
            Ok(0) => { break; } // Reprs EOF reached
            Ok(_) => {
                if counter % 100 == 0 {
                    let hash = line.split(":").next().unwrap();
                    let line_to_write = format!("{}:{}\n", hash, before_pos);
                    out_f.write_all(line_to_write.as_bytes())?
                }
            }
            Err(_) => {
                break;
            }
        }
        line.clear();
        counter += 1;
        if counter % 1000 == 0 {
            println!("Indexed {} hashes", counter);
        }
    }
    // Write the last line to the map to make searching easier
    // let hash = line.split(":").next().unwrap();
    // let line_to_write = format!("{}:{}\n", hash, f.stream_position()?);
    // out_f.write_all(line_to_write.as_bytes())?;
    out_f.flush()?;
    Ok(())
}

fn main() {
    let matches = App::new("My Test Program")
        .version("0.1.0")
        .author("John Lima <atten.dev@gmail.com>")
        .about("Checks passwords against haveIbeenpwned's password list")
        .arg(Arg::with_name("hash_file")
                .short("h")
                .long("hash-file")
                .takes_value(true)
                .required(true)
                .help("List of password hashes"))
        .arg(Arg::with_name("index_file")
                .short("i")
                .long("index-file")
                .takes_value(true)
                .required(true)
                .help("Name of index file"))
        .arg(Arg::with_name("create_index")
                .short("c")
                .long("create-index")
                .takes_value(false)
                .help("Create index file instead of running checking"))
        .get_matches();

    let hash_path = matches.value_of("hash_file").unwrap();
    let index_path = matches.value_of("index_file").unwrap();

    match matches.is_present("create_index") {
        true => {
            println!("Creating index at {} from {}", index_path, hash_path);
            create_index(hash_path, index_path).expect("Failed to create index");
        }
        false => {
            println!("Loading index file from {}", index_path);
            let mut hash_trie = PasswordChecker::new(hash_path);
            hash_trie.load_index(index_path).expect("Failed to open index file");
            loop {
                println!("Please enter the password you would like to check:");
                let mut pw = String::new();
                io::stdin().read_line(&mut pw).expect("Failed to read line");
                let pw = pw.trim();
                println!("You entered: {}", pw);
                let pw_exists = hash_trie.check_password_exists(pw);
                match pw_exists {
                    0 => println!("Password is not in database"),
                    i => println!("Password is in database {} times", i)
                }
                println!();
            }
        }
    }}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_hash() {
        let mut pc = PasswordChecker::new("");
        pc.store_hash("0", 1);
        assert_eq!(1, pc.check_hash_exists("0"));
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