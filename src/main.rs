use std::io::{self, BufRead, BufReader, Write, BufWriter, Seek, SeekFrom};
use std::fs::File;
use std::collections::BTreeMap;
use sha1::{Sha1, Digest};
use clap::{Arg, App};
use num_bigint::{BigInt};
use num_traits::Num;

struct PasswordChecker
{
    hash_pos_map: BTreeMap<BigInt, u64>,
    hash_path: String,
    index_block_size: u64
}

impl PasswordChecker
{
    fn new(hash_path: &str, index_block_size: u64) -> PasswordChecker {
        PasswordChecker {
            hash_pos_map: Default::default(),
            hash_path: hash_path.to_string(),
            index_block_size: index_block_size
        }
    }

    fn store_hash(&mut self, hash: &str, pos: u64) {
        self.hash_pos_map.insert(<BigInt as Num>::from_str_radix(hash, 16).unwrap(), pos);
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
            if counter % 10000 == 0 {
                println!("Loaded {} hashes so far", counter);
            }
        }
        println!("Done loading hashes");
        Ok(())
    }

    fn get_file_pos(&self, pw_hash: &str) -> u64 {
        match self.hash_pos_map.range(..<BigInt as Num>::from_str_radix(pw_hash, 16).unwrap()).next_back() {
            Some(kv) => *kv.1,
            None => 0
        }
    }

    fn check_hash_count(&self, pw_hash: &str) -> u64 {
        let pos = self.get_file_pos(pw_hash);
        let f = File::open(&self.hash_path).expect("Failed to open hash file");
        let mut f = BufReader::new(f);
        f.seek(SeekFrom::Start(pos)).expect("Failed to seek");
        for _ in 0..self.index_block_size {
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

    fn check_password_count(&self, pw: &str) -> u64 {
        let mut hasher = Sha1::new();
        hasher.update(pw);
        let result = hasher.finalize();
        return self.check_hash_count(&format!("{:X}", result));
    }
}

fn create_index(hash_path: &str, index_path: &str, index_block_size: u64) -> io::Result<()> {
    let mut f = BufReader::new(File::open(hash_path)?);
    let mut out_f = BufWriter::new(File::create(index_path)?);

    let mut line = String::new();
    let mut counter : u64 = 0;
    loop {
        let before_pos = f.stream_position()?;
        match f.read_line(&mut line) {
            Ok(0) => { break; } // Reprs EOF reached
            Ok(_) => {
                if counter % index_block_size == 0 {
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
    let index_block_size: u64 = 1000;

    match matches.is_present("create_index") {
        true => {
            println!("Creating index at {} from {}", index_path, hash_path);
            create_index(hash_path, index_path, index_block_size).expect("Failed to create index");
        }
        false => {
            println!("Loading index file from {}", index_path);
            let mut pass_checker = PasswordChecker::new(hash_path, index_block_size);
            pass_checker.load_index(index_path).expect("Failed to open index file");
            loop {
                println!("Please enter the password you would like to check:");
                let mut pw = String::new();
                io::stdin().read_line(&mut pw).expect("Failed to read line");
                let pw = pw.trim();
                println!("You entered: {}", pw);
                println!("Searching for your password.");
                let pw_count = pass_checker.check_password_count(pw);
                match pw_count {
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
        let mut pc = PasswordChecker::new("test_hashes.txt",100);
        pc.store_hash("0", 0);
        assert_eq!(1, pc.check_hash_count("0"));
    }

    #[test]
    fn load_index() {
        let index_path = "/tmp/index.txt";
        create_index("test_hashes.txt", index_path, 100).expect("Failed to create index");
        let mut pc = PasswordChecker::new("test_hashes.txt",100);
        
        pc.load_index(index_path).expect("Failed to load test vector");
        assert_eq!(9001, pc.check_password_count("password"));
        assert_eq!(0, pc.check_password_count("Password"));
        assert_eq!(1111, pc.check_password_count("abc123"));
    }

    #[test]
    fn boundary_cases() {
        let hash_path = "/tmp/hash.txt";
        let mut data = String::from("");
        for i in 0..1003 {
            data.push_str(&format!("{:X}:{}\n",i,i+1));
        }
        fs::write(hash_path, data).expect("Unable to write test hash file");

        let index_path = "/tmp/index.txt";
        create_index(hash_path, index_path,100).expect("Failed to create index");
        let mut pc = PasswordChecker::new(hash_path,100);
        
        pc.load_index(index_path).expect("Failed to load test vector");

        for (key, value) in &pc.hash_pos_map {
            println!("{}:{}", key, value);
        }
        assert_eq!(1, pc.check_hash_count("0"));
        assert_eq!(2, pc.check_hash_count("1"));
        assert_eq!(102, pc.check_hash_count(&format!("{:X}", 101)));
        assert_eq!(1002, pc.check_hash_count(&format!("{:X}", 1001)));
        assert_eq!(1003, pc.check_hash_count(&format!("{:X}", 1002)));
        assert_eq!(0, pc.check_hash_count(&format!("{:X}", 1003)));
    }
}