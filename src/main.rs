extern crate digest;
extern crate walkdir;
extern crate filebuffer;
extern crate clap;

#[cfg(feature = "sha2")]
extern crate sha2;

#[cfg(feature = "sha3")]
extern crate sha3;

#[cfg(feature = "blake3")]
extern crate blake3;

use std::collections::HashMap;
use std::io::BufRead;
use digest::Digest;
use filebuffer::FileBuffer;
use walkdir::WalkDir;
use clap::Parser;

#[derive(Parser)]
// TODO: why isn't this read from Cargo.toml?
//#[command(author, version, about, long_about = None)]
#[command(author = "René Mayrhofer", version, about = "Recursively compute file hashes over a tree", long_about = None)]
struct Args {
    /// Directory path to start recursive traversal from
    #[arg(short = 'p', long, default_value_t = String::from("."))]
    path: String,
 
    /// Hash function: sha2, sha3, or blake3
    #[arg(short = 'c', long, default_value_t = String::from("blake3"))]
    hasher: String,

    /// Auditing mode: read hashes from file specific by this parameter and compare with files in path.
    #[arg(short = 'a', long)]
    audit: Option<String>,
 }

fn main() {
    let args = Args::parse();

    let mut audit_map = None;
    if args.audit.is_some() {
        let audit_file = args.audit.unwrap();
        println!("Reading hashes from {}", audit_file);
        let faudit = FileBuffer::open(&audit_file).expect(&format!("failed to open file {}", audit_file).to_string());
        /*audit_map = ["hash", "path"].into_iter()
            .zip(faudit.lines().map(|l| l.expect("Unable to read line {}").split_once(char::is_whitespace)))
            .collect::<HashMap<_, _>>();
        println!("{:#?}", audit_map);*/
        panic!("not fully implemented")
    }

    match args.hasher.as_str() {
        #[cfg(feature = "sha2")]
        "sha2" => scan_dir::<sha2::Sha256>(&args.path, audit_map),

        #[cfg(feature = "sha3")]
        "sha3" => scan_dir::<sha3::Sha3_256>(&args.path, audit_map),

        #[cfg(feature = "blake3")]
        "blake3" => scan_dir::<blake3::Hasher>(&args.path, audit_map),

        _ => panic!("unknown hash function")
    };
}

fn scan_dir<D: Digest>(path: &str, audit_map: Option<HashMap<String, String>>)
        where D::OutputSize: std::ops::Add,
              <D::OutputSize as std::ops::Add>::Output: digest::generic_array::ArrayLength<u8> {

    for entry in WalkDir::new(path).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        let fname = entry.path();
        if ! fname.is_file() {
            continue;
        }

        let fbuf = FileBuffer::open(&fname).expect(&format!("failed to open file {}", fname.display()).to_string());

        // this may not be optimal from a performance point of view, but reset is problematic with re-using the digest in the generic case
        let mut digest = D::new();
        //Digest::reset(&mut digest);
        digest.update(&fbuf);

        let fhash = digest.finalize();
        match audit_map {
            Some(ref m) => {
                /*if m.contains_key(&fhash.to_string()) {
                    if (m.get(&fhash.to_string()).unwrap() != fname.display().to_string()) {
                        println!("{}  {}  (mismatch)", fhash, fname.display());
                    }
                }*/
            },
            None => {
                println!("{:x}  {}", fhash, fname.display());
            }
        }
    }
}
